import collections
from functools import reduce
from typing import Optional, Tuple

import angr
import copy
import claripy
from angr import SimMemoryMissingError
from angr.analyses import ReachingDefinitionsAnalysis
from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions import get_all_definitions
from angr.calling_conventions import SimStackArg, SimRegArg
from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register
from angr.knowledge_plugins.key_definitions.constants import OP_AFTER, OP_BEFORE
from angr.knowledge_plugins.key_definitions.heap_address import HeapAddress
from angr.knowledge_plugins.key_definitions.tag import LocalVariableTag
from angr.sim_type import SimTypeLongLong, SimTypeInt
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from angr.knowledge_plugins.key_definitions.undefined import Undefined
from angr.knowledge_plugins.key_definitions import LiveDefinitions

import sys, os

from HSEngine.src.MyUtils import utils

sys.path.append("..")
#from MyUtils import utils


class TaintedData(Undefined):
    def __init__(self, taint_name, offset):
        self.taint_name = taint_name
        self.offset = offset
        self.name = "<%s+%x>" % (taint_name, offset)

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, TaintedData):
            return self.taint_name == other.taint_name and self.offset == other.offset
        else:
            return False

    def __ne__(self, other):
        return not (self == other)

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.name


class TaintedVariableTag(LocalVariableTag):
    pass

class TaintHandler(FunctionHandler):
    def __init__(self, cfg, source_functions_info, vul_type, logger):
        self._vul_num = 0
        self._analysis = None
        self._tmp_state = None
        self.depth = 0
        self._reverse_plt = None
        self._cfg = cfg
        self._source_addrs = [function_info.addr for function_info in source_functions_info if
                              function_info.addr != None]
        self._source_functions_info = source_functions_info
        # self._taint_arg_ix = taint_idx
        self._taint_bb = []
        self._now_function = None
        self._black_list = []
        self._virtual_addresses = [0xD000000]
        self._virtual_addresses_used_num = 0
        self._not_find_new_viseted_blocks = 0
        self._vul_type = vul_type
        self.alert_info = []
        #self._log_file_name = log_file_name
        self._logger = logger

    def hook(self, rda: ReachingDefinitionsAnalysis):
        self._analysis = rda
        self._angr_project = rda.project
        self._reverse_plt = self._angr_project.loader.main_object.reverse_plt
        self._init_libc_handler()
        self._arch_bits = rda.project.arch.bits
        return self

    def handle_local_function(self,
                              state: 'ReachingDefinitionsState',
                              function_address: int,
                              call_stack: list,
                              maximum_local_call_depth: int,
                              visited_blocks: set[int],
                              dependency_graph,
                              src_ins_addr=None,
                              codeloc=None):

        reached_obs_points = all(op in self._analysis.observed_results for op in self._analysis._observation_points)
        sink_list = ['memset']

        if self._vul_type == 'ci':
            system_sink_functions = ["system","doSystemCmd", "twsystem", "execv", "dlopen", "FCGI_popen", "popen", "CsteSystem"]
            for system_sink_func in system_sink_functions:
                sink_list.append(system_sink_func)

        if reached_obs_points:
            return False, state, visited_blocks, dependency_graph

        function = self._angr_project.kb.functions.function(function_address)
        self._now_function = function

        if call_stack == None:
            call_stack = []

        call_stack.append(function_address)

        if len(call_stack) >= 20:
            latest_call_stack = call_stack[-3:]
            if len(set(latest_call_stack)) == 1:
                self._black_list.append(function_address)

        if function_address in visited_blocks:
            self._not_find_new_viseted_blocks += 1
        visited_blocks.add(function_address)

        self.depth += 1


        if function_address in self._black_list:
            return False, state, visited_blocks, dependency_graph

        if function_address in self._source_addrs:
            return self._handle_source_function(state, function_address, codeloc, visited_blocks, call_stack,
                                                dependency_graph, src_ins_addr)

        else:
            if function.name in sink_list:
                return self._handle_internal_function(state, function_address, codeloc, visited_blocks, call_stack,
                                                      dependency_graph)


            if self._is_args_tainted(function_address, state):
                self._taint_bb.append(hex(src_ins_addr))

                if self._vul_type == 'fmt' and function.name in ['printf', 'syslog', 'vprintf']:
                    self.save_alert_info()

                return self._handle_internal_function(state, function_address, codeloc, visited_blocks, call_stack,
                                                      dependency_graph)
            else:
                return False, state, visited_blocks, dependency_graph

    def save_alert_info(self):
        overflow_place = self._analysis._engine_vex.block.addr
        self.alert_info.append(hex(overflow_place))
        self._logger.info("Alert Address: {0}".format(hex(overflow_place)))

    def _create_handler(self, data_handler, arg_order, dst_arg_ix=None, fmt_string_ix=None):

        def _handler(state: "ReachingDefinitionsState", codeloc):
            args = []
            if arg_order:
                max_arg_ix = max(arg_order)
                n_fmt_args = 0
                for arg_ix in arg_order:
                    arg_defs = utils.get_arg_defs(self._angr_project, state, arg_ix)

                    if not arg_defs:
                        args.append(None)

                    arg_data = set()

                    for arg_def_values in arg_defs.values():
                        for arg_def_value in arg_def_values:
                            arg_data.add(arg_def_value)

                    args.append(arg_data)

                    if arg_ix == fmt_string_ix:
                        fmt_string_data = self.load_string(state, codeloc,  arg_data)
                        if fmt_string_data:
                            fmt_str = fmt_string_data.pop()
                            n_fmt_args = fmt_str.count("%") - fmt_str.count("%%") * 2

                for i in range(n_fmt_args):
                    arg_ix = max_arg_ix + 1 + i
                    arg_defs = utils.get_arg_defs(self._angr_project, state, arg_ix)
                    if arg_defs:
                        arg_data = next(iter(arg_defs.values()))

                    else:
                        arg_data = set()
                    args.append(arg_data)

            return data_handler(state, codeloc, *args)

        return _handler

    def _get_argument_definition(self, state: 'ReachingDefinitionsState', codeloc, arg_ix):
        cc = angr.DEFAULT_CC[self._angr_project.arch.name]
        register_name = cc.ARG_REGS[arg_ix]
        reg_offset, reg_size = self._angr_project.arch.registers[register_name]
        arg_defs = state.register_definitions.load(reg_offset, size=reg_size)
        return arg_defs

    def _get_return_definition(self, state: 'ReachingDefinitionsState', codeloc):
        cc = angr.DEFAULT_CC[self._angr_project.arch.name]
        return_register = cc.RETURN_VAL
        reg_offset, reg_size = self._angr_project.arch.registers[return_register.reg_name]
        return_defs = state.register_definitions.load(reg_offset, size=reg_size)
        return return_defs

    def _handle_external_function(self, state, function_address, codeloc, visited_blocks, call_stack, dependency_graph):
        function = self._angr_project.kb.functions.get_by_addr(function_address)
        return False, state, visited_blocks, dependency_graph

    def _handle_internal_function(self, state, function_address, codeloc, visited_blocks, call_stack, dependency_graph):
        # init_state is copied inside rda
        function = self._angr_project.kb.functions.get_by_addr(function_address)
        internal_func= self._analysis._engine_vex.block.addr
        self._logger.info("call_site_addr: " + hex(internal_func))
        self._logger.info(hex(function_address))

        ret_points = [("node", rs.addr, OP_AFTER) for rs in function.ret_sites]

        for jsaddr in function.jumpout_sites:
            jsaddr_node = ("node", jsaddr.addr, OP_BEFORE)
            ret_points.append(jsaddr_node)

        child_rda = self._angr_project.analyses.ReachingDefinitions(function,
                                                                    observation_points=self._analysis._observation_points + ret_points,
                                                                    init_state=state,
                                                                    function_handler=TaintHandler(cfg = self._cfg,
                                                                                                  source_functions_info = self._source_functions_info,
                                                                                                  vul_type = self._vul_type,
                                                                                                  logger = self._logger),
                                                                    visited_blocks=visited_blocks,
                                                                    maximum_local_call_depth=100,
                                                                    call_stack=call_stack,
                                                                    dep_graph=dependency_graph)

        livedefs_at_rets = []
        for op in ret_points:
            if op in child_rda.observed_results:
                livedefs_at_ret = child_rda.observed_results[op]
                livedefs_at_rets.append(livedefs_at_ret)
            else:
                self._logger.debug("Could not get livedef at return", op[1])

        tmp_states = []
        for tmp_livedef_at_ret in livedefs_at_rets:
            tmp_state = state.copy()
            tmp_state.live_definitions = tmp_livedef_at_ret
            state.merge(tmp_state)

        """
        if livedefs_at_rets:
           state.live_definitions = reduce(LiveDefinitions.merge, livedefs_at_rets)
        """

        self._analysis.observed_results.update(child_rda.observed_results)

        return True, state, visited_blocks, dependency_graph

    def _handle_source_function(self, state, function_address, codeloc, visited_blocks, call_stack, dependency_graph,
                                src_ins_addr):

        """
        :param state:
        :param function_address:
        :param codeloc:
        :param visited_blocks:
        :param call_stack:
        :param dependency_graph:
        :param src_ins_addr:
        :return:
        """

        self._taint_bb.append("source addr:"+hex(src_ins_addr))
        #self._taint_bb.append(hex(src_ins_addr))
        taint_place = None
        function = self._now_function

        input_limit_args = None
        output_taint_args = None

        """
        Match the source function
        """

        for function_info in self._source_functions_info:
            if function_info.addr == function_address:
                input_limit_args = function_info.input_format
                output_taint_args = function_info.output_format
                break

        if not output_taint_args:
            self._logger.debug("_handle_source_function:Could not find taint place in {0}".format(hex(function_address)))
            return False, state, visited_blocks, dependency_graph

        else:
            limit_size = None
            limit_buffer = None
            limit_chars = None

            """
            Get the limitation of the source function
            """
            if input_limit_args:
                limit_size, limit_buffer, limit_chars = self.get_input_limitation(state, input_limit_args)

            for taint_place in output_taint_args:

                source_value:bytes = self.set_initial_source_def_val()

                """
                If the taint place is at return value
                """
                if taint_place == 'RET':
                    exit_site_addresses = [b.addr for b in function.ret_sites + function.jumpout_sites]
                    ret_points = [("node", rs.addr, OP_AFTER) for rs in function.ret_sites + function.jumpout_sites]

                    """
                    child_rda = self._angr_project.analyses.ReachingDefinitions(function_address = function,
                                                                                observation_points=ret_points,
                                                                                dep_graph=dependency_graph,
                                                                                init_state=state,
                                                                                visited_blocks=visited_blocks,
                                                                                maximum_local_call_depth=10000,
                                                                                call_stack=call_stack)
                    """

                    cc = angr.DEFAULT_CC[self._angr_project.arch.name]
                    return_register = cc.RETURN_VAL
                    reg_offset, reg_size = self._angr_project.arch.registers[return_register.reg_name]

                    free_virtual_addresses_num = len(self._virtual_addresses) - self._virtual_addresses_used_num

                    if free_virtual_addresses_num == 1:
                        now_virtual_address = self._virtual_addresses[self._virtual_addresses_used_num - 1]
                        next_virtual_address = now_virtual_address + 1000
                        self._virtual_addresses.append(next_virtual_address)
                        self._virtual_addresses_used_num += 1
                    else:
                        self._logger.warning("_handle_source_function:Number of freed virtual addresses is wrong.")
                        return False, state, visited_blocks, dependency_graph

                    if now_virtual_address:
                        string_addr = now_virtual_address

                    padding_length = 1000 - len(source_value)
                    tmp_str = claripy.BVV(source_value + b'\0' * padding_length)

                    tmp_str_mm = MemoryLocation(string_addr, 1000)
                    state.memory_definitions.store(tmp_str_mm.addr, tmp_str)

                    """
                    Look at the state of string addr we have just stored

                    aa = state.memory_definitions.load(tmp_str_mm.addr, 1000)
                    for tmp_aa in aa.values.values():
                        print(tmp_aa)
                        for tmp_aaa in tmp_aa:
                            stt = tmp_aaa.args[0]
                    """

                    arch_bits = self._angr_project.arch.bits
                    string_addr_pointer = claripy.BVV(string_addr, arch_bits)

                    data = MultiValues(offset_to_values={0: {string_addr_pointer}})

                    state.kill_and_add_definition(Register(reg_offset, reg_size), codeloc, data,
                                                  tags={
                                                      TaintedVariableTag(self._source_addrs[0],
                                                                         "%s_%d" % (str(hex(function_address)), 0))})


                else:
                    preset_limit_size = 1
                    set_size = limit_size if limit_size else preset_limit_size

                    arg_defs: MultiValues = utils.get_arg_defs(self._angr_project, state, taint_place)
                    arg_data = set()
                    for arg_def_values in arg_defs.values():
                        for arg_def_value in arg_def_values:
                            arg_data.add(arg_def_value)

                    self.store_core(state,
                                    codeloc,
                                    arg_data,
                                    [source_value],
                                    {
                                        TaintedVariableTag(self._source_addrs[0], "%s_%d" % (str(hex(function_address)), 0))
                                    }
                                    )
                return True, state, visited_blocks, dependency_graph

    def _init_libc_handler(self):
        for fn in ["getenv"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_source_input, [0]))

        for fn in ["atoi"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_atoi, [0]))

        for fn in ["atol", "atoll"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_atol, [0]))

        for fn in ["strcat", "cmsUtl_strcat"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_strcat, [0, 1]))

        for fn in ["strncat", "cmsUtl_strncat"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_strncat, [0, 1, 2]))

        for fn in ["strlen"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_strlen, [0]))

        for fn in ["strncpy", "strlcpy", "__strcpy_chk", "__strlcpy_chk", "cmsUtl_strncpy"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_strncpy, [0, 1, 2]))

        for fn in ["memcpy"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_memcpy, [0, 1, 2]))

        for fn in ["memset"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_memset, [0, 1, 2]))

        for fn in ["strcpy", "__strcpy_chk", "cmsUtl_strcpy"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_strcpy, [0, 1]))

        for fn in ["strchr"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_strchr, [0, 1]))

        for fn in ["strrchr"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_strrchr, [0, 1]))

        for fn in ["strstr"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_strstr, [0, 1]))

        self.handle_sprintf = self._create_handler(self._handle_format_function, [0, 1], fmt_string_ix=1)
        self.handle_snprintf = self._create_handler(self._handle_snprintf_function, [0, 1, 2], fmt_string_ix=2)
        self.handle___sprintf_chk = self._create_handler(self._handle_format_function, [0, 3], fmt_string_ix=3)
        self.hanlde___snprintf_chk = self._create_handler(self._handle_snprintf_function, [0, 1, 4], fmt_string_ix=4)

        if self._vul_type == 'ci':
            for fn in ["system", "doSystemCmd", "twsystem", "execv", "dlopen", "FCGI_popen", "popen", "CsteSystem",
                       "save_encrypted_data"]:
                setattr(self, "handle_%s" % fn, self._create_handler(self._handle_system_like_function, [0]))

            for fn in ["unlink"]:
                setattr(self, "handle_%s" % fn, self._create_handler(self._handle_unlink, [0]))

            for fn in ["doSystem"]:
                setattr(self, "handle_%s" % fn, self._create_handler(self._handle_format_system_like_function, [0], fmt_string_ix=0))

            for fn in ["run_doSystemAction"]:
                setattr(self, "handle_%s" % fn,
                        self._create_handler(self._handle_format_system_like_function, [0, 1], fmt_string_ix=1))

        elif self._vul_type == 'fmt':
            setattr(self, "handle_%s" % fn,
                    self._create_handler(self._handle_format_system_like_function, [0], fmt_string_ix=0))


        for fn in ["puts", "__stack_chk_fail", "__errno_location", "tolower", "__adddf3",
                   "__muldf3", "__subdf3", "__fixdfsi"]:
            setattr(self, "handle_%s" % fn, self._create_handler(self._handle_skip_libc_func, []))

    def _handle_format_system_like_function(self, state:ReachingDefinitionsState, codeloc, fmt_arg_dataset, *val_arg_datasets):

        fmt_loaded_defs = self.load_core(state, codeloc, fmt_arg_dataset, None)
        fmt_loaded_strs = self.extract_defs_value_to_str(fmt_loaded_defs, truncate_flag=True)

        fmt_saved_strs = set()
        for fmt_loaded_str in fmt_loaded_strs:
            fmt_string = [fmt_loaded_str]
            for val_arg_dataset in val_arg_datasets:
                next_fmt_strings = []
                for fmt_sub_string in fmt_string:
                    perc_ix = fmt_sub_string.find("%")
                    arg_type = fmt_sub_string[perc_ix + 1]

                    if arg_type == 's':
                        str_arg_data = self.load_string(state, codeloc, val_arg_dataset)
                        if '' not in str_arg_data:
                            for str_arg in str_arg_data:
                                next_fmt_string = fmt_sub_string.replace("%s", str_arg)
                                next_fmt_strings.append(next_fmt_string)
                        else:
                            next_fmt_string = fmt_sub_string.replace("%s", "<<UNKNOWN>>")
                            next_fmt_strings.append(next_fmt_string)

                    elif arg_type == 'd':
                        for int_arg in val_arg_dataset:
                            next_fmt_string = fmt_sub_string.replace("%d", str(int_arg))
                            next_fmt_strings.append(next_fmt_string)
                    elif arg_type == '%':
                        next_fmt_strings.append(fmt_sub_string)
                    else:
                        # log.warning("Unrecognized arg_type '%s' in '%s'", arg_type, fmt_string)
                        next_fmt_strings.append(fmt_sub_string)

                fmt_string = next_fmt_strings.copy()

            fmt_saved_strs.update(fmt_string)
            if self._vul_type == 'ci':
                for fmt_saved_str in fmt_saved_strs:
                    if "UNKNOWN" in fmt_saved_str or "telnet" in fmt_saved_str:
                        self.save_alert_info()
                        self._vul_num += 1
        return False, state

    def _handle_unlink(self, state, codeloc, name_arg_dataset):

        name_loaded_defs = self.load_core(state, codeloc, name_arg_dataset, None)
        name_loaded_strs = self.extract_defs_value_to_str(name_loaded_defs, truncate_flag=True)

        if self._vul_type == 'ci':
            if name_loaded_strs:
                for name_loaded_str in name_loaded_strs:
                    if "telnetd" in name_loaded_str:
                        self.save_alert_info()
                        self._vul_num += 1
                        return False, state
                return False, state
            else:
                """"
                self.alert_info.append(self._vul_num)
                taint_trace = copy.deepcopy(self._taint_bb)
                self.alert_info.append(taint_trace)
                self.alert_info.append("get sink address")
                """
                self.save_alert_info()
                self._vul_num += 1
                return False, state

    def _handle_system_like_function(self, state, codeloc, command_arg_dataset, *other_arg_dataset):

        command_loaded_defs = self.load_core(state, codeloc, command_arg_dataset, None)
        command_loaded_strs = self.extract_defs_value_to_str(command_loaded_defs, truncate_flag=True)

        if self._vul_type == 'ci':
            if command_loaded_strs:
                for command_loaded_str in command_loaded_strs:
                    if "telnetd" in command_loaded_str:
                        self.save_alert_info()
                        self._vul_num += 1
                        return False, state
                return False, state
            else:
                self.save_alert_info()

                self._vul_num += 1
                return False, state

    def _handle_snprintf_function(self, state, codeloc, dst_arg_dataset, sz_arg_dataset: set, fmt_arg_dataset,
                                  *val_arg_datasets):

        fmt_loaded_defs = self.load_core(state, codeloc, fmt_arg_dataset, None)
        fmt_loaded_strs = self.extract_defs_value_to_str(fmt_loaded_defs, truncate_flag=True)

        sz_max_value = 0
        if sz_arg_dataset:

            for sz_data in sz_arg_dataset:
                if sz_data.op == 'BVV':
                    sz_value = sz_data.args[0]
                    sz_max_value = sz_value if sz_max_value < sz_value else sz_max_value
        else:
            return False, state

        fmt_saved_strs = set()
        for fmt_loaded_str in fmt_loaded_strs:
            fmt_string = [fmt_loaded_str]
            for val_arg_dataset in val_arg_datasets:
                next_fmt_strings = []
                for fmt_sub_string in fmt_string:
                    perc_ix = fmt_sub_string.find("%")
                    arg_type = fmt_sub_string[perc_ix + 1]

                    if arg_type == 's':
                        str_arg_data = self.load_string(state, codeloc, val_arg_dataset)
                        if '' not in str_arg_data:
                            for str_arg in str_arg_data:
                                next_fmt_string = fmt_sub_string.replace("%s", str_arg)
                                next_fmt_strings.append(next_fmt_string)
                        else:
                            next_fmt_string = fmt_sub_string.replace("%s", "<<UNKNOWN>>")
                            next_fmt_strings.append(next_fmt_string)

                    elif arg_type == 'd':
                        for int_arg in val_arg_dataset:
                            next_fmt_string = fmt_sub_string.replace("%d", str(int_arg.args[0]), 1)
                            next_fmt_strings.append(next_fmt_string)

                    elif arg_type == '%':
                        next_fmt_strings.append(fmt_sub_string)

                    else:
                        # log.warning("Unrecognized arg_type '%s' in '%s'", arg_type, fmt_string)
                        next_fmt_strings.append(fmt_sub_string)

                fmt_string = next_fmt_strings.copy()

            fmt_saved_strs.update(fmt_string)

        if fmt_saved_strs:
            rt_values = set()
            new_fmt_saved_strs = set()
            for fmt_saved_str in fmt_saved_strs:
                fmt_saved_str_len = len(fmt_saved_str)
                rt_values.add(fmt_saved_str_len)

                if fmt_saved_str_len >= sz_max_value:
                    new_fmt_saved_strs.add(fmt_saved_str[:sz_max_value - 1])
                else:
                    new_fmt_saved_strs.add(fmt_saved_str)

            is_alert = self.store_core(state, codeloc, dst_arg_dataset, list(new_fmt_saved_strs), taint_tag=TaintedVariableTag)
            if is_alert:
                self.save_alert_info()

        return False, state

    def _handle_format_function(self, state, codeloc, dst_arg_dataset, fmt_arg_dataset, *val_arg_datasets):

        fmt_loaded_defs = self.load_core(state, codeloc, fmt_arg_dataset, None)
        fmt_loaded_strs = self.extract_defs_value_to_str(fmt_loaded_defs, truncate_flag=True)

        fmt_saved_strs = set()
        for fmt_loaded_str in fmt_loaded_strs:
            fmt_string = [fmt_loaded_str]
            for val_arg_dataset in val_arg_datasets:
                next_fmt_strings = []
                for fmt_sub_string in fmt_string:
                    perc_ix = fmt_sub_string.find("%")
                    arg_type = fmt_sub_string[perc_ix + 1]

                    if arg_type == 's':
                        str_arg_data = self.load_string(state, codeloc, val_arg_dataset)
                        if '' not in str_arg_data and str_arg_data:
                            for str_arg in str_arg_data:
                                next_fmt_string = fmt_sub_string.replace("%s", str_arg, 1)
                                next_fmt_strings.append(next_fmt_string)
                        else:
                            next_fmt_string = fmt_sub_string.replace("%s", "<<UNKNOWN>>", 1)
                            next_fmt_strings.append(next_fmt_string)

                    elif arg_type == 'd':
                        if val_arg_dataset:
                            for int_arg in val_arg_dataset:
                                next_fmt_string = fmt_sub_string.replace("%d", str(int_arg.args[0]), 1)
                                next_fmt_strings.append(next_fmt_string)
                        else:
                            next_fmt_string = fmt_sub_string.replace("%d", "1", 1)
                            next_fmt_strings.append(next_fmt_string)
                    elif arg_type == '%':
                        next_fmt_strings.append(fmt_sub_string)
                    else:
                        next_fmt_strings.append(fmt_sub_string)

                fmt_string = next_fmt_strings.copy()

            fmt_saved_strs.update(fmt_string)

        if fmt_saved_strs:
            is_alert = self.store_core(state, codeloc, dst_arg_dataset, list(fmt_saved_strs), taint_tag=TaintedVariableTag)
            if is_alert:
                self.save_alert_info()

        return False, state

    def _handle_source_input(self, state, codeloc, *val_arg_dataset):
        rda = self._analysis
        assert isinstance(rda, ReachingDefinitionsAnalysis)

        source_value = self.set_initial_source_def_val()

        cc = angr.DEFAULT_CC[self._angr_project.arch.name]
        return_register = cc.RETURN_VAL
        reg_offset, reg_size = self._angr_project.arch.registers[return_register.reg_name]

        free_virtual_addresses_num = len(self._virtual_addresses) - self._virtual_addresses_used_num

        if free_virtual_addresses_num == 1:
            now_virtual_address = self._virtual_addresses[self._virtual_addresses_used_num - 1]
            next_virtual_address = now_virtual_address + 1000
            self._virtual_addresses.append(next_virtual_address)
            self._virtual_addresses_used_num += 1
        else:
            self._logger.warning("_handle_source_function:Number of freed virtual addresses is wrong")
            return False, state

        if now_virtual_address:
            string_addr = now_virtual_address

        padding_length = 1000 - len(source_value)
        tmp_str = claripy.BVV(source_value + b'\0' * padding_length)
        #tmp_str = claripy.BVS("arg", 1000*8)

        tmp_str_mm = MemoryLocation(string_addr, 1000)
        state.memory_definitions.store(tmp_str_mm.addr, tmp_str)
        arch_bits = self._angr_project.arch.bits
        string_addr_pointer = claripy.BVV(string_addr, arch_bits)

        data = MultiValues(offset_to_values={0: {string_addr_pointer}})

        state.kill_and_add_definition(Register(reg_offset, reg_size), codeloc, data,
                                      tags={
                                          TaintedVariableTag(self._source_addrs[0],
                                                             "%s_%d" % ("1111", 0))})
        return True, state


    def _handle_atoi(self, state, codeloc, src_arg_dataset):
        src_loaded_defs = self.load_core(state, codeloc, src_arg_dataset, None)

        if src_loaded_defs:
            src_loaded_strs = self.extract_defs_value_to_str(src_loaded_defs, truncate_flag=True)
            str_data_dict = {}
            offset = 0
            str_to_ints = set()
            for src_loaded_str in src_loaded_strs:
                str_to_int =  utils.str_to_int(src_loaded_str, "int")
                str_to_ints.add(str_to_int)

            for str_to_int in str_to_ints:
                str_data_dict[offset] = {claripy.BVV(str_to_int, 32)}
                offset += 1

            if str_data_dict:
                data = MultiValues(offset_to_values=str_data_dict)
                cc = angr.DEFAULT_CC[self._angr_project.arch.name]
                return_register = cc.RETURN_VAL
                reg_offset, reg_size = self._angr_project.arch.registers[return_register.reg_name]
                state.kill_and_add_definition(Register(reg_offset, reg_size), codeloc, data)
                return True, state

        return False, state

    def _handle_atol(self, state, codeloc, src_arg_dataset):

        src_loaded_defs = self.load_core(state, codeloc, src_arg_dataset, None)
        if src_loaded_defs:
            src_loaded_strs = self.extract_defs_value_to_str(src_loaded_defs, truncate_flag=True)
            str_data_dict = {}
            offset = 0
            str_to_ints = set()
            for src_loaded_str in src_loaded_strs:
                str_to_int = utils.str_to_int(src_loaded_str)
                str_to_ints.add(str_to_int)

            for str_to_int in str_to_ints:
                str_data_dict[offset] = {claripy.BVV(str_to_int, 32)}
                offset += 1

            if str_data_dict:
                data = MultiValues(offset_to_values=str_data_dict)
                cc = angr.DEFAULT_CC[self._angr_project.arch.name]
                return_register = cc.RETURN_VAL
                reg_offset, reg_size = self._angr_project.arch.registers[return_register.reg_name]
                state.kill_and_add_definition(Register(reg_offset, reg_size), codeloc, data)
                return True, state

        return False, state

    def _handle_memcpy(self, state, codeloc, dst_arg_dataset, src_arg_dataset, cp_sz_dataset):

        max_size = -1
        if not src_arg_dataset or not dst_arg_dataset:
            self._logger.debug("_handle_memcpy: src and dst buffer should not be nul")
            return False, state
        else:
            src_loaded_defs = self.load_core(state, codeloc, src_arg_dataset, cp_sz_dataset)
            if src_loaded_defs:
                src_loaded_strs = self.extract_defs_value_to_str(src_loaded_defs, truncate_flag=True)
                is_alert = self.store_core(state, codeloc, dst_arg_dataset, src_loaded_strs)
                if is_alert:
                    self.save_alert_info()
            return False, state

    def _handle_memset(self, state, codeloc, src_arg_dataset, memset_value_dataset, memset_size_dataset):

        if not src_arg_dataset or not memset_size_dataset:
            return False, state

        set_chars = set()
        for memset_value in memset_value_dataset:
            if memset_value.op == 'BVV' and len(memset_value.args) == 2:
                if memset_value.args[0] > 0 and memset_value.args[0] < 255:
                    set_char = chr(memset_value.args[0])
                else:
                    set_char = "0"
                set_chars.add(set_char)

        if not set_chars:
            set_chars.add('0')

        set_strs = set()
        for memset_size in memset_size_dataset:
            if memset_size.op == 'BVV' and len(memset_size.args) == 2:
                set_size = memset_size.args[0]
                for set_char in set_chars:
                    set_strs.add(set_char * set_size)

        is_alert = self.store_core(state, codeloc, src_arg_dataset, list(set_strs))
        if is_alert and self._vul_type == 'bof':
            self.save_alert_info()
        return False, state

    def _handle_strcat(self, state, codeloc, dst_arg_dataset, src_arg_dataset):

        src_loaded_defs = self.load_core(state, codeloc, src_arg_dataset, None)
        src_loaded_strs = self.extract_defs_value_to_str(src_loaded_defs, truncate_flag=True)

        dst_loaded_defs = self.load_core(state, codeloc, dst_arg_dataset, None)
        dst_loaded_strs = self.extract_defs_value_to_str(dst_loaded_defs, truncate_flag=True)

        if src_loaded_strs and dst_loaded_strs:
            saved_strs = set()
            for dst_loaded_str in dst_loaded_strs:
                for src_loaded_str in src_loaded_strs:
                    saved_strs.add(dst_loaded_str + src_loaded_str)

            is_alert = self.store_core(state, codeloc, dst_arg_dataset, list(saved_strs))
            if is_alert:
                self.save_alert_info()
        return False, state

    def _handle_strncat(self, state, codeloc, dst_arg_dataset, src_arg_dataset, sz_arg_dataset):

        src_loaded_defs = self.load_core(state, codeloc, src_arg_dataset, sz_arg_dataset)
        src_loaded_strs = self.extract_defs_value_to_str(src_loaded_defs, truncate_flag=True)

        dst_loaded_defs = self.load_core(state, codeloc, dst_arg_dataset, None)
        dst_loaded_strs = self.extract_defs_value_to_str(dst_loaded_defs, truncate_flag=True)

        if src_loaded_strs and dst_loaded_strs:
            saved_strs = set()
            for dst_loaded_str in dst_loaded_strs:
                for src_loaded_str in src_loaded_strs:
                    saved_strs.add(dst_loaded_strs + src_loaded_str)

            is_alert = self.store_core(state, codeloc, dst_arg_dataset, list(saved_strs))
            if is_alert:
                self.save_alert_info()

        return False, state

    def _handle_strstr(self, state, codeloc, dst_arg_dataset, src_arg_dataset):

        src_defs = self.load_core(state, codeloc, src_arg_dataset, None)
        src_strs = []
        if src_defs:
            src_strs = self.extract_defs_value_to_str(src_defs, truncate_flag=True)

        if src_strs:
            str_data_dict = collections.defaultdict(set)
            for dst_point in dst_arg_dataset:
                dst_loaded_def = self.load_one_core(state, codeloc, dst_point, None)
                char_pos = []
                if dst_loaded_def:
                    dst_loaded_str = self.extract_def_value_to_str(state, codeloc, dst_loaded_def, truncate_flag=False)
                    offset = 0

                    for src_str in src_strs:
                        char_pos = dst_loaded_str.find(src_str)
                        if char_pos == -1:
                            str_data_dict[offset].add(claripy.BVV('\x00\x00\x00\x00\x00\x00\x00\x00'))
                        else:
                            str_data_dict[offset].add(dst_point + char_pos)
                        offset += 1

            BV_0 = claripy.BVV('\x00\x00\x00\x00')
            offset = 0
            for value in str_data_dict.values():
                if BV_0 in value and len(value) > 1:
                    str_data_dict[offset].remove(BV_0)
                offset += 1

            if str_data_dict:
                data = MultiValues(offset_to_values=str_data_dict)
                cc = angr.DEFAULT_CC[self._angr_project.arch.name]
                return_register = cc.RETURN_VAL
                reg_offset, reg_size = self._angr_project.arch.registers[return_register.reg_name]
                state.kill_and_add_definition(Register(reg_offset, reg_size), codeloc, data)
                return True, state

            else:
                return False, state

        else:
            return False, state

    def _handle_strchr(self, state, codeloc, dst_arg_datset, src_arg_dataset):

        check_chars = set()
        for src_arg in src_arg_dataset:
            if src_arg.op == 'BVV' and len(src_arg.args) == 2:
                check_chars.add(chr(src_arg.args[0]))

        str_data_dict = collections.defaultdict(set)

        for dst_point in dst_arg_datset:
            dst_loaded_def = self.load_one_core(state, codeloc, dst_point, None)
            char_pos = []
            if dst_loaded_def:
                dst_loaded_str = self.extract_def_value_to_str(state, codeloc, dst_loaded_def, truncate_flag=False)
                offset = 0

                for check_char in check_chars:
                    char_pos = dst_loaded_str.find(check_char)
                    if char_pos == -1:
                        str_data_dict[offset].add(claripy.BVV('\x00\x00\x00\x00'))
                    else:
                        str_data_dict[offset].add(dst_point + char_pos)
                    offset += 1

        BV_0 = claripy.BVV('\x00\x00\x00\x00')
        offset = 0
        for value in str_data_dict.values():
            if BV_0 in value and len(value) > 1:
                str_data_dict[offset].remove(BV_0)

            offset += 1
        if str_data_dict:
            data = MultiValues(offset_to_values=str_data_dict)
            cc = angr.DEFAULT_CC[self._angr_project.arch.name]
            return_register = cc.RETURN_VAL
            reg_offset, reg_size = self._angr_project.arch.registers[return_register.reg_name]
            state.kill_and_add_definition(Register(reg_offset, reg_size), codeloc, data)

            return True, state

        else:
            return False, state

    def _handle_strrchr(self, state, codeloc, dst_arg_datset, src_arg_dataset):

        check_chars = set()
        for src_arg in src_arg_dataset:
            if src_arg.op == 'BVV' and len(src_arg.args) == 2:
                check_chars.add(chr(src_arg.args[0]))

        str_data_dict = collections.defaultdict(set)

        for dst_point in dst_arg_datset:
            dst_loaded_def = self.load_one_core(state, codeloc, dst_point, None)
            char_pos = []
            if dst_loaded_def:
                dst_loaded_str = self.extract_def_value_to_str(state, codeloc, dst_loaded_def, truncate_flag=False)
                offset = 0

                for check_char in check_chars:
                    char_pos = dst_loaded_str.rfind(check_char)
                    if char_pos == -1:
                        str_data_dict[offset].add(claripy.BVV('\x00\x00\x00\x00'))
                    else:
                        str_data_dict[offset].add(dst_point + char_pos)
                    offset += 1

        BV_0 = claripy.BVV('\x00\x00\x00\x00')
        offset = 0
        for value in str_data_dict.values():
            if BV_0 in value and len(value) > 1:
                str_data_dict[offset].remove(BV_0)

            offset += 1
        if str_data_dict:
            data = MultiValues(offset_to_values=str_data_dict)
            cc = angr.DEFAULT_CC[self._angr_project.arch.name]
            return_register = cc.RETURN_VAL
            reg_offset, reg_size = self._angr_project.arch.registers[return_register.reg_name]
            state.kill_and_add_definition(Register(reg_offset, reg_size), codeloc, data)

            return True, state

        else:
            return False, state

    def _handle_strcpy(self, state, codeloc, dst_arg_dataset, src_arg_dataset):

        if not src_arg_dataset or not dst_arg_dataset:
            self._logger.debug("_handle_strcpy:source and dst should not be null")
            return False, state
        else:
            src_loaded_defs = self.load_core(state, codeloc, src_arg_dataset, None)
            src_loaded_strs = self.extract_defs_value_to_str(src_loaded_defs, truncate_flag=True)

            is_alert = self.store_core(state, codeloc, dst_arg_dataset, src_loaded_strs)
            if is_alert and self._vul_type == 'bof':
                self.save_alert_info()
            return False, state

    def _handle_strlen(self, state:ReachingDefinitionsState, codeloc, src_arg_dataset):
        if not src_arg_dataset:
            self._logger.debug("_handle_strlen:source dataset should not be null.")
            return False, state
        else:
            try:
                loaded_defs = self.load_core(state, codeloc, src_arg_dataset, None)
                loaded_strs = self.extract_defs_value_to_str(loaded_defs, truncate_flag=True)

                offset = 0
                str_data_dict = {}
                if loaded_strs:
                    for str_data in loaded_strs:
                        str_len = len(str_data)
                        str_data_dict[offset] = {claripy.BVV(str_len, self._arch_bits)}
                        offset += 1

                    data = MultiValues(offset_to_values=str_data_dict)
                    cc = angr.DEFAULT_CC[self._angr_project.arch.name]
                    return_register = cc.RETURN_VAL
                    reg_offset, reg_size = self._angr_project.arch.registers[return_register.reg_name]
                    state.kill_and_add_definition(Register(reg_offset, reg_size), codeloc, data)
                    return False, state
                else:
                    return False, state
            except:
                return False, state

    def _handle_strncpy(self, state, codeloc, dst_arg_dataset, src_arg_dataset, cp_sz_dataset):

        max_size = -1
        if not src_arg_dataset or not dst_arg_dataset:
            self._logger.debug("_handle_strncpy: src and dst buffer should not be null.")
            return False, state
        else:
            src_loaded_defs = self.load_core(state, codeloc, src_arg_dataset, cp_sz_dataset)
            if src_loaded_defs:
                src_loaded_strs = self.extract_defs_value_to_str(src_loaded_defs, truncate_flag=True)
                is_alert = self.store_core(state, codeloc, dst_arg_dataset, src_loaded_strs)
                if is_alert:
                    self.save_alert_info()
            return False, state

    def _handle_strtok(self, state, codeloc, dst_arg_dataset, src_arg_dataset):

        if not src_arg_dataset or not dst_arg_dataset:
            self._logger.debug("_handle_strtok: src and dst buffer should not be null")
            return False, state
        else:
            src_loaded_defs = self.load_core(state, codeloc, src_arg_dataset, None)
            dst_loaded_defs = self.load_core(state, codeloc, dst_arg_dataset, None)

            if src_loaded_defs:
                src_loaded_strs = self.extract_defs_value_to_str(src_loaded_defs, truncate_flag=True)

            if dst_loaded_defs:
                dst_loaded_strs = self.extract_defs_value_to_str(dst_loaded_defs, truncate_flag=True)

            #assert isinstance(dst_loaded_strs, MultiValues)
            #dst_loaded_strs.one_value()

            # is_alert = self.store_core(state, codeloc, dst_arg_dataset, src_loaded_strs)
            # if is_alert:
            # self.alert_info.append([codeloc])
            return False, state

    def _handle_skip_libc_func(self, state, codeloc):
        return False, state

    def _is_args_tainted(self, function_address, state):
        #functions = self._angr_project.kb.functions
        cfg = self._cfg

        function = self._angr_project.kb.functions.get_by_addr(function_address)
        livedefs = state.live_definitions

        cc = function.calling_convention
        if not cc:
            cc_result = self._angr_project.analyses.CallingConvention(function, cfg, analyze_callsites=True)
            cc = cc_result.cc

        if not cc:
            return True

        for arg in cc.int_args:
            if isinstance(arg, SimRegArg):
                reg_offset, reg_size = self._angr_project.arch.registers[arg.reg_name]
                try:
                    arg_defs = livedefs.register_definitions.load(reg_offset, reg_size)
                except SimMemoryMissingError:
                    return

            elif isinstance(arg, SimStackArg):
                arg_defs = livedefs.stack_definitions.get_objects_by_offset(arg.stack_offset)

            else:
                continue

            for arg_def_values in arg_defs.values():
                for arg_def_value in arg_def_values:
                    arg_value = list(livedefs.extract_defs(arg_def_value))
                    is_arg_tainted = self.is_tainted(self._analysis.dep_graph, arg_value)
                    if is_arg_tainted:
                        break

            if is_arg_tainted:
                return True

        return False

    def is_tainted(self, rda_dep_graph, rda_arg_def):
        # arg_data = rda_arg_def.data
        is_tainted = False

        if not rda_arg_def:
            return False

        self_tags = rda_arg_def[0].tags
        for self_tag in self_tags:
            if isinstance(self_tag, TaintedVariableTag):
                return True

        if isinstance(rda_arg_def[0], TaintedData):
            return True

        elif not isinstance(rda_arg_def[0], int):
            try:
                deps = rda_dep_graph.transitive_closure(rda_arg_def[0])
            except:
                is_tainted = False
                deps = []
            for dep in deps:

                dep_tg = dep.tags
                if dep_tg != None:
                    for i, name in enumerate(dep_tg):
                        if isinstance(name, TaintedVariableTag):
                            is_tainted = True
                            return is_tainted

        return is_tainted

    def load_core(self, state: ReachingDefinitionsState, codeloc, addr_dataset: set, sz_dataset: set) -> list:
        sz_values = set()
        loaded_defs = []

        if sz_dataset:
            for sz_data in sz_dataset:
                if sz_data.op == 'BVV':
                    sz_value = sz_data.args[0]
                    sz_values.add(sz_value)
        if not sz_values:
            #return loaded_defs
            sz_values.add(1000)

        for addr in addr_dataset:
            for sz_value in sz_values:
                if state.is_top(addr):
                    continue

                elif state.is_stack_address(addr):
                    stack_offset = state.get_stack_offset(addr)
                    if stack_offset is not None:
                        stack_addr = state.live_definitions.stack_offset_to_stack_addr(stack_offset)
                        if self._arch_bits == 64:
                            stack_default_max_size = 0xffffffffffffffff
                        else:
                            stack_default_max_size = 0xffffffff

                        if stack_offset > 0:
                             max_load_sz_in_stack = stack_default_max_size - stack_offset + 1
                        else:
                            max_load_sz_in_stack = -stack_offset

                        """
                        TODO: Expand more size in stack
                        """
                        if sz_value > max_load_sz_in_stack:
                            if sz_value != 1000:
                                self._logger.warning("The length of data is larger than stack buffer")

                            sz_value = max_load_sz_in_stack

                        data_from_stack = None
                        count_num = sz_value

                        while(count_num > 0):
                            try:
                                data_from_stack:MultiValues = state.stack_definitions.load(stack_addr, size=count_num)
                                #data_from_stack: MultiValues = state.stack_definitions.load(stack_addr, size=sz_value)
                                loaded_defs.append(data_from_stack)
                                break
                            except Exception as e:
                                count_num -= 1
                                continue
                        # loaded_defs = loaded_defs.merge(data_from_stack) if loaded_defs is not None else data_from_stack

                elif state.is_heap_address(addr):
                    heap_offset = state.get_heap_offset(addr)
                    data_from_heap: MultiValues = state.heap_definitions.load(heap_offset)
                    loaded_defs.append(data_from_heap)
                else:
                    addr_value = addr._model_concrete.value

                    # If the addr is in the range of program loader memory
                    if (addr_value < self._angr_project.loader.memory.max_addr) and \
                            (addr_value > self._angr_project.loader.memory.min_addr):

                        tmp_sz_value = sz_value
                        if sz_value > 8192:
                            continue

                        while(tmp_sz_value > 0):
                            try:
                                data_from_memory = state.memory_definitions.load(addr_value, tmp_sz_value)
                                loaded_defs.append(data_from_memory)
                                break
                            except:
                                tmp_sz_value -= 1

                        if len(loaded_defs) == 0:
                            try:
                                load_bytes = self._angr_project.loader.memory.load(addr_value, sz_value)
                                loaded_defs.append(load_bytes)
                            except:
                                continue

                    # If the addr is in the virtual range of the program
                    elif addr_value >= self._virtual_addresses[0] and addr_value <= self._virtual_addresses[
                        self._virtual_addresses_used_num]:
                        if sz_value > 1000:
                            sz_value = 1000

                        for virtual_address in self._virtual_addresses:
                            if addr_value >= virtual_address and addr_value < (virtual_address + 1000):
                                max_read_addr_value = addr_value + sz_value
                                if max_read_addr_value > virtual_address + 1000:
                                    sz_value = virtual_address + 1000 - addr_value
                                break
                        try:
                            data_from_memory = state.memory_definitions.load(addr_value, sz_value)
                            loaded_defs.append(data_from_memory)

                        except:
                            continue

                    else:
                        continue
        return loaded_defs

    def load_data(self, state, addr_dataset, sz_dataset=None):
        sizes = set()
        assert isinstance(state, ReachingDefinitionsState)
        addr_values = set()
        sz_values = []

        for addr_data in addr_dataset:
            if addr_data.op == 'BVV':
                addr_data_bitvector = addr_data
                addr_value = addr_data_bitvector.args[0]
                addr_values.add(addr_value)

        if sz_dataset:
            for sz_data in sz_dataset:
                if sz_data.op == 'BVV':
                    sz_data_bitvector = sz_data
                    sz_value = sz_data_bitvector.args[0]
                    sz_values.append(sz_value)

        if addr_values:
            loaded_data = set()
            for addr_value in addr_values:
                if not sz_values:
                    sz_values.append(1000)
                for tmp_sz_value in sz_values:

                    if (addr_value < self._angr_project.loader.memory.max_addr) and \
                            (addr_value > self._angr_project.loader.memory.min_addr):
                        str_bytes = self._angr_project.loader.memory.load(addr_value, tmp_sz_value)
                        loaded_data.add(str_bytes)

                    elif addr_value >= self._virtual_addresses[0] and addr_value <= self._virtual_addresses[
                        self._virtual_addresses_used_num]:

                        if tmp_sz_value > 1000:
                            tmp_sz_value = 1000
                        for now_virtual_address in self._virtual_addresses:
                            if addr_value >= now_virtual_address and addr_value < (now_virtual_address + 1000):
                                tmp_sz_value = now_virtual_address + 1000 - addr_value
                                break

                        value_data = state.memory_definitions.load(addr_value, tmp_sz_value)
                        for value_data_values in value_data.values():
                            for tmp_value in value_data_values:
                                if tmp_value.op == "BVV":
                                    str_bytes = tmp_value.args[0].to_bytes(tmp_sz_value, 'big')
                                    loaded_data.add(str_bytes)
                    else:
                        continue
            return loaded_data
        else:
            return None

    def load_string(self, state, codeloc, addr_dataset, sz_dataset=None) -> set:
        loaded_data_defs = self.load_core(state, codeloc, addr_dataset, sz_dataset)
        loaded_data_strs = self.extract_defs_value_to_str(loaded_data_defs, truncate_flag=True)

        """
        str_data = set()
        if loaded_data:
            for str_bytes in loaded_data:
                if 0 in str_bytes:
                    str_bytes = str_bytes[:str_bytes.find(0)]

                str_data.add(str_bytes.decode("utf-8", errors="backslashreplace"))
        else:
            str_data = set()
        return str_data
        """
        return set(loaded_data_strs)

    def extract_defs_value_to_str(self, loaded_defs: list, truncate_flag: bool) -> list:
        loaded_strs = []
        for loaded_def in loaded_defs:
            if isinstance(loaded_def, bytes):
                loaded_strs.append(loaded_def)
            elif isinstance(loaded_def, MultiValues):
                vls = next(iter(loaded_def.values()))
                for vl in vls:
                    if vl.op == "BVV" and vl.args[0] and vl.args[1]:
                        loaded_str = vl.args[0].to_bytes(int(vl.args[1] / 8), 'big')
                        loaded_strs.append(loaded_str)
                    elif vl.op == "Concat":
                        vl_first_arg = vl.args[0]
                        if vl_first_arg.op == "BVV": #and vl_first_arg[0] and vl_first_arg[1]:
                            loaded_str = vl_first_arg.args[0].to_bytes(int(vl_first_arg.args[1]/8), 'big')
                            loaded_strs.append(loaded_str)
            else:
                continue

        str_data = []
        if loaded_strs:
            for loaded_str in loaded_strs:
                if truncate_flag:
                    if 0 in loaded_str:
                        loaded_str = loaded_str[:loaded_str.find(0)]

                str_data.append(loaded_str.decode("utf-8", errors="backslashreplace"))

        return str_data

    def store_core(self, state: ReachingDefinitionsState, codeloc, dst_addrs: set, store_datas: list, taint_tag=None):
        # dst_addrs = next(iter(dst_arg_dataset.values.values()))
        for addr in dst_addrs:
            if state.is_top(addr):
                continue
            else:
                for store_data in store_datas:
                    size = len(store_data)
                    # if size == 0:
                    #    continue
                    if type(store_data).__name__ == 'bytes':
                        store_data_str = store_data.decode()
                    else:
                        store_data_str = store_data
                    data = MultiValues(
                        offset_to_values={
                            0: {
                                claripy.BVV(
                                    store_data_str + '\x00'
                                )
                            }
                        }
                    )

                    if state.is_stack_address(addr):
                        stack_offset = state.get_stack_offset(addr)
                        if self._arch_bits == 64:
                            stack_default_max_size = 0xffffffffffffffff
                        else:
                            stack_default_max_size = 0xffffffff

                        if stack_offset < 0:
                            max_store_sz_in_stack = -stack_offset
                        else:
                            max_store_sz_in_stack = stack_default_max_size - stack_offset + 1
                        if size > max_store_sz_in_stack:
                            return True
                        atom = MemoryLocation(SpOffset(self._angr_project.arch.bits, state.get_stack_offset(addr)),
                                              size)

                        function_address = None  # we cannot get the function address in the middle of a store if a CFG
                        tags = taint_tag
                        # does not exist. you should backpatch the function address later using
                        # the 'ins_addr' metadata entry.
                        # tags = {LocalVariableTag(
                        #    function=function_address,
                        #    metadata={'tagged_by': 'SimEngineRDVEX._store_core',
                        #              'ins_addr': codeloc}
                        # )}

                    elif state.is_heap_address(addr):
                        atom = MemoryLocation(HeapAddress(state.get_heap_offset(addr)), size)
                        tags = taint_tag

                    elif len(addr.args) == 2 and addr.op == "BVV":
                        atom = MemoryLocation(addr._model_concrete.value, size)
                        tags = taint_tag

                    else:
                        continue

                    state.live_definitions.kill_and_add_definition(atom, codeloc, data, tags=tags)
                    return False

    def extract_def_value_to_str(self, state, codeloc, loaded_def, truncate_flag):
        loaded_str = ''
        if isinstance(loaded_def, bytes):
            loaded_str = loaded_def
        elif isinstance(loaded_def, MultiValues):
            vls = next(iter(loaded_def.values()))
            for vl in vls:
                if vl.op == "BVV" and vl.args[0] and vl.args[1]:
                    loaded_str = vl.args[0].to_bytes(int(vl.args[1] / 8), 'big')
        else:
            loaded_str = ''

        if truncate_flag:
            if 0 in loaded_str:
                loaded_str = loaded_str[:loaded_str.find(0)]

        if loaded_str!='':
            str_data = loaded_str.decode("utf-8", errors="backslashreplace")
        else:
            str_data = ''

        return str_data

    def load_one_core(self, state:ReachingDefinitionsState, codeloc, addr, sz_dataset):
        sz_values = set()
        loaded_defs = []

        if sz_dataset:
            for sz_data in sz_dataset:
                if sz_data.op == 'BVV':
                    sz_value = sz_data.args[0]
                    sz_values.add(sz_value)
        if not sz_values:
            sz_values.add(1000)

        for sz_value in sz_values:
            if state.is_top(addr):
                continue

            elif state.is_stack_address(addr):
                stack_offset = state.get_stack_offset(addr)
                if stack_offset is not None:
                    stack_addr = state.live_definitions.stack_offset_to_stack_addr(stack_offset)

                    if self._arch_bits == 64:
                        stack_default_max_size = 0xffffffffffffffff
                    else:
                        stack_default_max_size = 0xffffffff

                    max_load_sz_in_stack = stack_default_max_size - stack_offset + 1
                    if sz_value > max_load_sz_in_stack:
                        sz_value = max_load_sz_in_stack

                    try:
                        data_from_stack: MultiValues = state.stack_definitions.load(stack_addr, size=sz_value)
                        return data_from_stack
                        # loaded_defs.append(data_from_stack)
                    except Exception as e:
                        continue
                    # loaded_defs = loaded_defs.merge(data_from_stack) if loaded_defs is not None else data_from_stack

            elif state.is_heap_address(addr):
                heap_offset = state.get_heap_offset(addr)
                data_from_heap: MultiValues = state.heap_definitions.load(heap_offset)
            else:
                addr_value = addr._model_concrete.value

                # If the addr is in the range of program loader memory
                if (addr_value < self._angr_project.loader.memory.max_addr) and \
                        (addr_value > self._angr_project.loader.memory.min_addr):
                    try:
                        load_bytes = self._angr_project.loader.memory.load(addr_value, sz_value)
                        return load_bytes
                        # loaded_defs.append(load_bytes)

                    except:
                        continue

                # If the addr is in the virtual range of the program
                elif addr_value >= self._virtual_addresses[0] and addr_value <= self._virtual_addresses[
                    self._virtual_addresses_used_num]:
                    if sz_value > 1000:
                        sz_value = 1000

                    for virtual_address in self._virtual_addresses:
                        if addr_value >= virtual_address and addr_value < (virtual_address + 1000):
                            sz_value = virtual_address + 1000 - addr_value
                            break
                    try:
                        data_from_memory = state.memory_definitions.load(addr_value, sz_value)
                        return data_from_memory
                        # loaded_defs.append(data_from_memory)

                    except:
                        continue

                else:
                    continue

        return None

    def get_input_limitation(self, state, input_limit_args):
        limit_size = None
        limit_buffer = None
        limit_chars = None
        max_size = 0
        if input_limit_args[0] == 'LEN':
            arg_ix = input_limit_args[1]
            arg_defs = utils.get_arg_defs(self._angr_project, state, arg_ix)
            if arg_defs:
                size_data = set()
                for arg_def_values in arg_defs.values():
                    for arg_def_value in arg_def_values:
                        size_data.add(arg_def_value)

                for size_def_value in size_data:
                    if size_def_value.op == 'BVV' and len(size_def_value.args) > 0:
                        size = size_def_value.args[0]
                        max_size = size if size > max_size else max_size

        elif input_limit_args[0] == 'LEN_MUL':
            arg_ix_1 = input_limit_args[1]
            arg_ix_2 = input_limit_args[2]

            arg_ix_1_defs = utils.get_arg_defs(self._angr_project, state, arg_ix_1)
            arg_ix_2_defs = utils.get_arg_defs(self._angr_project, state, arg_ix_2)

            if arg_ix_1_defs and arg_ix_2_defs:
                size_data_in_arg1 = set()
                size_data_in_arg2 = set()
                for arg_def_values in arg_ix_1_defs.values():
                    for arg_def_value in arg_def_values:
                        size_data_in_arg1.add(arg_def_value)

                for arg_def_values in arg_ix_2_defs.values():
                    for arg_def_value in arg_def_values:
                        size_data_in_arg2.add(arg_def_value)

                arg1_max_size = 0
                arg2_max_size = 0

                for arg1_size_def_value in size_data_in_arg1:
                    if arg1_size_def_value.op == 'BVV' and len(arg1_size_def_value.args) > 0:
                        size = arg1_size_def_value.args[0]
                        arg1_max_size = size if size > max_size else arg1_max_size

                for arg2_size_def_value in size_data_in_arg2:
                    if arg2_size_def_value.op == 'BVV' and len(arg2_size_def_value.args) > 0:
                        size = arg2_size_def_value.args[0]
                        arg2_max_size = size if size > max_size else arg2_max_size

                max_size = arg1_max_size * arg2_max_size

        limit_size = max_size if max_size > 0 else None

        return limit_size, limit_buffer, limit_chars

    def set_initial_source_def_val(self, limit_size=None, limit_char=None):
        if self._vul_type == 'bof':
            default_size = limit_size if limit_size else 999
            source_value = default_size * b"a"

        elif self._vul_type == "ci":
            source_value = ";telnetd &;".encode()

        elif self._vul_type == "fmt":
            source_value = b"%s" * 100

        elif self._vul_type == "predictseed":
            source_value = b"predictseed"

        elif self._vul_type == "useofhttp":
            source_value = b"useofhttp"

        elif self._vul_type == "taintpath":
            source_value = b"*.txt"

        elif self._vul_type == "sqltaint":
            source_value = b"' or '1'='1"

        elif self._vul_type == "csrf":
            source_value = b"csrf"

        else:
            source_value = b"any value"

        return source_value