import logging

import angr
import func_timeout
from angr.analyses.reaching_definitions.external_codeloc import ExternalCodeLocation
from angr.storage.memory_mixins.paged_memory.pages.multi_values import MultiValues
from func_timeout import func_set_timeout

import networkx
import pickle
import angr.analyses.reaching_definitions.dep_graph as dep_graph
from angr.knowledge_plugins.key_definitions.constants import OP_BEFORE, OP_AFTER
from angr.knowledge_plugins.key_definitions.tag import ReturnValueTag
from angr.knowledge_plugins.key_definitions.undefined import Undefined
from angr.analyses.reaching_definitions.subject import SubjectType

import sys
import os

from HSEngine.src.MyHandler.RDATaintHandler import TaintHandler, TaintedVariableTag

sys.path.append("..\\")
#from MyHandler.RDATaintHandler import TaintHandler

class _MockFunctionSubject:  # pylint:disable=too-few-public-methods
    class _MockFunction:  # pylint:disable=too-few-public-methods
        def __init__(self):
            self.addr = 0xF934

    def __init__(self):
        self.type = SubjectType.Function
        self.cc = None  # pylint:disable=invalid-name
        self.content = self._MockFunction()


class PotenialPath():
    def __init__(self, source_caller_function_addrs:int):
                 #sink_caller_function_addrs:set, source_point:dict, sink_point:dict):
        self.source_caller_function_addrs = source_caller_function_addrs
        self.sink_caller_function_addrs = set()
        self.source_points = []
        self.sink_points = []

    def add_source_point(self, node_info):
        self.source_points.append(node_info)

    def add_sink_point(self, node_info):
        self.sink_points.append(node_info)

class HermeScan():
    def __init__(self, bin_name, vul_type, ida_function_addresses=None, project=None, cfg=None, function_summaries=None,
                 p_logger=None):
        self.bin_name = bin_name
        self.vul_type = vul_type
        if not project and not cfg:
            project, cfg = self.preload_bin(bin_name, ida_function_addresses)

        self.bin_project = project
        self.bin_cfg = cfg
        self.sources_info = None
        self.sinks_info = None
        self.function_summaries = function_summaries
        self.logger = p_logger
        self.potential_paths = []

    def get_callers(self, address_f=None, name_f=None):
        to_analyze = []

        """
        Get the address of sub-like functions
        """

        if name_f.startswith("sub_"):
            func_addr = int(name_f.split('sub_')[1], 16)
            if func_addr < 0x400000:
                func_addr += 0x400000
        else:
            func_addr = None

        if address_f:
            nodes = [x for x in self.bin_cfg.nodes() if x.addr == address_f]
            if nodes:
                node = nodes[0]
                preds =self.bin_cfg.get_predecessors(node)
                to_analyze += [(p.function_address, p, name_f) for p in preds]

            return to_analyze

        if name_f:
            prefix_name_f = '.' + name_f
            if name_f in self.bin_project.loader.main_object.plt:
                plt_addr = self.bin_project.loader.main_object.plt[name_f]
                node = [x for x in self.bin_cfg.nodes() if x.addr == plt_addr]
                if node:
                    node = node[0]
                    preds = self.bin_cfg.get_predecessors(node)
                    to_analyze += [(p.function_address, p, name_f, node) for p in preds]

                    # in this case, although the plt section is existed, the program may not load function by plt
                    if not to_analyze:
                        for (i, angr_default_function) in self.bin_cfg.functions.items():
                            if angr_default_function.name == name_f and angr_default_function.addr!= plt_addr:
                                ext_addr = angr_default_function.addr
                                ext_node = [x for x in self.bin_cfg.nodes() if x.addr == ext_addr]
                                if ext_node:
                                    ext_node = ext_node[0]
                                    ext_preds = self.bin_cfg.get_predecessors(ext_node)
                                    to_analyze += [(p.function_address, p, name_f, node) for p in ext_preds]

            elif name_f in self.bin_project.kb.functions.keys():
                plt_addr = self.bin_project.kb.functions[name_f].addr
                node = [x for x in self.bin_cfg.nodes() if x.addr == plt_addr]
                if node:
                    node = node[0]
                    preds = self.bin_cfg.get_predecessors(node)
                    to_analyze += [(p.function_address, p, name_f, node) for p in preds]

            elif func_addr:
                if func_addr in self.bin_project.kb.functions.keys():
                    node = [x for x in self.bin_cfg.nodes() if x.addr == func_addr]
                    if node:
                        node = node[0]
                        preds = self.bin_cfg.get_predecessors(node)
                        to_analyze += [(p.function_address, p, name_f, node) for p in preds]

            return to_analyze

        else:
            self.logger.warning("Function address or name need to be offered!")
            return None

    def get_potential_paths(self):
        sources_info = self.sources_info
        sinks_info = self.sinks_info
        potential_paths = []
        cg = self.bin_cfg.functions.callgraph
        for source_index, source_info in enumerate(sources_info):
            source_caller_function_addr = source_info[0]
            source_node = source_info[1]
            source_function_name = source_info[2]
            exist_path = False

            # First traverse the known path and check if there is a calling function at the source point
            for cf_path in potential_paths:
                if source_caller_function_addr == cf_path.source_caller_function_addrs:
                    potential_path = cf_path
                    exist_path = True
                    break

            if not exist_path:
                potential_path = PotenialPath(source_caller_function_addrs=source_caller_function_addr)

            for sink_info_index, sink_info in enumerate(sinks_info):
                sink_caller_function_addr = sink_info[0]
                sink_node = sink_info[1]
                sink_function_name = sink_info[2]
                source_dict = {}
                sink_dict = {}

                has_path = networkx.has_path(cg, source_caller_function_addr, sink_caller_function_addr)

                if has_path:
                    potential_path.sink_caller_function_addrs.add(sink_caller_function_addr)
                    source_dict[source_node] = source_function_name
                    sink_dict[sink_node] = sink_function_name

                    if source_dict not in potential_path.source_points:
                        potential_path.add_source_point(source_dict)

                    if sink_dict not in potential_path.sink_points:
                        potential_path.add_sink_point(sink_dict)

            if len(potential_path.sink_caller_function_addrs) > 0 and not exist_path:
                potential_paths.append(potential_path)

        self.logger.debug("Potential Paths need to be analyzed:{0}".format(len(potential_paths)))
        self.potential_paths = potential_paths

    def get_sinks_node(self, sink_functions_name, sink_addresses=[]):
        sinks = []
        for function_name in sink_functions_name:
            sinks += self.get_callers(name_f=function_name)

        """
        sinks = self.get_callers(name_f='strcpy')
        sinks += self.get_callers(name_f='strncpy')
        sinks += self.get_callers(name_f='strcat')
        sinks += self.get_callers(name_f='sprintf')
        sinks += self.get_callers(name_f='memcpy')

        sinks += self.get_callers(name_f='system')
        sinks += self.get_callers(name_f='doSystemCmd')
        sinks += self.get_callers(name_f='twsystem')
        sinks += self.get_callers(name_f='popen')
        """
        for sink_addresse in sink_addresses:
            sinks += [(x, sink_addresses[0])for x in self.get_callers(address_f=sink_addresses[1], name_f=sink_addresses[2])]
        #return sinks
        self.sinks_info = sinks
        return sinks

    def get_sources_node(self, source_functions_name=None, source_addresses=[]):
        sources = []
        for function_name in source_functions_name:
            sources += self.get_callers(name_f=function_name)
        """
        sources = [(x, ('RET',)) for x in self.get_callers(name_f='socket')]
        sources += [(x, ('RET', 0)) for x in self.get_callers(name_f='open')]
        sources += [(x, (0, 1)) for x in self.get_callers(name_f='read')]
        #sources += [(x, (0, 3)) for x in self.get_callers('fread')]
        #sources += [(x, ('RET', 0)) for x in self.get_callers('fopen')]
        sources += [(x, ('RET', 0)) for x in self.get_callers(name_f='open64')]
        sources += [(x, ('RET', 0)) for x in self.get_callers(name_f='fopen64')]
        sources += [(x, ('RET', 0)) for x in self.get_callers(name_f='getenv')]
        #sources += [(x, ('RET', 0, 1)) for x in self.get_callers(name_f='setenv')]
        sources += [(x, ('RET', 0)) for x in self.get_callers(name_f='pipe')]
        sources += [(x, ('RET', 0)) for x in self.get_callers(name_f='ftok')]
        sources += [(x, ('RET', 0)) for x in self.get_callers(name_f='shm_open')]
        """
        for source_address in source_addresses:
            sources += [(x, source_address)for x in self.get_callers(address_f=source_address)]

        self.sources_info = sources
        return sources

    def preload_bin(self, binary_path:str, ida_function_addresses:list):

        self.logger.info("Creating angr Project")
        project = angr.Project(binary_path, auto_load_libs=True)

        self.logger.info("Creating binary CFG")
        bin_cfg = project.analyses.CFG(resolve_indirect_jumps=True,
                               cross_references=True,
                               force_complete_scan=False,
                               function_starts = ida_function_addresses,
                               heuristic_plt_resolving = True,
                               normalize=False,
                               symbols=True)

        self.store_cfg(bin_cfg)
        self.store_angr_project(project)

        return project, bin_cfg

    def recover_symbol(self, functions_info):
        for(i, angr_default_function) in self.bin_cfg.functions.items():
            match_flag = False
            for function_info in functions_info:

                if angr_default_function.addr == int(function_info.func_addr):

                    if function_info.func_name.startswith('__imp_'):
                        break

                    if function_info.func_name.startswith('sub_'):
                        break

                    if angr_default_function.name.startswith('sub_'):
                        angr_default_function.name = function_info.func_name

    def recover_plt(self, functions_info):
        plts = self.bin_project.loader.main_object.plt
        imports = self.bin_project.loader.main_object.imports
        for i, function in self.bin_cfg.functions.items():
            if function.is_plt == True:
                plts[function.name] = function.addr

    def single_run(self, function_summaries, p_logger=None):

        """
        {('node', '0x42a59c', < ObservationPointType.OP_BEFORE: 0 >),
         ('node', '0x42a5f0', < ObservationPointType.OP_BEFORE: 0 >),
         ('node', '0x425454', < ObservationPointType.OP_BEFORE: 0 >),
         ('node', '0x4253f4', < ObservationPointType.OP_BEFORE: 0 >),
         ('node', '0x429c00', < ObservationPointType.OP_BEFORE: 0 >)}
         """

        state = self.bin_project.factory.blank_state()
        assert isinstance(self.bin_project, angr.Project)

        import claripy
        #string_addr = state.solver.BVV(0, 8 * string_len)
        #state.memory.store(string_addr, b'A' * string_len)

        self.function_summaries = function_summaries
        start_function = self.bin_cfg.functions.get_by_addr(0xF934)
        func = self.bin_cfg.functions[0xf934]
        taint_handler = TaintHandler(cfg=self.bin_cfg, source_functions_info=function_summaries, vul_type=self.vul_type,
                                     logger=p_logger)
        observation_points = []
        observation_point = ("insn", 0xF9D8 , OP_AFTER) #0x42a3ac, 0x42a1dc
        observation_points.append(observation_point)
        from angr.analyses.reaching_definitions import rd_state
        from angr.knowledge_plugins.key_definitions.live_definitions import LiveDefinitions

        live_def = LiveDefinitions(self.bin_project.arch)
        state = rd_state.ReachingDefinitionsState(self.bin_project.arch, subject=_MockFunctionSubject(), live_definitions=live_def)

        from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation, Register
        from angr.knowledge_plugins.key_definitions.definition import Definition
        test_arch = self.bin_project.arch

        reg_offset, reg_size = self.bin_project.arch.registers['r0']
        reg_atom = Register(reg_offset, reg_size)
        reg_def = Definition(reg_atom, ExternalCodeLocation(), tags={TaintedVariableTag()})
        r0 = state.annotate_with_def(claripy.BVV(0xf934, test_arch.bits), reg_def)
        state.register_definitions.store(reg_offset, r0)

        program_rda = self.bin_project.analyses.ReachingDefinitions(
            subject=start_function,
            #track_tmps = True,
            function_handler=taint_handler,
            observation_points=list(observation_points),
            maximum_local_call_depth=10000,
            #init_state = state,
            dep_graph=dep_graph.DepGraph()
        )


    def run(self, function_summaries):
        self.function_summaries = function_summaries

        all_possible_paths = self.potential_paths
        if len(all_possible_paths) > 0:
            alerts_info = []
            for possible_path in all_possible_paths:
                start_function = self.bin_cfg.functions.get_by_addr(possible_path.source_caller_function_addrs)

                taint_handler = TaintHandler(cfg=self.bin_cfg, source_functions_info=function_summaries, vul_type=self.vul_type,
                                             logger=self.logger)
                observation_points = set()
                for sink_points in possible_path.sink_points:
                    for sink_point_value in sink_points.keys():
                        observation_point_addr = sink_point_value.addr
                        observation_point = ("node", hex(observation_point_addr), OP_AFTER)
                        observation_points.add(observation_point)

                self.logger.info("Start Analyze Function at {0}".format(hex(possible_path.source_caller_function_addrs)))

                self.logger.debug(hex(possible_path.source_caller_function_addrs), observation_points)

                succ_num = 0
                fail_num = 0
                timeout_num = 0

                try:
                    self.run_taint_rda(start_function, taint_handler, observation_points)
                    succ_num += 1

                except func_timeout.exceptions.FunctionTimedOut:
                    timeout_num += 1
                    self.logger.warning("Timeout!\n")

                except Exception as ex:
                    fail_num += 1
                    self.logger.warning("Failed with reason {0}\n".format(ex))

            return alerts_info

    def store_angr_project(self, project):
        project._store(self.bin_name + '_angr')

    def store_cfg(self, bin_cfg):
        cfg_file = open(self.bin_name + '_cfg', 'wb')
        pickle.dump(bin_cfg, cfg_file, -1)
        cfg_file.seek(0)
        cfg_file.close()

    @func_set_timeout(60 * 5)
    def run_taint_rda(self, start_function, taint_handler, observation_points):
        program_rda = self.bin_project.analyses.ReachingDefinitions(
            subject=start_function,
            function_handler=taint_handler,
            observation_points=list(observation_points),
            dep_graph=dep_graph.DepGraph()
        )

        return taint_handler
