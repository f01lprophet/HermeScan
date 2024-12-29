from angr import DEFAULT_CC
import angr
from angr.calling_conventions import SimRegArg, SimStackArg
from angr.engines.light import SpOffset
from angr.knowledge_plugins.key_definitions.atoms import MemoryLocation
from angr.sim_type import parse_file, SimTypeInt
from angr.analyses.reaching_definitions.rd_state import ReachingDefinitionsState
from angr.analyses.reaching_definitions import get_all_definitions

def get_arg_defs(project, livedefs: 'ReachingDefinitionsState', arg_ix):

    arch = project.arch
    cc = angr.DEFAULT_CC[arch.name](arch)
    """
    we could use the prototype information from IDA
    execve = parse_file('int execve(const char *pathname, char *const argv[], char *const envp[]);')[0]['execve']
    print(execve)
    """

    n_arg_regs = len(cc.ARG_REGS)
    if arg_ix < n_arg_regs:
        tmp_r = cc.ARG_REGS[arg_ix]
        reg_offset, reg_size = project.arch.registers[tmp_r]
        arg_defs = livedefs.register_definitions.load(reg_offset, reg_size)

    else:
        current_sp_offset = livedefs.get_sp()
        stack_addr = (arg_ix - n_arg_regs) * project.arch.bytes * 4 + current_sp_offset
        stack_addr = current_sp_offset + 16

        """
        try to get all stack defs here
        
        all_stack_defs = get_all_definitions(livedefs.stack_definitions)
        defs_by_stack_offset = dict((-d.atom.addr.offset, d) for d in all_stack_defs
                                    if isinstance(d.atom, MemoryLocation) and isinstance(d.atom.addr, SpOffset))

        arg_session = cc.arg_session(SimTypeInt().with_arch(project.arch))
        for _ in range(30):  # at most 30 arguments
            arg_loc = cc.next_arg(arg_session, SimTypeInt().with_arch(project.arch))
            if isinstance(arg_loc, SimRegArg):
                reg_offset = project.arch.registers[arg_loc.reg_name][0]
                # is it initialized?
                print(reg_offset)
            elif isinstance(arg_loc, SimStackArg):
                if arg_loc.stack_offset in defs_by_stack_offset:
                    print("hello")
                else:
                    # no more arguments
                    break
            else:
                break
        """
        try:
            arg_defs = livedefs.stack_definitions.load(stack_addr, project.arch.byte_width)

        except:
            arg_defs = None

    return arg_defs

def str_to_int(self, src_loaded_str, limit=None):

    INT_MIN = None
    INT_MAX = None
    if limit == 'int':
        INT_MAX = 2147483647
        INT_MIN = -2147483648
    result = 0

    if not src_loaded_str:
        return result

    i = 0
    while i < len(src_loaded_str) and src_loaded_str[i] == " ":
        i += 1

    sign = 1
    if src_loaded_str[i] == "+":
        i += 1
    elif src_loaded_str[i] == "-":
        sign = -1
        i += 1

    while i < len(src_loaded_str) and src_loaded_str[i] >= '0' and src_loaded_str[i] <= '9':
        if INT_MIN and INT_MAX:
            if result > (INT_MAX - (ord(src_loaded_str[i]) - ord('0'))) / 10:
                return INT_MAX if sign > 0 else INT_MIN
        result = result * 10 + ord(src_loaded_str[i]) - ord('0')
        i += 1

    return sign * result