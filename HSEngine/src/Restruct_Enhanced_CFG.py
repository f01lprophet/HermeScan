import idaapi
import idc
import idautils
import ida_auto

from config import STRINGS_PATH
from ControlFlowRecovery import CreateFunction, utils, LocateCandidateFunctions

idc.auto_wait()
min_addr, max_addr = utils.get_min_max_addr()
arch, bits, endian = utils.get_program_arch()
file_path = utils.get_file_path()
file_name = utils.get_file_name()
create_func_num = CreateFunction.create_function(arch, min_addr, max_addr)
source_functions_list = LocateCandidateFunctions.my_run(STRINGS_PATH)
CreateFunction.get_functions_list(create_func_num, source_functions_list)
idc.qexit(0)