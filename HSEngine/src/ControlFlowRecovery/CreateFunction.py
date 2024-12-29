import idc
import idautils
import idaapi
import ida_funcs
import ida_nalt
from ControlFlowRecovery.utils import *

def create_function(arch, start_addr, end_addr)->int:
    make_func_num = 0
    if arch == 'ARM':
        tmp_addr = start_addr
        while True:
            insn = idc.generate_disasm_line(tmp_addr, 0)
            if "PUSH" in insn:
                if(idc.get_func_name(tmp_addr) == ""):
                    make_func_num += 1
                    prev_tmp_addr = idc.prev_head(tmp_addr)
                    prev_insn = idc.generate_disasm_line(prev_tmp_addr, 0)
                    if "SUB  " in prev_insn:
                        ida_funcs.add_func(prev_tmp_addr)
                    else:
                        ida_funcs.add_func(tmp_addr)

            if "STP             X29, X30" in insn:
                if(idc.get_func_name(tmp_addr) == ""):
                    make_func_num += 1
                    prev_tmp_addr = idc.prev_head(tmp_addr)
                    prev_insn = idc.generate_disasm_line(prev_tmp_addr, 0)
                    if "SUB             SP" in prev_insn:
                        ida_funcs.add_func(prev_tmp_addr)
                    else:
                        ida_funcs.add_func(tmp_addr)

            tmp_addr = idc.next_head(tmp_addr)
            if tmp_addr > end_addr:
                break
    
    elif arch == 'mipsl' or arch == 'mipsb':
        tmp_addr = start_addr
        while True:
            insn = idc.generate_disasm_line(tmp_addr, 0)
            if "addiu   $sp" in insn:
                if(idc.get_func_name(tmp_addr) == ""):
                    make_func_num += 1
                    prev_tmp_addr = idc.prev_head(tmp_addr)
                    prev_insn = idc.generate_disasm_line(prev_tmp_addr, 0)
                    if "lui     $gp" in prev_insn:
                        ida_funcs.add_func(prev_tmp_addr)
                    else:
                        ida_funcs.add_func(tmp_addr)
            
            if "addiu   $a0" in insn:
                if(idc.get_func_name(tmp_addr) == ""):
                    make_func_num += 1
                    next_tmp_addr = idc.next_head(tmp_addr)
                    next_insn = idc.generate_disasm_line(next_tmp_addr, 0)
                    if "lui     $gp" in next_insn:
                        ida_funcs.add_func(next_tmp_addr)
                    else:
                        ida_funcs.add_func(tmp_addr)

            tmp_addr = idc.next_head(tmp_addr)
            if tmp_addr > end_addr:
                break
        
    return make_func_num

def get_functions_list(make_num:int, src_func_list:list):
    function_num = 0
    program_name = ida_nalt.get_root_filename()
    functions_info_file_name = program_name + '_functions_info.txt'
    functions_info_file = open(functions_info_file_name,mode="w+")

    ext_num = 0
    symbol_num =0
    for func_start_addr in idautils.Functions():
        func_name = idc.get_func_name(func_start_addr)
        seg_name = idc.get_segm_name(func_start_addr)
        function_num += 1
        if seg_name == 'extern':
            ext_num += 1
        
        if (not func_name.startswith('sub_')):
            symbol_num += 1

        if src_func_list:
            is_src_func = "True" if func_start_addr in src_func_list else "False"
        else:
            is_src_func = "False"

        functions_info_file.write(str(func_start_addr)+ " name: " +func_name + " seg: " + seg_name 
                                  + " source_function: " + is_src_func + '\n')
                                  
    #functions_info_file.write(str(ext_num) +" " + str(symbol_num) + " " + str(make_num))
    functions_info_file.close()

def my_run():
    arch, bits, endian =  get_program_arch()
    min_addr, max_addr = get_min_max_addr()

    make_func_num = create_function(arch, min_addr, max_addr)

    #get_functions_list(make_func_num)

    
#ida_auto.auto_wait()
#my_run()
#idc.Exit(0)


