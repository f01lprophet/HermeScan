import idautils
import idc
import idaapi
import os
import subprocess
from ida_search import SEARCH_DOWN, SEARCH_UP
from ida_idaapi import BADADDR

arm_jump_insn_ops = ['B', 'BL']
mips_jump_insn_ops = ['jalr', 'j', 'jr']
la_op_value = BADADDR


def get_program_arch():
    info = idaapi.get_inf_structure()

    if info.is_64bit():
        bits = 64
    elif info.is_32bit():
        bits = 32
    else:
        bits = 16

    try:
        is_be = info.is_be()
    except:
        is_be = None
    endian = "big" if is_be else "little"
    return info.procName, bits, endian


def find_jump_addr_within_arch(now_addr, arch) -> int:
    # insn = idc.generate_disasm_line(now_addr, 0)
    insn_operator = idc.print_insn_mnem(now_addr)
    global la_op_value

    if arch == 'ARM':
        print(hex(now_addr))
        if insn_operator in arm_jump_insn_ops:
            jump_addr = idc.get_operand_value(now_addr, 0)
        else:
            jump_addr = BADADDR

    elif arch == 'mipsl' or arch == 'mipsb':
        if insn_operator == 'jalr':
            jump_addr = la_op_value

        elif insn_operator == 'la':
            la_op_value = idc.get_operand_value(now_addr, 1)
            jump_addr = BADADDR

        elif insn_operator == 'bal':
            jump_addr = idc.get_operand_value(now_addr, 0)

        elif insn_operator == 'jal':
            jump_addr = idc.get_operand_value(now_addr, 0)

        else:
            jump_addr = BADADDR

    else:
        jump_addr = BADADDR

    # print(arch, insn_operator, len(insn_operator), hex(jump_addr))
    return jump_addr

def get_candidate_source_functions(strs_addrs: list) -> list:
    target_function_addrs = []
    arch, bits, endian = get_program_arch()

    for str_addr in strs_addrs:
        func = idaapi.get_func(str_addr)
        global la_op_value
        la_op_value = BADADDR
        find_flag = 0
        if func:
            fc = idaapi.FlowChart(func, flags=idaapi.FC_PREDS)
            for block in fc:
                b_start = block.start_ea
                b_end = block.end_ea
                if str_addr >= b_start and str_addr <= b_end:
                    now_addr = str_addr
                    print("-------------------------------------------")
                    print("now_addr is {0}, basic block start addr is {1}, basic block end addr is {2}".format(hex(now_addr), hex(b_start), hex(b_end)))
                    while (now_addr < b_end):
                        jump_addr = find_jump_addr_within_arch(now_addr, arch)

                        if jump_addr != BADADDR:
                            target_function_addrs.append(jump_addr)
                            find_flag = 1
                            break

                        now_addr = idc.next_head(now_addr)

                    now_addr = str_addr
                    while (now_addr >= b_start):
                        jump_addr = find_jump_addr_within_arch(now_addr, arch)
                        if jump_addr != BADADDR:
                            target_function_addrs.append(jump_addr)
                            find_flag = 1
                            break

                        now_addr = idc.prev_head(now_addr)

                    if "mip" in arch:
                        jump_addr = find_jump_addr_within_arch(idc.prev_head(b_start), arch)
                        if jump_addr != BADADDR:
                            find_flag = 1

                        if b_end == str_addr:
                            find_flag = 1

                    break
            if find_flag == 0:
                print("not find:", hex(str_addr))

    return target_function_addrs

#get_candidate_source_functions()

def Read_Strs_Refs_Addrs_From_File(log_file_name):
    valid_addrs = []
    with open(log_file_name, 'r+') as log_file:
        addrs =log_file.readlines()
        for addr in addrs:
            valid_addr = addr.strip("\n")
            valid_addrs.append(int(addr, 16))
    return valid_addrs
