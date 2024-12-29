from audioop import add
from gettext import find
from importlib import metadata
from sre_parse import FLAGS
from tracemalloc import start
from types import ClassMethodDescriptorType
from typing import List
import idc
import idautils
import idaapi

def find_func_addr_by_name(target_funcs_name:list):
    #print(target_funcs_name)
    target_funcs_addr = set()
    for func_start_addr in idautils.Functions():
        func_name = idc.get_func_name(func_start_addr)
        #print(func_name)
        if func_name in target_funcs_name:
            target_funcs_addr.add(func_start_addr)
    #print(target_funcs_addr)
    return target_funcs_addr

def find_caller_funcs(addr):
    caller_funcs = []
    xref_to_addrs = find_func_xrefs_to(addr)
    for xref_to_addr in xref_to_addrs:
        caller_func = idaapi.get_func(xref_to_addr)
        if caller_func not in caller_funcs:
            caller_funcs.append(caller_func)
    
    return caller_funcs

def find_func_xrefs_to(addr):
    func = idaapi.get_func(addr)
    num = 0
    xref_addr = set()
    for ref in idautils.XrefsTo(addr, flags=0):
        num += 1
        xref_addr.add(ref.frm)
    #print(num)
    return xref_addr

def backtracking_sink_function(target_funcs, orgin_func, depth):
    if depth == 5:
        return False

    if orgin_func!= None:
        func_start_addr = orgin_func.start_ea

    else:
        return False    



def find_all_paths(source_functions_addrs, sink_functions_addrs):
    source_points_addrs = []
    sink_points_addrs = []
    src_caller_funcs_addrs = []
    sk_caller_funcs_addrs = []

    for source_func_addr in source_functions_addrs:
        source_points_addrs += find_func_xrefs_to(source_func_addr)
        
    for sink_func_addr in sink_functions_addrs:
        sink_points_addrs += find_func_xrefs_to(sink_func_addr)
            
    print(len(source_points_addrs), len(sink_points_addrs))

    for src_pt_addr in source_points_addrs:
        src_caller_func = idaapi.get_func(src_pt_addr)
        if src_caller_func:
            src_caller_funcs_addrs.append(src_caller_func.start_ea)

    for sk_pt_addr in sink_points_addrs:
        sk_caller_func = idaapi.get_func(sk_pt_addr)
        if sk_caller_func:
            sk_caller_funcs_addrs.append(sk_caller_func.start_ea)

    program_name = ida_nalt.get_root_filename()
    file_name = program_name + '_IDA_source_sink_caller_functions_addrs.txt'
    result_file = open(file_name, 'a+')
    for addr in src_caller_funcs_addrs:
        line = "source_caller_func_addr:" + str(addr) + "\n"
        print(hex(addr))
        result_file.write(line)

    for addr in sk_caller_funcs_addrs:
        line = "sink_caller_func_addr:" + str(addr) + "\n"
        #print(hex(addr))
        result_file.write(line)
    
    result_file.close()


source_functions_name = ["websGetVarN", "websGetVar", "j_websGetVar", "websGetVarString", "read", "getenv", "shmat", "fread", 
                         "cgiGetValueByNameSafe", "tm_nmc_extractXmlValue", "tm_nmc_extractXmlElementAttributeValue", "tm_nmc_extractXmlElementAttributeValue",
                         "upnp_xml_find_tag_value", "upnp_xml_find_attribute_value", ".config_get", "nvram_get"]


sink_functions_name = ["strcpy", "strncpy", "strcat", "strncat", "sprintf", "vsprintf", "snprintf", "memcpy", "gets",
                        "system", "doSystemCmd", "twSystem", "popen", "execv", "dlopen", "printf", "puts", "fopen",
                        "fopen64", "send", "sendto"]


#find_func_xrefs(0x431570)
#program_name = ida_nalt.get_root_filename()
#file_name = program_name + '_HermeScan_paths.txt'
#result_file = open(file_name, 'a+')
#ida_auto.auto_wait()
source_functions_addrs = find_func_addr_by_name(source_functions_name)
sink_functions_addrs = find_func_addr_by_name(sink_functions_name)

source_caller_func_num = 0
all_source_caller_funcs = []
for addr in source_functions_addrs:
    #print("Here is", hex(addr))
    caller_funcs = find_caller_funcs(addr)
    #source_caller_func_num += len(caller_funcs)
    for caller_func in caller_funcs:
        if caller_func not in all_source_caller_funcs:
            all_source_caller_funcs.append(caller_func)

sink_caller_func_num = 0
all_sink_caller_funcs = []
for addr in sink_functions_addrs:
    #print("Here is", hex(addr))
    caller_funcs = find_caller_funcs(addr)
    for caller_func in caller_funcs:
        if caller_func not in all_sink_caller_funcs:
            all_sink_caller_funcs.append(caller_func)
print(start)
print(len(all_source_caller_funcs))
print(len(all_sink_caller_funcs))
#results_str = "source num: " + str(len(all_source_caller_funcs)) + " sink num: " + str(len(all_sink_caller_funcs)) + "\n"
#result_file.write(results_str)
#result_file.close()

find_all_paths(source_functions_addrs, sink_functions_addrs)

print("end")
#idc.Exit(0)