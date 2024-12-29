from importlib import metadata
from types import ClassMethodDescriptorType
import idc
import idautils
import idaapi

#tif = idaapi.tinfo_t()
#idaapi.get_tinfo2(0x456750,tif)

ea = 0x40839c
tif = idaapi.tinfo_t()
is_function = ida_nalt.get_tinfo(tif, ea)
#print(is_function)
function_type = tif.get_rettype()
print("function type is:", function_type)

funcdata = idaapi.func_type_data_t()
get_detail = tif.get_func_details(funcdata)

print(funcdata.size(), hex(funcdata.cc))
for i,v in enumerate(funcdata):
    print(i, v)

"""
for function in idautils.Functions(): 
    function_name = idc.get_name(function) 
    function_type_1 = idaapi.print_type(function, True)
    #prototype_details = idc.parse_decl(function_type_1, idc.PT_SILENT)
    print(function_name)
    print(function_type_1)
    #print(prototype_details)
    #itype = ida_typeinf.print_tinfo('', 0, 0, idc.PRTYPE_1LINE, v.type, '', '')
"""
#ida_nalt.get_tinfo(tif, 0x456750)
#function_detail = tif.get_func_details()
#print(function_detail)
#function_type = tif.get_rettype()
#print(function_type)
#metadata[function]["ret_type"] = function_type
#funcdata = ida_typeinf.func_type_data_t()
#for i,v in enumerate(funcdata):
#        itype = ida_typeinf.print_tinfo('', 0, 0, idc.PRTYPE_1LINE, v.type, '', '')
#        metadata[function]["parameter_list"].append(tuple([i, v.name,itype]))