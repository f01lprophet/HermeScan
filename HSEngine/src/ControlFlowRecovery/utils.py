import ida_ida
import idaapi
import idc
import idautils
import ida_nalt

def get_file_path():
    return ida_nalt.get_input_file_path()

def get_file_name():
    return ida_nalt.get_root_filename()

def get_extern_segment_info():
    for i in idautils.Segments():
        if idc.get_segm_name(i) == 'extern':
            extern_start_addr = idc.get_segm_start(i)
            extern_end_addr = idc.get_segm_end(i)
            return extern_start_addr, extern_end_addr

def get_min_max_addr():
    min_addr = ida_ida.inf_get_min_ea()
    max_addr = ida_ida.inf_get_max_ea()
    return min_addr, max_addr

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