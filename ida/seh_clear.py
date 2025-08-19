import ida_funcs
import ida_segment
import ida_xref

log_level = 5
def log(level, msg):
    if level <= log_level:
        print(msg)

def get_exception_data(imagebase):
    if ida_bytes.get_word(imagebase) != 0x5a4d:
        print(f'No executable header at {hex(imagebase)}')
        return None
    ntheader = imagebase + ida_bytes.get_dword(imagebase + 0x3C)
    if ida_bytes.get_dword(ntheader) != 0x4550 or ida_bytes.get_word(ntheader + 0x18) != 0x20B:
        print(f'No PE header at {hex(imagebase)}')
        return None
    start = imagebase + ida_bytes.get_dword(ntheader + 0xA0)
    size = ida_bytes.get_dword(ntheader + 0xA4)
    entries = int(size / 12)
    if entries * 12 != size:
        print(f'Bad exception directory size: {size}')
        return None
    return (start, entries)

def read_runtime_function_start_rva(ea, index = 0):
    return ida_bytes.get_dword(ea + 12 * index)
def read_runtime_function_end_rva(ea, index = 0):
    return ida_bytes.get_dword(ea + 12 * index + 4)
def read_runtime_function_unwind_rva(ea, index):
    return ida_bytes.get_dword(ea + 12 * index + 8)
def read_unwind_info_flag(ea):
    return ida_bytes.get_byte(ea) >> 3
def unwind_payload_ea(ea):
    num_codes = ida_bytes.get_byte(ea + 2)
    return ea + 4 + 4 * ((num_codes + 1) >> 1)

def unwind_info_chained(imagebase, start, index):
    return read_unwind_info_flag(imagebase + read_runtime_function_unwind_rva(start, index)) == 4

# returns None or (ea_start, ea_end, ea_unwind)
# TODO: can use binary search here...
def find_unwind_info(imagebase, ea, start, count):
    rva = ea - imagebase
    for i in range(count):
        begin = read_runtime_function_start_rva(start, i)
        end = read_runtime_function_end_rva(start, i)
        if rva >= begin and rva < end:
            # found the entry; find all related chained entries
            index_start = i
            while unwind_info_chained(imagebase, start, index_start):
                index_start -= 1
            if index_start != i:
                begin = read_runtime_function_start_rva(start, index_start)

            index_end = i + 1
            while index_end < count and unwind_info_chained(imagebase, start, index_end):
                index_end += 1
            if index_end != i + 1:
                end = read_runtime_function_end_rva(start, index_end - 1)

            return (imagebase + begin, imagebase + end, imagebase + read_runtime_function_unwind_rva(start, index_start))
    return None

def process_function(imagebase, ea_start, ea_end, ea_unwind, index, count):
    unwind_flags = read_unwind_info_flag(ea_unwind) if ea_unwind else 0
    log(0, f'Processing function {index}/{count}: {hex(ea_start)} - {hex(ea_end)} unwind={hex(ea_unwind)} flags={hex(unwind_flags)}')
    if unwind_flags >= 4:
        print(f'Unsupported unwind flags at {hex(ea_unwind)}')
        return

    ida_bytes.del_items(ea_start, ida_bytes.DELIT_EXPAND, ea_end - ea_start)

    patches = []
    ida_bytes.visit_patched_bytes(ea_start, ea_end, lambda ea, fpos, org_val, patch_val : patches.append(ea))
    print(f'Found {len(patches)} patched bytes, reverting')
    for ea in patches:
        ida_bytes.revert_byte(ea)

    nranges = 0
    while True:
        range = ida_bytes.get_next_hidden_range(ea_start)
        if not range or range.start_ea >= ea_end:
            break
        nranges += 1
        ida_bytes.del_hidden_range(range.start_ea)
    print(f'Found {nranges} hidden ranges')


def process_single_function(ea):
    seg = ida_segment.getseg(ea)
    if not seg:
        print(f'Failed to find segment for {hex(ea)}')
        return
    imagebase = seg.start_ea
    if imagebase == 0x140001000:
        imagebase -= 0x1000 # hack: if file was loaded into idb without headers, adjust...
    exc = get_exception_data(imagebase)
    if not exc:
        return
    unwind = find_unwind_info(imagebase, ea, exc[0], exc[1])
    if not unwind:
        print(f'Failed to find unwind data for {hex(ea)}')
        return
    process_function(imagebase, unwind[0], unwind[1], unwind[2], 0, 1)

#process_function(0x140000000, 0x140025A70, 0x140025EE5, 0, 0, 1)
process_single_function(idaapi.get_screen_ea())
