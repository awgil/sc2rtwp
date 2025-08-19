import ida_funcs
import ida_segment
import ida_xref

log_level = 5
process_entire_segment = False
modify_function = True
run_sim = True
redefine_functions = True
patch_jumps = True
c_seh_handler_rva = 0x1DFBD18 # this is not great...
primary_seh_handlers = []

def log(level, msg):
    if level <= log_level:
        print(msg)

def decode_insn(ea):
	insn = ida_ua.insn_t()
	return insn if ida_ua.decode_insn(insn, ea) != 0 else None

def decode_prev_insn(ea):
	insn = ida_ua.insn_t()
	return insn if ida_ua.decode_prev_insn(insn, ea) != idaapi.BADADDR else None

def is_nop(insn):
    mnem = insn.get_canon_mnem()
    return mnem == 'nop' or mnem == 'xchg' and insn.Op1.type == ida_ua.o_reg and insn.Op1.type == insn.Op2.type and insn.Op1.reg == insn.Op2.reg # xchg reg, reg is a synonym for a nop

def set_comment(ea, comment):
    existing = ida_bytes.get_cmt(ea, False)
    if not existing or comment not in existing:
        ida_bytes.append_cmt(ea, comment, False)

def set_func_comment(ea, comment):
    func = ida_funcs.get_func(ea)
    if not func:
        return
    existing = ida_funcs.get_func_cmt(func, False)
    if existing and comment in existing:
        return
    if existing:
        comment = existing + '\n' + comment
    ida_funcs.set_func_cmt(func, comment, False)

def ensure_func_exists(ea, name):
    existing = ida_funcs.get_func_name(ea)
    if not existing:
        ida_funcs.add_func(ea)
    if not existing or existing.startswith('sub_'):
        ida_name.set_name(ea, name)

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

# SEH structures
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

# TODO: this needs to account for nesting...
def check_runtime_functions_equal(ea1, ea2):
    for b in range(3):
        if ida_bytes.get_dword(ea1 + 4 * b) != ida_bytes.get_dword(ea2 + 4 * b):
            print(f'Unwind data at {hex(ea1)} and {hex(ea2)} differ at word {b}')

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

            # check that all chained ranges are consecutive and point to same root
            for j in range(index_start + 1, index_end):
                if read_runtime_function_end_rva(start, j - 1) != read_runtime_function_start_rva(start, j):
                    print(f'Gap before chained unwind info at {hex(start + 12 * j)}')
                check_runtime_functions_equal(start + 12 * index_start, unwind_payload_ea(imagebase + read_runtime_function_unwind_rva(start, j)))

            return (imagebase + begin, imagebase + end, imagebase + read_runtime_function_unwind_rva(start, index_start))
    return None

# Conditionals (first instruction is 'jump when set', second is 'jump if not set')
# OF: jo - jno
# SF: js - jns
# ZF: je/jz - jne/jnz
# CF: jc/jb/jnae - jnc/jnb/jae
# PF: jp/jpe - jnp/jpo
# BE = CF | ZF: jbe/jna - jnbe/ja
# SO = SF ^ OF: jl/jnge - jnl/jge
# LE = ZF | (SF ^ OF): jle/jng - jnle/jg
class FakeBranching:
    flags_known = 0
    flags_value = 0 # invariant: flags_value & ~flags_known == 0 (ie all unknown bits are zero)

    def fork(self):
        res = FakeBranching()
        res.flags_known = self.flags_known
        res.flags_value = self.flags_value
        return res

    def set_all_flags(self, known, mask):
        self.flags_known = known
        self.flags_value = mask

    def is_flag_known(self, index):
        return (self.flags_known & (1 << index)) != 0

    def flag_value(self, index):
        return (self.flags_value & (1 << index)) != 0

    def set_flag_raw(self, index, value):
        bit = 1 << index
        self.flags_known |= bit
        if value:
            self.flags_value |= bit
        else:
            self.flags_value &= ~bit

    def forget_flag(self, index):
        bit = 1 << index
        self.flags_known &= ~bit
        self.flags_value &= ~bit

    def set_flag_conditional(self, index, value):
        # TODO: current code doesn't account for the fact that eg jbe taken followed by jc not taken implies jz will be taken...
        self.set_flag_raw(index, value)

    def update_xor_pseudoflag(self, index, i1, i2):
        if self.is_flag_known(i1) and self.is_flag_known(i2):
            self.set_flag_raw(index, self.flag_value(i1) != self.flag_value(i2))
        else:
            self.forget_flag(index)

    def update_or_pseudoflag(self, index, i1, i2):
        if self.flag_value(i1) or self.flag_value(i2): # value implies known
            self.set_flag_raw(index, True)
        elif self.is_flag_known(i1) and self.is_flag_known(i2):
            self.set_flag_raw(index, False)
        else:
            self.forget_flag(index)

    def set_flag(self, index, value):
        self.set_flag_raw(index, value)
        if index == 0 or index == 1:
            self.update_xor_pseudoflag(6, 0, 1)
        if index == 2 or index == 3:
            self.update_or_pseudoflag(5, 2, 3)
        if index == 0 or index == 1 or index == 2:
            self.update_xor_pseudoflag(7, 2, 6)

    def process_conditional_jump(self, index, value, insn):
        if insn.Op1.type != ida_ua.o_near:
            return None # only near jumps are supported
        target_taken = insn.Op1.addr
        target_not_taken = insn.ea + insn.size
        if not self.is_flag_known(index):
            #print(f'Exploring fork: {hex(insn.ea)}')
            cond_taken = self.fork()
            cond_taken.set_flag_conditional(index, value)
            end_taken = cond_taken.find_sequence_end(target_taken, True) or target_taken

            self.set_flag_conditional(index, not value)
            end_nt = self.find_sequence_end(target_not_taken, True) or target_not_taken
            converging = end_taken == end_nt
            #print(f'{hex(insn.ea)}: jump {"converging" if converging else "diverging"}: {hex(end_taken)} vs {hex(end_nt)}')
            return end_taken if converging else None
        else:
            taken = self.flag_value(index) == value
            target = target_taken if taken else target_not_taken
            #print(f'{hex(insn.ea)}: jump {"always" if taken else "never"} taken: {hex(target)}')
            return self.find_sequence_end(target, True) or target

    def find_sequence_end(self, ea, have_jump = False):
        #print(f'>> Starting: {hex(ea)}')
        while True:
            #print(f'>>> BR: {hex(ea)}')
            insn = decode_insn(ea)
            if not insn:
                return ea if have_jump else None
            next_ea = ea + insn.size
            match insn.get_canon_mnem():
                case 'nop':
                    pass
                case 'sal' | 'sar' | 'shl' | 'shr':
                    if insn.Op2.type == ida_ua.o_imm and insn.Op2.value == 0: # shift x,0 is a no-op
                        pass
                    else:
                        break
                case 'xchg' | 'mov':
                    if insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_reg and insn.Op1.reg == insn.Op2.reg: # xchg/mov reg,reg is a no-op
                        pass
                    else:
                        break
                case 'or' | 'xor':
                    if insn.Op2.type == ida_ua.o_imm and insn.Op2.value == 0: # [x]or x,0 clears OF & CF and modifies other flags
                        self.set_all_flags(9, 0)
                    else:
                        break
                case 'and':
                    if insn.Op2.type == ida_ua.o_imm and (insn.Op2.dtype == ida_ua.dt_byte and insn.Op2.value == 0xff): # and x,~0 clears OF & CF and modifies other flags
                        self.set_all_flags(9, 0)
                    else:
                        break
                case 'test': # test x,y clears OF & CF and modifies other flags
                    self.set_all_flags(9, 0)
                case 'clc':
                    self.set_flag(3, False)
                case 'stc':
                    self.set_flag(3, True)
                case 'jmp':
                    if insn.Op1.type != ida_ua.o_near:
                        break
                    have_jump = True
                    next_ea = insn.Op1.addr
                case 'jo':
                    return self.process_conditional_jump(0, True, insn)
                case 'jno':
                    return self.process_conditional_jump(0, False, insn)
                case 'js':
                    return self.process_conditional_jump(1, True, insn)
                case 'jns':
                    return self.process_conditional_jump(1, False, insn)
                case 'je' | 'jz':
                    return self.process_conditional_jump(2, True, insn)
                case 'jne' | 'jnz':
                    return self.process_conditional_jump(2, False, insn)
                case 'jc' | 'jb' | 'jnae':
                    return self.process_conditional_jump(3, True, insn)
                case 'jnc' | 'jnb' | 'jae':
                    return self.process_conditional_jump(3, False, insn)
                case 'jp':
                    return self.process_conditional_jump(4, True, insn)
                case 'jnp':
                    return self.process_conditional_jump(4, False, insn)
                case 'jbe' | 'jna':
                    return self.process_conditional_jump(5, True, insn)
                case 'jnbe' | 'ja':
                    return self.process_conditional_jump(5, False, insn)
                case 'jl' | 'jnge':
                    return self.process_conditional_jump(6, True, insn)
                case 'jge' | 'jnl':
                    return self.process_conditional_jump(6, False, insn)
                case 'jle' | 'jng':
                    return self.process_conditional_jump(7, True, insn)
                case 'jnle' | 'jg':
                    return self.process_conditional_jump(7, False, insn)
                case _:
                    break
            ea = next_ea
        return ea if have_jump else None # no conditional jumps found...

class ExecutionContext:
    blocks = [] # (begin, end), sorted and non-overlapping
    patches = [] # (from, to, long)
    branches_pending = []

    def __init__(self, range_start, range_end, imagebase):
        self.range_start = range_start
        self.range_end = range_end
        self.imagebase = imagebase

    # find index of the block with begin > ea (return len(blocks) if none are found)
    def next_block(self, ea):
        first = 0
        size = len(self.blocks)
        while size > 0:
            step = size >> 1
            mid = first + step
            if self.blocks[mid][0] <= ea:
                first = mid + 1
                size -= step + 1
            else:
                size = step
        return first

    def queue_simulation(self, ea):
        if ea >= self.range_start and ea < self.range_end:
            self.branches_pending.append(ea)

    def queue_jump_target(self, insn):
        if insn.Op1.type == ida_ua.o_near:
            # normal jump
            self.queue_simulation(insn.Op1.addr)
        else:
            # treat indirect jump as a return (tail recursion call), unless it's a switch
            sw = ida_nalt.switch_info_t()
            if ida_nalt.get_switch_info(sw, insn.ea):
                for i in range(sw.get_jtable_size()):
                    target = self.imagebase + ida_bytes.get_dword(sw.jumps + 4 * i)
                    log(0, f'Switch {i}: {hex(insn.ea)} -> {hex(target)}')
                    self.queue_simulation(target)


    def apply_patches(self):
        for ea, to, long in self.patches:
            jmp_len = 5 if long else 2
            print(f'- Patching jump from {hex(ea)} to {hex(to)}')

            next_block_idx = self.next_block(ea)
            if next_block_idx == 0 or self.blocks[next_block_idx - 1][1] != ea + jmp_len:
                for i in range(len(self.blocks)):
                    print(f'-- Block {i}: {hex(self.blocks[i][0])} - {hex(self.blocks[i][1])}')
                raise Exception(f'Failed to patch {hex(ea)} to {hex(to)}: next={next_block_idx}')

            junk_end = self.blocks[next_block_idx][0] if next_block_idx < len(self.blocks) else self.range_end
            ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND | ida_bytes.DELIT_DELNAMES, junk_end - ea)

            comment = 'Original:'
            for b in range(jmp_len):
                comment += f' {ida_bytes.get_byte(ea + b):02X}'
            if long:
                ida_bytes.patch_byte(ea, 0xE9)
                ida_bytes.patch_dword(ea + 1, to - ea - jmp_len)
            else:
                ida_bytes.patch_byte(ea, 0xEB)
                ida_bytes.patch_byte(ea + 1, to - ea - jmp_len)
            ida_ua.create_insn(ea)
            set_comment(ea, comment)
            ida_bytes.add_hidden_range(ea + jmp_len, junk_end, 'Junk code', 'Junk start', 'Junk end')

    def simulate_one(self, ea):
        next_block_idx = self.next_block(ea)
        if next_block_idx > 0 and self.blocks[next_block_idx - 1][1] > ea:
            # this code was already analyzed
            if ea > self.blocks[next_block_idx - 1][0]:
                # split block into two neighbouring ones - this way we can detect jumps mid patched instruction, which would change meaning of the code
                self.blocks.insert(next_block_idx, (ea, self.blocks[next_block_idx - 1][1]))
                self.blocks[next_block_idx - 1] = (self.blocks[next_block_idx - 1][0], ea)
            return

        start = ea
        limit = self.blocks[next_block_idx][0] if next_block_idx < len(self.blocks) else self.range_end
        #print(f'Starting sim: {hex(ea)}, next-block={next_block_idx}, limit={hex(limit)}')
        while ea < limit:
            #print(f'> sim: {hex(ea)}')
            insn = decode_insn(ea)
            if not insn:
                log(0, f'Failed to decode instruction at {hex(ea)}')
                break

            flags = ida_bytes.get_flags(ea)
            if not ida_bytes.is_code(flags):
                ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND)
                ida_ua.create_insn(ea)

            mnem = insn.get_canon_mnem()
            if mnem == 'retn':
                ea += insn.size
                break

            if mnem == 'jmp':
                self.queue_jump_target(insn)
                ea += insn.size
                break

            if patch_jumps and ((ea & 0xF) == 0 or not is_nop(insn)):
                # scrambled jumps always are aligned to 0x10; we can't safely consume preceeding nops, in case the jump itself is a branch target
                branch_seq_end = FakeBranching().find_sequence_end(ea)
                if branch_seq_end and branch_seq_end != ea and branch_seq_end != ea + 1:
                    long = branch_seq_end > ea + 129 or branch_seq_end < ea - 126
                    self.patches.append((ea, branch_seq_end, long))
                    self.queue_simulation(branch_seq_end)
                    ea += 5 if long else 2
                    break

            if mnem.startswith('j'):
                # conditional jump
                self.queue_jump_target(insn)

            ea += insn.size

        # insert processed block
        self.blocks.insert(next_block_idx, (start, ea))

    def simulate_all(self, ea):
        self.queue_simulation(ea)
        while self.branches_pending:
            ea = self.branches_pending.pop(len(self.branches_pending) - 1)
            self.simulate_one(ea)
        self.apply_patches()


def process_function(imagebase, ea_start, ea_end, ea_unwind, index, count):
    unwind_flags = read_unwind_info_flag(ea_unwind) if ea_unwind else 0
    log(0, f'Processing function {index}/{count}: {hex(ea_start)} - {hex(ea_end)} unwind={hex(ea_unwind)} flags={hex(unwind_flags)}')
    if unwind_flags >= 4:
        print(f'Unsupported unwind flags at {hex(ea_unwind)}')
        return

    existing_func = ida_funcs.get_func(ea_start)
    if existing_func and existing_func.start_ea != ea_start:
        existing_name = ida_funcs.get_func_name(ea_start)
        log(0, f'{hex(ea_start)} is part of existing function {existing_name} @ {hex(existing_func.start_ea)}, is it a wrong guess?..')
        if redefine_functions and existing_name.startswith('sub_'):
            # TODO: for some reason, even though we create new function with correct bounds, IDA changes it to single-instruction on the next frame...
            ida_funcs.del_func(ea_start)
            ida_bytes.del_items(existing_func.start_ea, ida_bytes.DELIT_EXPAND, existing_func.end_ea - existing_func.start_ea)
        else:
            return

    #ida_bytes.del_items(ea_start, ida_bytes.DELIT_EXPAND, ea_end - ea_start)
    if modify_function:
        try:
            if run_sim:
                ExecutionContext(ea_start, ea_end, imagebase).simulate_all(ea_start)
            ida_funcs.add_func(ea_start)
            #ida_funcs.reanalyze_function(ida_funcs.get_func(ea_start))
            ida_funcs.set_func_end(ea_start, ea_end)
        except Exception as e:
            print(f'Error while processing function at ${hex(ea_start)}: {e}')
            raise

    ea_unwind_extra = unwind_payload_ea(ea_unwind) if ea_unwind else 0
    if unwind_flags & 3:
        primary_handler = imagebase + ida_bytes.get_dword(ea_unwind_extra)
        set_func_comment(ea_start, f'SEH primary handler: {hex(primary_handler)}: {"exception" if unwind_flags == 1 else "termination" if unwind_flags == 2 else "both"}')
        ida_xref.add_cref(ea_start, primary_handler, ida_xref.fl_CN | ida_xref.XREF_USER)
        if primary_handler not in primary_seh_handlers:
            primary_seh_handlers.append(primary_handler)
        scope_count = ida_bytes.get_dword(ea_unwind_extra + 4) if primary_handler == imagebase + c_seh_handler_rva else 0
        ea_scope = ea_unwind_extra + 8
        for i in range(scope_count):
            scope_begin = imagebase + ida_bytes.get_dword(ea_scope)
            scope_end = imagebase + ida_bytes.get_dword(ea_scope + 4)
            scope_filter = ida_bytes.get_dword(ea_scope + 8)
            scope_handler = ida_bytes.get_dword(ea_scope + 12)
            if scope_filter > 1 or scope_filter < -1:
                scope_filter += imagebase
                ensure_func_exists(scope_filter, f'seh_filter_{hex(scope_filter)[2:]}')
                ida_xref.add_cref(ea_start, scope_filter, ida_xref.fl_CN | ida_xref.XREF_USER)
            if scope_handler:
                scope_handler += imagebase
                set_comment(scope_begin, f'try ... except ({hex(scope_filter)}) {hex(scope_handler)}')
                ida_name.set_name(scope_handler, f'seh_handler_{i}', ida_name.SN_LOCAL)
                ida_xref.add_cref(scope_begin, scope_handler, ida_xref.fl_JN | ida_xref.XREF_USER)
            else:
                set_comment(scope_begin, f'try ... finally ({hex(scope_filter)})')
            set_comment(scope_end, f'^^ end try')
            print(f'SEH range: {hex(scope_begin)}-{hex(scope_end)} -> {hex(scope_filter)} -> {hex(scope_handler)}')
            ea_scope += 16

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

def process_segment(ea):
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
    index = 0
    while index < exc[1]:
        begin = read_runtime_function_start_rva(exc[0], index)
        end = read_runtime_function_end_rva(exc[0], index)
        chain_end = index + 1
        while chain_end < exc[1] and unwind_info_chained(imagebase, exc[0], chain_end):
            if read_runtime_function_start_rva(exc[0], chain_end) != end:
                print(f'Gap before chained unwind info at {hex(exc[0] + 12 * chain_end)}')
            end = read_runtime_function_end_rva(exc[0], chain_end)
            #check_runtime_functions_equal(exc[0] + 12 * index, unwind_payload_ea(imagebase + read_runtime_function_unwind_rva(exc[0], chain_end)))
            chain_end += 1
        process_function(imagebase, imagebase + begin, imagebase + end, imagebase + read_runtime_function_unwind_rva(exc[0], index), index, exc[1])
        index = chain_end

#process_function(0x140000000, 0x140025A70, 0x140025EE5, 0, 0, 1)
if process_entire_segment:
    process_segment(idaapi.get_screen_ea())
else:
    process_single_function(idaapi.get_screen_ea())

for h in primary_seh_handlers:
    print(f'Found primary SEH handler: {hex(h)}')
