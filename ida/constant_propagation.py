import copy

import idaapi
import ida_xref
import ida_ua
import ida_idp

def decode_insn(ea):
	insn = ida_ua.insn_t()
	return insn if ida_ua.decode_insn(insn, ea) != 0 else None

def set_comment(ea, comment):
    existing = ida_bytes.get_cmt(ea, False)
    if not existing or comment not in existing:
        ida_bytes.append_cmt(ea, comment, False)

imagebase = 0x7ff6ae4d0000
decode_addr = 0x7ff6ae57f1d4
num_skip = 0 # tweak as needed...
values = {
	'r15': 0x11110960000, # antidebug state
	#'r8': decode_addr,
	#'r14': imagebase,
}
def value_or(v):
	if v in values:
		return values[v]
	if v.startswith('[0x') and v.endswith(']'):
		addr = int(v[1:len(v)-1], 16)
		val = ida_bytes.get_qword(addr)
		print(f'{v} = {hex(val)}')
		return val
	return None

def decode_operand(insn, op):
	match op.type:
		case ida_ua.o_reg:
			return ida_idp.get_reg_name(op.reg, 8)
		case ida_ua.o_mem:
			offset = op.addr
			if op.specflag1:
				# SIB without base
				sib = op.specflag2
				rex = insn.insnpref
				index = ((sib >> 3) & 7) | (8 if rex & 2 else 0)
				scale = 1 << ((sib >> 6) & 3)
				if index != 4:
					index_name = ida_idp.get_reg_name(index, 8)
					index_val = value_or(index_name)
					if index_val == None:
						print(f'Index not found for {index_name}')
						return None
					offset += index_val * scale
			return f'[{hex(offset)}]'
		case ida_ua.o_phrase | ida_ua.o_displ:
			if op.specflag1:
				sib = op.specflag2
				rex = insn.insnpref
				base = (sib & 7) | (8 if rex & 1 else 0)
				index = ((sib >> 3) & 7) | (8 if rex & 2 else 0)
				scale = 1 << ((sib >> 6) & 3)
			else:
				base = op.phrase
				index = 4 # n/a
				scale = 0
			offset = op.addr if op.type == ida_ua.o_displ else 0
			if index != 4:
				index_name = ida_idp.get_reg_name(index, 8)
				index_val = value_or(index_name)
				if index_val == None:
					print(f'Index not found for {index_name}')
					return None
				offset += index_val * scale
			base_name = ida_idp.get_reg_name(base, 8)
			if base_name == 'rbp' or base_name == 'rsp':
				return f'[{base_name}+{hex(offset)}]'
			base_val = value_or(base_name)
			if base_val == None:
				print(f'Base not found for [{base_name}+{hex(offset)}]')
				return None
			addr = base_val + offset
			return f'[{hex(addr)}]'
		case _:
			print(f'Unknown op type {op.type}')
			return None

def decode_value(insn, op):
	return op.value if op.type == ida_ua.o_imm else value_or(decode_operand(insn, op))

def value_is_addr(v, is_stack):
	return isinstance(v, str) and v.startswith('&[r' if is_stack else '&[0x')

def op_width(dtype):
	match dtype:
		case ida_ua.dt_byte:
			return 8
		case ida_ua.dt_word:
			return 16
		case ida_ua.dt_dword:
			return 32
		case ida_ua.dt_qword:
			return 64
		case _:
			return 0

def op_width_mask(width):
	return (1 << width) - 1

def set_value_raw(ea, dest, src):
	values[dest] = src
	set_comment(ea, f'{dest} = {src if isinstance(src, str) else hex(src)}')

def set_value(ea, dest, src, dtype):
	if src == None or dest == None:
		return False
	mask = op_width_mask(op_width(dtype))
	if not mask:
		print(f'Unknown op size: {dtype}')
		return False
	if isinstance(src, str) and src.startswith('&') and op_width(dtype) == 64:
		set_value_raw(ea, dest, src)
	else:
		set_value_raw(ea, dest, src & mask)
	return True


def process(ea):
	global num_skip
	while True:
		insn = decode_insn(ea)
		print(f'{hex(ea)}: {insn.get_canon_mnem()}')
		match insn.get_canon_mnem():
			case 'mov':
				dest = decode_operand(insn, insn.Op1)
				src = decode_value(insn, insn.Op2)
				if not set_value(ea, dest, src, insn.Op1.dtype):
					return
			case 'add':
				dest = decode_operand(insn, insn.Op1)
				orig = value_or(dest)
				mod = decode_value(insn, insn.Op2)
				if not dest or orig == None or mod == None:
					return
				set_value(ea, dest, orig + mod, insn.Op1.dtype)
			case 'sub':
				dest = decode_operand(insn, insn.Op1)
				orig = value_or(dest)
				mod = decode_value(insn, insn.Op2)
				if not dest or orig == None or mod == None:
					return
				set_value(ea, dest, orig - mod, insn.Op1.dtype)
			case 'not':
				dest = decode_operand(insn, insn.Op1)
				orig = value_or(dest)
				if not dest or not orig:
					return
				set_value(ea, dest, ~orig, insn.Op1.dtype)
			case 'and':
				dest = decode_operand(insn, insn.Op1)
				orig = value_or(dest)
				mod = decode_value(insn, insn.Op2)
				if not dest or orig == None or mod == None:
					return
				set_value(ea, dest, orig & mod, insn.Op1.dtype)
			case 'or':
				dest = decode_operand(insn, insn.Op1)
				orig = value_or(dest)
				mod = decode_value(insn, insn.Op2)
				if not dest or orig == None or mod == None:
					return
				set_value(ea, dest, orig | mod, insn.Op1.dtype)
			case 'xor':
				dest = decode_operand(insn, insn.Op1)
				if insn.Op1.type == ida_ua.o_reg and insn.Op1.type == insn.Op2.type and insn.Op1.reg == insn.Op2.reg:
					# xor reg, reg === mov reg, 0
					set_value(ea, dest, 0, insn.Op1.dtype)
				else:
					orig = value_or(dest)
					mod = decode_value(insn, insn.Op2)
					if not dest or orig == None or mod == None:
						return
					set_value(ea, dest, orig ^ mod, insn.Op1.dtype)
			case 'shr':
				dest = decode_operand(insn, insn.Op1)
				orig = value_or(dest)
				shift = decode_value(insn, insn.Op2)
				if not dest or orig == None or not shift:
					return
				set_value(ea, dest, orig >> shift, insn.Op1.dtype)
			case 'shl':
				dest = decode_operand(insn, insn.Op1)
				orig = value_or(dest)
				shift = decode_value(insn, insn.Op2)
				if not dest or orig == None or not shift:
					return
				set_value(ea, dest, orig << shift, insn.Op1.dtype)
			case 'ror':
				dest = decode_operand(insn, insn.Op1)
				orig = value_or(dest)
				shift = decode_value(insn, insn.Op2)
				w = op_width(insn.Op1.dtype)
				if not dest or not orig or not shift or not w:
					return
				orig &= op_width_mask(w)
				set_value(ea, dest, (orig >> shift) | (orig << (w - shift)), insn.Op1.dtype)
			case 'rol':
				dest = decode_operand(insn, insn.Op1)
				orig = value_or(dest)
				shift = decode_value(insn, insn.Op2)
				w = op_width(insn.Op1.dtype)
				if not dest or not orig or not shift or not w:
					return
				orig &= op_width_mask(w)
				set_value(ea, dest, (orig << shift) | (orig >> (w - shift)), insn.Op1.dtype)
			case 'jmp':
				if insn.Op1.type != ida_ua.o_near:
					return
				ea = insn.Op1.addr
			case 'lea':
				dest = decode_operand(insn, insn.Op1)
				src = decode_operand(insn, insn.Op2)
				if not dest or not src or not src.startswith('['):
					return
				value = '&' + src
				if insn.Op2.type == ida_ua.o_mem:
					print(f'{value}')
				if value_is_addr(value, False):
					set_value(ea, dest, int(value[2:len(value)-1], 16), insn.Op1.dtype)
				else:
					set_value_raw(ea, dest, value)
			case 'call':
				target = decode_value(insn, insn.Op1)
				if value_is_addr(target, False):
					target = int(target[2:len(target)-1], 16)
				if target != decode_addr:
					return
				arg1 = value_or('rcx')
				arg2 = value_or('rdx')
				if not value_is_addr(arg1, True) or not value_is_addr(arg2, True):
					return
				v1 = value_or(arg1[1:])
				v2 = value_or(arg2[1:])
				if not v1 or not v2:
					return
				v1 ^= 0xF3791823EBD0BA08 ^ ~imagebase
				v2 = 0xA08F3791823EBD0B - v2
				v1 &= (1 << 64) - 1
				v2 &= (1 << 64) - 1
				values[arg1[1:]] = v1
				values[arg2[1:]] = v2
				set_comment(ea, f'{arg1[1:]} = {hex(v1)}, {arg2[1:]} = {hex(v2)}')
			case 'nop':
				pass
			case 'xchg':
				if insn.Op1.type == ida_ua.o_reg and insn.Op1.type == insn.Op2.type and insn.Op1.reg == insn.Op2.reg:
					pass # no-op
				else:
					return
			case _:
				if num_skip <= 0:
					return
				num_skip -= 1
		if ea == insn.ea:
			ea += insn.size

process(idaapi.get_screen_ea())
