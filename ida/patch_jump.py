import copy

import idaapi
import ida_xref
import ida_ua

def decode_insn(ea):
	insn = ida_ua.insn_t()
	return insn if ida_ua.decode_insn(insn, ea) != 0 else None

# Conditionals (first instruction is 'jump when set', second is 'jump if not set')
# OF: jo - jno
# SF: js - jns
# ZF: je/jz - jne/jnz
# CF: jc/jb/jnae - jnc/jnb/jae
# PF: jp/jpe - jnp/jpo
# BE = CF | ZF: jbe/jna - jnbe/ja
# SO = SF ^ OF: jl/jnge - jnl/jge
# LE = ZF | (SF ^ OF): jle/jng - jnle/jg
class Conditional:
	known = 0
	value = 0

	def __init__(self, known = 0, value = 0):
		self.known = known
		self.value = value

	def set_all(self, known, value):
		self.known = known
		self.value = value

	def is_known(self, index):
		return (self.known & (1 << index)) != 0

	def bit_value(self, index):
		return (self.value & (1 << index)) != 0

	def set_bit_raw(self, index, value):
		bit = 1 << index
		self.known |= bit
		if value:
			self.value |= bit
		else:
			self.value &= ~bit

	def forget(self, index):
		bit = 1 << index
		self.known &= ~bit
		self.value &= ~bit

	def set_conditional(self, index, value):
		# TODO: current code doesn't account for the fact that eg jbe taken followed by jc not taken implies jz will be taken...
		self.set_bit_raw(index, value)

	def update_xor(self, index, i1, i2):
		if self.is_known(i1) and self.is_known(i2):
			self.set_bit_raw(index, self.bit_value(i1) != self.bit_value(i2))
		else:
			self.forget(index)

	def update_or(self, index, i1, i2):
		if self.bit_value(i1) or self.bit_value(i2): # value implies known
			self.set_bit_raw(index, True)
		elif self.is_known(i1) and self.is_known(i2):
			self.set_bit_raw(index, False)
		else:
			self.forget(index)

	def set_bit(self, index, value):
		self.set_bit_raw(index, value)
		if index == 0 or index == 1:
			self.update_xor(6, 0, 1)
		if index == 2 or index == 3:
			self.update_or(5, 2, 3)
		if index == 0 or index == 1 or index == 2:
			self.update_or(7, 2, 6)


def process_conditional_jump(cond, index, value, insn):
	if insn.Op1.type != ida_ua.o_near:
		return insn.ea # only near jumps are supported
	target_taken = insn.Op1.addr
	target_not_taken = insn.ea + insn.size
	if not cond.is_known(index):
		cond_taken = Conditional(cond.known, cond.value)
		cond_taken.set_conditional(index, value)
		end_taken = find_sequence_end(target_taken, cond_taken)
		cond.set_conditional(index, not value)
		end_nt = find_sequence_end(target_not_taken, cond)
		print(f'{hex(insn.ea)}: jump {"converging" if end_taken == end_nt else "diverging"}')
		return end_taken if end_taken == end_nt else insn.ea
	else:
		taken = cond.bit_value(index) == value
		print(f'{hex(insn.ea)}: jump {"always" if taken else "never"} taken')
		return find_sequence_end(target_taken if taken else target_not_taken, cond)

def find_sequence_end(ea, cond):
	while True:
		insn = decode_insn(ea)
		print(f'{hex(ea)} = {insn.get_canon_mnem()}')
		match insn.get_canon_mnem():
			case 'nop':
				ea += insn.size
			case 'sal' | 'sar' | 'shl' | 'shr':
				if insn.Op2.type == ida_ua.o_imm and insn.Op2.value == 0: # shift x,0 is a no-op
					ea += insn.size
				else:
					break
			case 'xchg' | 'mov':
				if insn.Op1.type == ida_ua.o_reg and insn.Op2.type == ida_ua.o_reg and insn.Op1.reg == insn.Op2.reg: # xchg/mov reg,reg is a no-op
					ea += insn.size
				else:
					break
			case 'or' | 'xor':
				if insn.Op2.type == ida_ua.o_imm and insn.Op2.value == 0: # [x]or x,0 clears OF & CF and modifies other flags
					ea += insn.size
					cond.set_all(9, 0)
				else:
					break
			case 'and':
				if insn.Op2.type == ida_ua.o_imm and (insn.Op2.dtype == ida_ua.dt_byte and insn.Op2.value == 0xff): # and x,~0 clears OF & CF and modifies other flags
					ea += insn.size
					cond.set_all(9, 0)
				else:
					break
			case 'test': # test x,y clears OF & CF and modifies other flags
				ea += insn.size
				cond.set_all(9, 0)
			case 'clc':
				ea += insn.size
				cond.set_bit(3, False)
			case 'stc':
				ea += insn.size
				cond.set_bit(3, True)
			case 'jmp':
				if insn.Op1.type != ida_ua.o_near:
					return ea
				ea = insn.Op1.addr
			case 'jo':
				return process_conditional_jump(cond, 0, True, insn)
			case 'jno':
				return process_conditional_jump(cond, 0, False, insn)
			case 'js':
				return process_conditional_jump(cond, 1, True, insn)
			case 'jns':
				return process_conditional_jump(cond, 1, False, insn)
			case 'je' | 'jz':
				return process_conditional_jump(cond, 2, True, insn)
			case 'jne' | 'jnz':
				return process_conditional_jump(cond, 2, False, insn)
			case 'jc' | 'jb' | 'jnae':
				return process_conditional_jump(cond, 3, True, insn)
			case 'jnc' | 'jnb' | 'jae':
				return process_conditional_jump(cond, 3, False, insn)
			case 'jp':
				return process_conditional_jump(cond, 4, True, insn)
			case 'jnp':
				return process_conditional_jump(cond, 4, False, insn)
			case 'jbe' | 'jna':
				return process_conditional_jump(cond, 5, True, insn)
			case 'jnbe' | 'ja':
				return process_conditional_jump(cond, 5, False, insn)
			case 'jl' | 'jnge':
				return process_conditional_jump(cond, 6, True, insn)
			case 'jge' | 'jnl':
				return process_conditional_jump(cond, 6, False, insn)
			case 'jle' | 'jng':
				return process_conditional_jump(cond, 7, True, insn)
			case 'jnle' | 'jg':
				return process_conditional_jump(cond, 7, False, insn)
			case _:
				break
	print(f'{hex(ea)}: ending at {insn.get_canon_mnem()}')
	return ea # that's it

ea = idaapi.get_screen_ea()
cond = Conditional()
end_ea = find_sequence_end(ea, cond)
if end_ea >= ea + 2:
	print(f'Jump to {hex(end_ea)}')
	if ida_ua.create_insn(end_ea) == 0:
		ida_bytes.del_items(end_ea, ida_bytes.DELIT_EXPAND)
	ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, end_ea - ea)
	jmp_len = 0
	if end_ea > ea + 129:
		jmp_len = 5
		ida_bytes.patch_byte(ea, 0xE9)
		ida_bytes.patch_dword(ea + 1, end_ea - ea - jmp_len)
	else:
		jmp_len = 2
		ida_bytes.patch_byte(ea, 0xEB)
		ida_bytes.patch_byte(ea + 1, end_ea - ea - jmp_len)
	ida_ua.create_insn(ea)
	ida_bytes.add_hidden_range(ea + jmp_len, end_ea, 'Junk code', 'Junk start', 'Junk end')
else:
	print('Failed to convert jumps')


#insn_len = ida_ua.decode_insn(insn, ea)
#if insn_len == 2 and insn.Op1.type == ida_ua.o_near:
#	ida_bytes.patch_byte(ea, 0xeb)
#	target = insn.Op1.addr
#	if ida_ua.create_insn(target) == 0:
#		ida_bytes.del_items(target, ida_bytes.DELIT_EXPAND)
#	ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND)
#	ida_ua.create_insn(ea)
#else:
#	print(f'Unsupported instruction (len={insn_len}): {insn.get_canon_mnem()}')
