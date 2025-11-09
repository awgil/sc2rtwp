module;

#include <intrin0.inl.h>
#include <capstone/capstone.h>

export module unpack.x86.disasm;

export import unpack.x86.instruction;

namespace x86 {

// simple RAII wrapper around capstone disassembler
struct Capstone
{
	csh handle = {};

	Capstone()
	{
		ensure(cs_open(CS_ARCH_X86, CS_MODE_64, &handle) == CS_ERR_OK);
		ensure(cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) == CS_ERR_OK);
	}

	~Capstone()
	{
		ensure(cs_close(&handle) == CS_ERR_OK);
	}
};

// singleton instance
Capstone gCapstone;

Reg convertReg(x86_reg reg)
{
	switch (reg)
	{
	case X86_REG_INVALID: return Reg::none;
	case X86_REG_AH: return Reg::ah;
	case X86_REG_AL: return Reg::al;
	case X86_REG_AX: return Reg::ax;
	case X86_REG_BH: return Reg::bh;
	case X86_REG_BL: return Reg::bl;
	case X86_REG_BP: return Reg::bp;
	case X86_REG_BPL: return Reg::bpl;
	case X86_REG_BX: return Reg::bx;
	case X86_REG_CH: return Reg::ch;
	case X86_REG_CL: return Reg::cl;
	case X86_REG_CS: return Reg::cs;
	case X86_REG_CX: return Reg::cx;
	case X86_REG_DH: return Reg::dh;
	case X86_REG_DI: return Reg::di;
	case X86_REG_DIL: return Reg::dil;
	case X86_REG_DL: return Reg::dl;
	case X86_REG_DS: return Reg::ds;
	case X86_REG_DX: return Reg::dx;
	case X86_REG_EAX: return Reg::eax;
	case X86_REG_EBP: return Reg::ebp;
	case X86_REG_EBX: return Reg::ebx;
	case X86_REG_ECX: return Reg::ecx;
	case X86_REG_EDI: return Reg::edi;
	case X86_REG_EDX: return Reg::edx;
	case X86_REG_ES: return Reg::es;
	case X86_REG_ESI: return Reg::esi;
	case X86_REG_ESP: return Reg::esp;
	case X86_REG_FS: return Reg::fs;
	case X86_REG_GS: return Reg::gs;
	case X86_REG_RAX: return Reg::rax;
	case X86_REG_RBP: return Reg::rbp;
	case X86_REG_RBX: return Reg::rbx;
	case X86_REG_RCX: return Reg::rcx;
	case X86_REG_RDI: return Reg::rdi;
	case X86_REG_RDX: return Reg::rdx;
	case X86_REG_RIP: return Reg::rip;
	//case X86_REG_RIZ: return Reg::zero;
	case X86_REG_RSI: return Reg::rsi;
	case X86_REG_RSP: return Reg::rsp;
	case X86_REG_SI: return Reg::si;
	case X86_REG_SIL: return Reg::sil;
	case X86_REG_SP: return Reg::sp;
	case X86_REG_SPL: return Reg::spl;
	case X86_REG_SS: return Reg::ss;
	case X86_REG_R8: return Reg::r8;
	case X86_REG_R9: return Reg::r9;
	case X86_REG_R10: return Reg::r10;
	case X86_REG_R11: return Reg::r11;
	case X86_REG_R12: return Reg::r12;
	case X86_REG_R13: return Reg::r13;
	case X86_REG_R14: return Reg::r14;
	case X86_REG_R15: return Reg::r15;
	case X86_REG_XMM0: return Reg::xmm0;
	case X86_REG_XMM1: return Reg::xmm1;
	case X86_REG_XMM2: return Reg::xmm2;
	case X86_REG_XMM3: return Reg::xmm3;
	case X86_REG_XMM4: return Reg::xmm4;
	case X86_REG_XMM5: return Reg::xmm5;
	case X86_REG_XMM6: return Reg::xmm6;
	case X86_REG_XMM7: return Reg::xmm7;
	case X86_REG_XMM8: return Reg::xmm8;
	case X86_REG_XMM9: return Reg::xmm9;
	case X86_REG_XMM10: return Reg::xmm10;
	case X86_REG_XMM11: return Reg::xmm11;
	case X86_REG_XMM12: return Reg::xmm12;
	case X86_REG_XMM13: return Reg::xmm13;
	case X86_REG_XMM14: return Reg::xmm14;
	case X86_REG_XMM15: return Reg::xmm15;
	case X86_REG_XMM16: return Reg::xmm16;
	case X86_REG_XMM17: return Reg::xmm17;
	case X86_REG_XMM18: return Reg::xmm18;
	case X86_REG_XMM19: return Reg::xmm19;
	case X86_REG_XMM20: return Reg::xmm20;
	case X86_REG_XMM21: return Reg::xmm21;
	case X86_REG_XMM22: return Reg::xmm22;
	case X86_REG_XMM23: return Reg::xmm23;
	case X86_REG_XMM24: return Reg::xmm24;
	case X86_REG_XMM25: return Reg::xmm25;
	case X86_REG_XMM26: return Reg::xmm26;
	case X86_REG_XMM27: return Reg::xmm27;
	case X86_REG_XMM28: return Reg::xmm28;
	case X86_REG_XMM29: return Reg::xmm29;
	case X86_REG_XMM30: return Reg::xmm30;
	case X86_REG_XMM31: return Reg::xmm31;
	case X86_REG_YMM0: return Reg::ymm0;
	case X86_REG_YMM1: return Reg::ymm1;
	case X86_REG_YMM2: return Reg::ymm2;
	case X86_REG_YMM3: return Reg::ymm3;
	case X86_REG_YMM4: return Reg::ymm4;
	case X86_REG_YMM5: return Reg::ymm5;
	case X86_REG_YMM6: return Reg::ymm6;
	case X86_REG_YMM7: return Reg::ymm7;
	case X86_REG_YMM8: return Reg::ymm8;
	case X86_REG_YMM9: return Reg::ymm9;
	case X86_REG_YMM10: return Reg::ymm10;
	case X86_REG_YMM11: return Reg::ymm11;
	case X86_REG_YMM12: return Reg::ymm12;
	case X86_REG_YMM13: return Reg::ymm13;
	case X86_REG_YMM14: return Reg::ymm14;
	case X86_REG_YMM15: return Reg::ymm15;
	case X86_REG_YMM16: return Reg::ymm16;
	case X86_REG_YMM17: return Reg::ymm17;
	case X86_REG_YMM18: return Reg::ymm18;
	case X86_REG_YMM19: return Reg::ymm19;
	case X86_REG_YMM20: return Reg::ymm20;
	case X86_REG_YMM21: return Reg::ymm21;
	case X86_REG_YMM22: return Reg::ymm22;
	case X86_REG_YMM23: return Reg::ymm23;
	case X86_REG_YMM24: return Reg::ymm24;
	case X86_REG_YMM25: return Reg::ymm25;
	case X86_REG_YMM26: return Reg::ymm26;
	case X86_REG_YMM27: return Reg::ymm27;
	case X86_REG_YMM28: return Reg::ymm28;
	case X86_REG_YMM29: return Reg::ymm29;
	case X86_REG_YMM30: return Reg::ymm30;
	case X86_REG_YMM31: return Reg::ymm31;
	case X86_REG_ZMM0: return Reg::zmm0;
	case X86_REG_ZMM1: return Reg::zmm1;
	case X86_REG_ZMM2: return Reg::zmm2;
	case X86_REG_ZMM3: return Reg::zmm3;
	case X86_REG_ZMM4: return Reg::zmm4;
	case X86_REG_ZMM5: return Reg::zmm5;
	case X86_REG_ZMM6: return Reg::zmm6;
	case X86_REG_ZMM7: return Reg::zmm7;
	case X86_REG_ZMM8: return Reg::zmm8;
	case X86_REG_ZMM9: return Reg::zmm9;
	case X86_REG_ZMM10: return Reg::zmm10;
	case X86_REG_ZMM11: return Reg::zmm11;
	case X86_REG_ZMM12: return Reg::zmm12;
	case X86_REG_ZMM13: return Reg::zmm13;
	case X86_REG_ZMM14: return Reg::zmm14;
	case X86_REG_ZMM15: return Reg::zmm15;
	case X86_REG_ZMM16: return Reg::zmm16;
	case X86_REG_ZMM17: return Reg::zmm17;
	case X86_REG_ZMM18: return Reg::zmm18;
	case X86_REG_ZMM19: return Reg::zmm19;
	case X86_REG_ZMM20: return Reg::zmm20;
	case X86_REG_ZMM21: return Reg::zmm21;
	case X86_REG_ZMM22: return Reg::zmm22;
	case X86_REG_ZMM23: return Reg::zmm23;
	case X86_REG_ZMM24: return Reg::zmm24;
	case X86_REG_ZMM25: return Reg::zmm25;
	case X86_REG_ZMM26: return Reg::zmm26;
	case X86_REG_ZMM27: return Reg::zmm27;
	case X86_REG_ZMM28: return Reg::zmm28;
	case X86_REG_ZMM29: return Reg::zmm29;
	case X86_REG_ZMM30: return Reg::zmm30;
	case X86_REG_ZMM31: return Reg::zmm31;
	case X86_REG_R8B: return Reg::r8b;
	case X86_REG_R9B: return Reg::r9b;
	case X86_REG_R10B: return Reg::r10b;
	case X86_REG_R11B: return Reg::r11b;
	case X86_REG_R12B: return Reg::r12b;
	case X86_REG_R13B: return Reg::r13b;
	case X86_REG_R14B: return Reg::r14b;
	case X86_REG_R15B: return Reg::r15b;
	case X86_REG_R8D: return Reg::r8d;
	case X86_REG_R9D: return Reg::r9d;
	case X86_REG_R10D: return Reg::r10d;
	case X86_REG_R11D: return Reg::r11d;
	case X86_REG_R12D: return Reg::r12d;
	case X86_REG_R13D: return Reg::r13d;
	case X86_REG_R14D: return Reg::r14d;
	case X86_REG_R15D: return Reg::r15d;
	case X86_REG_R8W: return Reg::r8w;
	case X86_REG_R9W: return Reg::r9w;
	case X86_REG_R10W: return Reg::r10w;
	case X86_REG_R11W: return Reg::r11w;
	case X86_REG_R12W: return Reg::r12w;
	case X86_REG_R13W: return Reg::r13w;
	case X86_REG_R14W: return Reg::r14w;
	case X86_REG_R15W: return Reg::r15w;
	default: throw std::runtime_error("Unexpected register");
	}
}

OpMem convertMem(const x86_op_mem& mem) { return{ convertReg(mem.segment), convertReg(mem.base), convertReg(mem.index), static_cast<i8>(mem.scale), static_cast<i32>(mem.disp) }; }

Operand convertOp(const cs_x86_op& op)
{
	ensure(!op.avx_bcast && !op.avx_zero_opmask);
	switch (op.type)
	{
	case X86_OP_REG:
	{
		const auto reg = convertReg(op.reg);
		ensure(reg.width() == op.size);
		return Operand{ reg, static_cast<i8>(op.size) };
	}
	case X86_OP_IMM:
		return Operand{ op.imm, static_cast<i8>(op.size) };
	case X86_OP_MEM:
		return Operand{ convertMem(op.mem), static_cast<i8>(op.size) };
	default:
		ensure(false); // unexpected op type
		return {};
	}
}

export Instruction disasm(std::span<const u8> code, i32 offset, i32 codeStart = 0, bool convertRipRelative = true)
{
	Instruction result{ codeStart + offset };

	// avoid memory allocations, mostly to provide thread safety...
	cs_detail detail;
	cs_insn insn;
	insn.detail = &detail;
	auto ptr = code.data() + offset;
	auto size = code.size() - offset;
	auto address = static_cast<size_t>(result.rva);
	if (cs_disasm_iter(gCapstone.handle, &ptr, &size, &address, &insn))
	{
		result.mnem = static_cast<x86_insn>(insn.id);
		result.length = insn.size;
		result.opcount = detail.x86.op_count;
		ensure(result.opcount <= result.ops.size());
		for (int i = 0; auto& op : result.operands())
		{
			op = convertOp(detail.x86.operands[i++]);
			if (convertRipRelative && op.type == OpType::Mem && op.mem.base == Reg::rip)
			{
				op.mem.base = Reg::imagebase;
				op.mem.displacement += result.rva + result.length;
			}
		}

		// multibyte nops have no real operands...
		if (result.mnem == X86_INS_NOP)
		{
			result.opcount = 0;
		}
	}

	return result;
}

}
