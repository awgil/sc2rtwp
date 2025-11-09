module;

#include <capstone/capstone.h>

export module unpack.instruction;

import std;
import common;
import unpack.pe_binary;

export struct Register
{
	// offset is in virtual register file
	static std::pair<int, int> toOffsetSize(x86_reg reg)
	{
		static constexpr int gprStart = 0;
		static constexpr int gprSize = 8;
		static auto gprOffset = [](int index) { return gprStart + index * gprSize; };
		static auto gprPair = [](int index, int size, int offset = 0) { return std::make_pair(gprOffset(index) + offset, size); };
		static constexpr int xmmStart = gprOffset(16);
		static constexpr int xmmSize = 64;
		static auto xmmOffset = [](int index) { return xmmStart + index * xmmSize; };
		static auto xmmPair = [](int index, int size) { return std::make_pair(xmmOffset(index), size); };
		// unsupported: flags, ip, segment regs, cr, dr, fpu, mmx, k (avx), bnd
		switch (reg)
		{
		case X86_REG_AL: return gprPair(0, 1);
		case X86_REG_AH: return gprPair(0, 1, 1);
		case X86_REG_AX: return gprPair(0, 2);
		case X86_REG_EAX: return gprPair(0, 4);
		case X86_REG_RAX: return gprPair(0, 8);
		case X86_REG_CL: return gprPair(1, 1);
		case X86_REG_CH: return gprPair(1, 1, 1);
		case X86_REG_CX: return gprPair(1, 2);
		case X86_REG_ECX: return gprPair(1, 4);
		case X86_REG_RCX: return gprPair(1, 8);
		case X86_REG_DL: return gprPair(2, 1);
		case X86_REG_DH: return gprPair(2, 1, 1);
		case X86_REG_DX: return gprPair(2, 2);
		case X86_REG_EDX: return gprPair(2, 4);
		case X86_REG_RDX: return gprPair(2, 8);
		case X86_REG_BL: return gprPair(3, 1);
		case X86_REG_BH: return gprPair(3, 1, 1);
		case X86_REG_BX: return gprPair(3, 2);
		case X86_REG_EBX: return gprPair(3, 4);
		case X86_REG_RBX: return gprPair(3, 8);
		case X86_REG_SPL: return gprPair(4, 1);
		case X86_REG_SP: return gprPair(4, 2);
		case X86_REG_ESP: return gprPair(4, 4);
		case X86_REG_RSP: return gprPair(4, 8);
		case X86_REG_BPL: return gprPair(5, 1);
		case X86_REG_BP: return gprPair(5, 2);
		case X86_REG_EBP: return gprPair(5, 4);
		case X86_REG_RBP: return gprPair(5, 8);
		case X86_REG_SIL: return gprPair(6, 1);
		case X86_REG_SI: return gprPair(6, 2);
		case X86_REG_ESI: return gprPair(6, 4);
		case X86_REG_RSI: return gprPair(6, 8);
		case X86_REG_DIL: return gprPair(7, 1);
		case X86_REG_DI: return gprPair(7, 2);
		case X86_REG_EDI: return gprPair(7, 4);
		case X86_REG_RDI: return gprPair(7, 8);
		case X86_REG_R8B: return gprPair(8, 1);
		case X86_REG_R8W: return gprPair(8, 2);
		case X86_REG_R8D: return gprPair(8, 4);
		case X86_REG_R8: return gprPair(8, 8);
		case X86_REG_R9B: return gprPair(9, 1);
		case X86_REG_R9W: return gprPair(9, 2);
		case X86_REG_R9D: return gprPair(9, 4);
		case X86_REG_R9: return gprPair(9, 8);
		case X86_REG_R10B: return gprPair(10, 1);
		case X86_REG_R10W: return gprPair(10, 2);
		case X86_REG_R10D: return gprPair(10, 4);
		case X86_REG_R10: return gprPair(10, 8);
		case X86_REG_R11B: return gprPair(11, 1);
		case X86_REG_R11W: return gprPair(11, 2);
		case X86_REG_R11D: return gprPair(11, 4);
		case X86_REG_R11: return gprPair(11, 8);
		case X86_REG_R12B: return gprPair(12, 1);
		case X86_REG_R12W: return gprPair(12, 2);
		case X86_REG_R12D: return gprPair(12, 4);
		case X86_REG_R12: return gprPair(12, 8);
		case X86_REG_R13B: return gprPair(13, 1);
		case X86_REG_R13W: return gprPair(13, 2);
		case X86_REG_R13D: return gprPair(13, 4);
		case X86_REG_R13: return gprPair(13, 8);
		case X86_REG_R14B: return gprPair(14, 1);
		case X86_REG_R14W: return gprPair(14, 2);
		case X86_REG_R14D: return gprPair(14, 4);
		case X86_REG_R14: return gprPair(14, 8);
		case X86_REG_R15B: return gprPair(15, 1);
		case X86_REG_R15W: return gprPair(15, 2);
		case X86_REG_R15D: return gprPair(15, 4);
		case X86_REG_R15: return gprPair(15, 8);
		case X86_REG_XMM0: return xmmPair(0, 16);
		case X86_REG_YMM0: return xmmPair(0, 32);
		case X86_REG_ZMM0: return xmmPair(0, 64);
		case X86_REG_XMM1: return xmmPair(1, 16);
		case X86_REG_YMM1: return xmmPair(1, 32);
		case X86_REG_ZMM1: return xmmPair(1, 64);
		case X86_REG_XMM2: return xmmPair(2, 16);
		case X86_REG_YMM2: return xmmPair(2, 32);
		case X86_REG_ZMM2: return xmmPair(2, 64);
		case X86_REG_XMM3: return xmmPair(3, 16);
		case X86_REG_YMM3: return xmmPair(3, 32);
		case X86_REG_ZMM3: return xmmPair(3, 64);
		case X86_REG_XMM4: return xmmPair(4, 16);
		case X86_REG_YMM4: return xmmPair(4, 32);
		case X86_REG_ZMM4: return xmmPair(4, 64);
		case X86_REG_XMM5: return xmmPair(5, 16);
		case X86_REG_YMM5: return xmmPair(5, 32);
		case X86_REG_ZMM5: return xmmPair(5, 64);
		case X86_REG_XMM6: return xmmPair(6, 16);
		case X86_REG_YMM6: return xmmPair(6, 32);
		case X86_REG_ZMM6: return xmmPair(6, 64);
		case X86_REG_XMM7: return xmmPair(7, 16);
		case X86_REG_YMM7: return xmmPair(7, 32);
		case X86_REG_ZMM7: return xmmPair(7, 64);
		case X86_REG_XMM8: return xmmPair(8, 16);
		case X86_REG_YMM8: return xmmPair(8, 32);
		case X86_REG_ZMM8: return xmmPair(8, 64);
		case X86_REG_XMM9: return xmmPair(9, 16);
		case X86_REG_YMM9: return xmmPair(9, 32);
		case X86_REG_ZMM9: return xmmPair(9, 64);
		case X86_REG_XMM10: return xmmPair(10, 16);
		case X86_REG_YMM10: return xmmPair(10, 32);
		case X86_REG_ZMM10: return xmmPair(10, 64);
		case X86_REG_XMM11: return xmmPair(11, 16);
		case X86_REG_YMM11: return xmmPair(11, 32);
		case X86_REG_ZMM11: return xmmPair(11, 64);
		case X86_REG_XMM12: return xmmPair(12, 16);
		case X86_REG_YMM12: return xmmPair(12, 32);
		case X86_REG_ZMM12: return xmmPair(12, 64);
		case X86_REG_XMM13: return xmmPair(13, 16);
		case X86_REG_YMM13: return xmmPair(13, 32);
		case X86_REG_ZMM13: return xmmPair(13, 64);
		case X86_REG_XMM14: return xmmPair(14, 16);
		case X86_REG_YMM14: return xmmPair(14, 32);
		case X86_REG_ZMM14: return xmmPair(14, 64);
		case X86_REG_XMM15: return xmmPair(15, 16);
		case X86_REG_YMM15: return xmmPair(15, 32);
		case X86_REG_ZMM15: return xmmPair(15, 64);
		case X86_REG_XMM16: return xmmPair(16, 16);
		case X86_REG_YMM16: return xmmPair(16, 32);
		case X86_REG_ZMM16: return xmmPair(16, 64);
		case X86_REG_XMM17: return xmmPair(17, 16);
		case X86_REG_YMM17: return xmmPair(17, 32);
		case X86_REG_ZMM17: return xmmPair(17, 64);
		case X86_REG_XMM18: return xmmPair(18, 16);
		case X86_REG_YMM18: return xmmPair(18, 32);
		case X86_REG_ZMM18: return xmmPair(18, 64);
		case X86_REG_XMM19: return xmmPair(19, 16);
		case X86_REG_YMM19: return xmmPair(19, 32);
		case X86_REG_ZMM19: return xmmPair(19, 64);
		case X86_REG_XMM20: return xmmPair(20, 16);
		case X86_REG_YMM20: return xmmPair(20, 32);
		case X86_REG_ZMM20: return xmmPair(20, 64);
		case X86_REG_XMM21: return xmmPair(21, 16);
		case X86_REG_YMM21: return xmmPair(21, 32);
		case X86_REG_ZMM21: return xmmPair(21, 64);
		case X86_REG_XMM22: return xmmPair(22, 16);
		case X86_REG_YMM22: return xmmPair(22, 32);
		case X86_REG_ZMM22: return xmmPair(22, 64);
		case X86_REG_XMM23: return xmmPair(23, 16);
		case X86_REG_YMM23: return xmmPair(23, 32);
		case X86_REG_ZMM23: return xmmPair(23, 64);
		case X86_REG_XMM24: return xmmPair(24, 16);
		case X86_REG_YMM24: return xmmPair(24, 32);
		case X86_REG_ZMM24: return xmmPair(24, 64);
		case X86_REG_XMM25: return xmmPair(25, 16);
		case X86_REG_YMM25: return xmmPair(25, 32);
		case X86_REG_ZMM25: return xmmPair(25, 64);
		case X86_REG_XMM26: return xmmPair(26, 16);
		case X86_REG_YMM26: return xmmPair(26, 32);
		case X86_REG_ZMM26: return xmmPair(26, 64);
		case X86_REG_XMM27: return xmmPair(27, 16);
		case X86_REG_YMM27: return xmmPair(27, 32);
		case X86_REG_ZMM27: return xmmPair(27, 64);
		case X86_REG_XMM28: return xmmPair(28, 16);
		case X86_REG_YMM28: return xmmPair(28, 32);
		case X86_REG_ZMM28: return xmmPair(28, 64);
		case X86_REG_XMM29: return xmmPair(29, 16);
		case X86_REG_YMM29: return xmmPair(29, 32);
		case X86_REG_ZMM29: return xmmPair(29, 64);
		case X86_REG_XMM30: return xmmPair(30, 16);
		case X86_REG_YMM30: return xmmPair(30, 32);
		case X86_REG_ZMM30: return xmmPair(30, 64);
		case X86_REG_XMM31: return xmmPair(31, 16);
		case X86_REG_YMM31: return xmmPair(31, 32);
		case X86_REG_ZMM31: return xmmPair(31, 64);
		default: throw std::exception("Unsupported register");
		}
	}

	static std::pair<int, int> toRange(x86_reg reg)
	{
		auto [begin, size] = toOffsetSize(reg);
		return{ begin, begin + size };
	}
};

export enum class OperandType : u8
{
	Invalid, // not an operand
	Reg,
	Imm,
	Mem,
	ImmRVA, // immediate, to be treated as RVA (jump/call)
	MemRVA, // memory; base is to be ignored (assumed 0), displacement is rva (rip-relative)
};

// TODO: improve..
export struct Operand
{
	OperandType type;
	u8 size;
	x86_reg reg : 9; // only valid if type == Reg
	cs_ac_type access : 7;
};
//static_assert(sizeof(Operand) == 4);

// TODO: this can be seriously improved (eg max 1 memory access, max 1 displacement, ...)
export struct Instruction
{
	rva_t rva;
	x86_insn mnem;
	u8 opcount;
	Operand ops[4];
	x86_op_mem mem; // data for memory operand (if any)
	int64_t imm; // immediate operand value (if any)

	std::span<Operand> operands() { return { ops, opcount }; }
	std::span<const Operand> operands() const { return { ops, opcount }; }
};

// utility for pretty-printing instructions
export struct InstructionPrinter
{
	const PEBinary& mBin;
	const Instruction& mIsn;

	InstructionPrinter(const PEBinary& bin, const Instruction& isn) : mBin(bin), mIsn(isn) {}
};

export template<> struct std::formatter<InstructionPrinter>
{
	constexpr auto parse(format_parse_context& ctx)
	{
		return ctx.begin();
	}

	auto formatReg(const PEBinary& bin, x86_reg reg, format_context& ctx) const
	{
		return format_to(ctx.out(), "{}", bin.registerName(reg));
	}

	auto formatSize(u8 size, format_context& ctx) const
	{
		switch (size)
		{
		case 1: return format_to(ctx.out(), "byte");
		case 2: return format_to(ctx.out(), "word");
		case 4: return format_to(ctx.out(), "dword");
		case 8: return format_to(ctx.out(), "qword");
		case 16: return format_to(ctx.out(), "xmmword");
		case 32: return format_to(ctx.out(), "ymmword");
		case 64: return format_to(ctx.out(), "zmmword");
		default: return format_to(ctx.out(), "{}", size);
		}
	}

	auto formatMem(const PEBinary& bin, u8 size, const x86_op_mem& mem, format_context& ctx) const
	{
		formatSize(size, ctx);
		format_to(ctx.out(), " ptr ");
		if (mem.segment != X86_REG_INVALID)
		{
			formatReg(bin, mem.segment, ctx);
			*ctx.out()++ = ':';
		}
		*ctx.out()++ = '[';
		formatReg(bin, mem.base, ctx);
		if (mem.index != X86_REG_INVALID)
		{
			format_to(ctx.out(), " + ");
			if (mem.scale > 1)
				format_to(ctx.out(), "{} * ", mem.scale);
			formatReg(bin, mem.index, ctx);
		}
		if (mem.disp > 0)
			format_to(ctx.out(), " + 0x{:X}", mem.disp);
		else if (mem.disp < 0)
			format_to(ctx.out(), " - 0x{:X}", -mem.disp);
		*ctx.out()++ = ']';
		return ctx.out();
	}

	auto formatMemRVA(const PEBinary& bin, u8 size, const x86_op_mem& mem, format_context& ctx) const
	{
		formatSize(size, ctx);
		format_to(ctx.out(), " ptr ");
		assert(mem.segment == X86_REG_INVALID);
		format_to(ctx.out(), "[rva 0x{}", mem.disp);
		if (mem.index != X86_REG_INVALID)
		{
			format_to(ctx.out(), " + ");
			if (mem.scale > 1)
				format_to(ctx.out(), "{} * ", mem.scale);
			formatReg(bin, mem.index, ctx);
		}
		*ctx.out()++ = ']';
		return ctx.out();
	}

	auto formatOperand(const PEBinary& bin, const Instruction& isn, const Operand& op, format_context& ctx) const
	{
		switch (op.type)
		{
		case OperandType::Reg: return formatReg(bin, op.reg, ctx);
		case OperandType::Imm: return format_to(ctx.out(), "{}", isn.imm);
		case OperandType::Mem: return formatMem(bin, op.size, isn.mem, ctx);
		case OperandType::ImmRVA: return format_to(ctx.out(), "rva 0x{:X}", isn.imm);
		case OperandType::MemRVA: return formatMemRVA(bin, op.size, isn.mem, ctx);
		default: return format_to(ctx.out(), "???");
		}
	}

	auto format(const InstructionPrinter& obj, format_context& ctx) const
	{
		format_to(ctx.out(), "{}", obj.mBin.instructionName(obj.mIsn.mnem));
		for (int i = 0; i < obj.mIsn.opcount; ++i)
		{
			if (i != 0)
				*ctx.out()++ = ',';
			*ctx.out()++ = ' ';
			formatOperand(obj.mBin, obj.mIsn, obj.mIsn.ops[i], ctx);
		}
		return ctx.out();
	}
};
