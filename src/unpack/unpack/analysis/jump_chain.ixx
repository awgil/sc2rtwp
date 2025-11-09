//module;
//
//#include <common/bitfield_ops.h>

export module unpack.analysis.jump_chain;

export import unpack.x86.disasm;

namespace analysis {

// Condition mask (in comments, first instruction is 'jump when set', second is 'jump if not set')
// order matches condition test field encoding, see B.1.4.7 in intel's manual - this can allow extracting bits 1-3 of the instruction byte...
enum class ConditionMask : u8
{
	None = 0,
	OF = 1 << 0, // jo - jno
	CF = 1 << 1, // jc/jb/jnae - jnc/jnb/jae
	ZF = 1 << 2, // je/jz - jne/jnz
	CZ = 1 << 3, // jbe/jna - jnbe/ja (CF | ZF)
	SF = 1 << 4, // js - jns
	PF = 1 << 5, // jp/jpe - jnp/jpo
	SO = 1 << 6, // jl/jnge - jnl/jge (SF ^ OF)
	LE = 1 << 7, // jle/jng - jnle/jg (ZF | (SF ^ OF))
};
//ADD_BITFIELD_OPS(ConditionMask);
//
//// a set of known values for condition flags
//class ConditionState
//{
//public:
//	void setAll(ConditionMask known, ConditionMask mask)
//	{
//		ensure((mask & ~known) == ConditionMask::None);
//		mKnown = known;
//		mValue = mask;
//	}
//
//	bool isKnown(ConditionMask flag) const { return (mKnown & flag) != ConditionMask::None; }
//	bool isSet(ConditionMask flag) const { return (mValue & flag) != ConditionMask::None; }
//
//	void forget(ConditionMask flag)
//	{
//		mKnown &= ~flag;
//		mValue &= ~flag;
//	}
//
//	void setConditional(ConditionMask flag, bool value)
//	{
//		// TODO: current code doesn't account for the fact that eg jbe taken followed by jc not taken implies jz will be taken...
//		setRaw(flag, value);
//	}
//
//	void setFlag(ConditionMask flag, bool value)
//	{
//		setRaw(flag, value);
//		if (flag == ConditionMask::CF || flag == ConditionMask::ZF)
//			updateOrPseudoflag(ConditionMask::CZ, ConditionMask::CF, ConditionMask::ZF);
//		if (flag == ConditionMask::OF || flag == ConditionMask::SF)
//			updateXorPseudoflag(ConditionMask::SO, ConditionMask::OF, ConditionMask::SF);
//		if (flag == ConditionMask::OF || flag == ConditionMask::SF || flag == ConditionMask::ZF)
//			updateXorPseudoflag(ConditionMask::LE, ConditionMask::ZF, ConditionMask::SO);
//	}
//
//private:
//	void setRaw(ConditionMask flag, bool value)
//	{
//		mKnown |= flag;
//		if (value)
//			mValue |= flag;
//		else
//			mValue &= ~flag;
//	}
//
//	void updateXorPseudoflag(ConditionMask flag, ConditionMask f1, ConditionMask f2)
//	{
//		if (isKnown(f1) && isKnown(f2))
//			setRaw(flag, isSet(f1) != isSet(f2));
//		else
//			forget(flag);
//	}
//
//	void updateOrPseudoflag(ConditionMask flag, ConditionMask f1, ConditionMask f2)
//	{
//		if (isSet(f1) || isSet(f2)) // set implies known
//			setRaw(flag, true);
//		else if (isKnown(f1) && isKnown(f2))
//			setRaw(flag, false);
//		else
//			forget(flag);
//	}
//
//private:
//	ConditionMask mKnown = ConditionMask::None;
//	ConditionMask mValue = ConditionMask::None; // invariant: mValue & ~mKnown == 0 (ie all unknown bits are zero)
//};

// special form of nop used as filler in jump chains: "s[ha][lr] x,0", "xchg/mov reg,reg"
bool isEffectiveNop(const x86::Instruction& ins)
{
	switch (ins.mnem)
	{
	case X86_INS_SAL: case X86_INS_SAR: case X86_INS_SHL: case X86_INS_SHR:
		return ins.ops[1] == 0;
	case X86_INS_MOV: case X86_INS_XCHG:
		return ins.ops[0] == ins.ops[1];
	default:
		return false;
	}
}

// instructions that only modify flags and are used in jump chains: "[x]or x,0", "and x,~0", "test x,y", "clc/stc"
// clc/stc clears/sets CF without touching remaining flags, rest clear CF/OF and modify remaining flags
bool isFlagsOnly(const x86::Instruction& ins)
{
	switch (ins.mnem)
	{
	case X86_INS_OR: case X86_INS_XOR:
		return ins.ops[1] == 0;
	case X86_INS_AND:
		return ins.ops[1] == -1;
	case X86_INS_TEST: case X86_INS_CLC: case X86_INS_STC:
		return true;
	default:
		return false;
	}
}

// get a set of jcc instructions that are always-taken after specific flags-only instruction
std::span<const x86::Mnem> getGuaranteedConditions(x86::Mnem ins)
{
	static const x86::Mnem stc[] = { X86_INS_JB, X86_INS_JBE }; // stc sets CF => jb/jbe are unconditional
	static const x86::Mnem clc[] = { X86_INS_JAE }; // clc clears CF => jae is unconditional
	static const x86::Mnem rest[] = { X86_INS_JAE, X86_INS_JNO }; // other clear CF & OF => jae/jno are unconditional
	switch (ins)
	{
	case X86_INS_STC: return stc;
	case X86_INS_CLC: return clc;
	default: return rest;
	}
}

bool isJmpRel(const x86::Instruction& ins) { return ins.mnem == X86_INS_JMP && ins.ops[0].type == x86::OpType::Imm; }
bool isJccRel(const x86::Instruction& ins) { return ins.mnem.isConditionalJump() && ins.ops[0].type == x86::OpType::Imm; }

// returns condition flag + whether it's taken if flag is set
auto getJumpCondition(x86::Mnem mnem)
{
	switch (mnem)
	{
	case X86_INS_JO:  return std::pair(ConditionMask::OF, true);
	case X86_INS_JNO: return std::pair(ConditionMask::OF, false);
	case X86_INS_JB:  return std::pair(ConditionMask::CF, true);
	case X86_INS_JAE: return std::pair(ConditionMask::CF, false);
	case X86_INS_JE:  return std::pair(ConditionMask::ZF, true);
	case X86_INS_JNE: return std::pair(ConditionMask::ZF, false);
	case X86_INS_JBE: return std::pair(ConditionMask::CZ, true);
	case X86_INS_JA:  return std::pair(ConditionMask::CZ, false);
	case X86_INS_JS:  return std::pair(ConditionMask::SF, true);
	case X86_INS_JNS: return std::pair(ConditionMask::SF, false);
	case X86_INS_JP:  return std::pair(ConditionMask::PF, true);
	case X86_INS_JNP: return std::pair(ConditionMask::PF, false);
	case X86_INS_JL:  return std::pair(ConditionMask::SO, true);
	case X86_INS_JGE: return std::pair(ConditionMask::SO, false);
	case X86_INS_JLE: return std::pair(ConditionMask::LE, true);
	case X86_INS_JG:  return std::pair(ConditionMask::LE, false);
	default: throw std::exception("Unexpected Jcc");
	}
}

// debug logging
enum class LogLevel { None, Important, Verbose, Nops };
constexpr LogLevel gLogLevel = LogLevel::Important;

template<typename... Args>
void log(LogLevel level, std::format_string<Args...> fmt, Args&&... args)
{
	if (level > gLogLevel)
		return;
	std::print("[JumpChain] ");
	std::println(fmt, std::forward<Args>(args)...);
}

void log(LogLevel level, const x86::Instruction& ins, std::string_view message, std::string_view prefix = {}) { log(level, "{}{:X}: {} = {}", prefix, ins.rva, ins, message); }

// yield passed instruction (depending on argument), and then disassemble and continue yielding subsequent ones
std::generator<const x86::Instruction&> disasmSequence(std::span<const u8> imageBytes, const x86::Instruction& firstIns, bool yieldFirst)
{
	if (yieldFirst)
		co_yield firstIns;
	auto rva = firstIns.rva + firstIns.length;;
	while (true)
	{
		auto next = x86::disasm(imageBytes, rva);
		co_yield next;
		rva = next.rva + next.length;
	}
}

// find next 'interesting' (non-nop) instruction
x86::Instruction disasmNextNonNop(std::span<const u8> imageBytes, const x86::Instruction& firstIns, bool considerFirst, std::string_view logPrefix = {})
{
	for (auto& ins : disasmSequence(imageBytes, firstIns, considerFirst))
	{
		if (ins.mnem != X86_INS_NOP && !isEffectiveNop(ins))
			return ins;
		log(LogLevel::Nops, ins, "nop", logPrefix);
	}
	std::unreachable(); // the loop never ends naturally
}

i32 followJumpChain(std::span<const u8> imageBytes, const x86::Instruction& jcc, std::span<const x86::Mnem> expected, std::string_view logPrefix)
{
	auto rva = jcc.ops[0].immediate<i32>();
	while (true)
	{
		auto ins = disasmNextNonNop(imageBytes, x86::disasm(imageBytes, rva), true, logPrefix);
		auto isJump = (ins.mnem == X86_INS_JMP || std::ranges::contains(expected, ins.mnem)) && ins.ops[0].type == x86::OpType::Imm;
		log(LogLevel::Verbose, ins, isJump ? "jcc chain cont" : "jcc chain end", logPrefix);
		if (!isJump)
			return rva;
		rva = ins.ops[0].immediate<i32>();
	}
}

i32 followJumpChain(std::span<const u8> imageBytes, const x86::Instruction& jcc, std::string_view logPrefix)
{
	const x86::Mnem expected[] = { jcc.mnem };
	return followJumpChain(imageBytes, jcc, expected, logPrefix);
}

i32 findJumpChainEnd(std::span<const u8> imageBytes, const x86::Instruction& firstIns)
{
	log(LogLevel::Verbose, "Starting from {:X}", firstIns.rva);
	auto first = disasmNextNonNop(imageBytes, firstIns, true);
	if (isFlagsOnly(first))
	{
		log(LogLevel::Verbose, first, "flags-only");
		auto second = disasmNextNonNop(imageBytes, first, false);
		auto expected = getGuaranteedConditions(first.mnem);
		if (std::ranges::contains(expected, second.mnem) && second.ops[0].type == x86::OpType::Imm)
		{
			log(LogLevel::Verbose, second, "jcc chain start");
			auto target = followJumpChain(imageBytes, second, expected, {});
			log(LogLevel::Important, first, "*** always-taken branch!");
			return target;
		}
		else
		{
			log(LogLevel::Verbose, second, "not a jcc chain");
			ensure(first.mnem == X86_INS_TEST); // TODO: are there legitimate reasons to have other instructions?
			return 0;
		}
	}
	else if (isJccRel(first))
	{
		// if the next interesting instruction is opposite jump, see if two chains converge
		log(LogLevel::Verbose, first, "jcc");
		auto second = disasmNextNonNop(imageBytes, first, false);
		if (!isJccRel(second))
		{
			log(LogLevel::Verbose, second, "not a jcc pair");
			return 0;
		}

		auto [c1, v1] = getJumpCondition(first.mnem);
		auto [c2, v2] = getJumpCondition(second.mnem);
		auto matchingPair = c1 == c2 && v1 != v2;
		if (!matchingPair)
		{
			log(LogLevel::Verbose, second, "mismatched jcc pair");
			return 0;
		}

		log(LogLevel::Verbose, second, "matching jcc pair");
		auto branch1 = followJumpChain(imageBytes, first, "+ ");
		auto branch2 = followJumpChain(imageBytes, second, "- ");
		if (branch1 != branch2)
		{
			// TODO: should second conditional jump be patched to jmp?..
			log(LogLevel::Important, second, "*** diverging branch!");
			__debugbreak();
			return 0;
		}

		log(LogLevel::Important, first, "*** converging branch!");
		return branch1;
	}
	else
	{
		log(LogLevel::Important, first, "unexpected");
		__debugbreak();
		return 0;
	}
}

// TODO: this is quite ugly, refactor...
// we really need to support the following:
// 1. <flags-only> <jcc> -> <jcc> -> ... -> <term> ==> <jmp term> (jcc guaranteed to be taken)
// 2. <jcc> <jncc>   -> <jncc> -> ... -> <term> ==> <jmp term>
//          -> <jcc> -> <jcc>  -> ... -> <term>
// so i guess we could start by skipping over nops & flags-only (maintaining flags state) (and following unconditional jmps?..) until we reach first conditional jump
// then if conditional jump is guaranteed, we have a chain of type 1, so just continue following (skip nops and follow same jccs)
// otherwise continue looking forward by the flow - if the rest is nops followed by inverse jump, we have a chain of type 2, *if* chains converge
//i32 findJumpChainEndOld(std::span<const u8> imageBytes, const x86::Instruction& firstIns, ConditionState flags, bool afterJump = false)
//{
//	do {
//		auto next = ins.rva + ins.length; // by default, continue with the flow
//		std::print("[FJCE] {:X}: {} = ", ins.rva, ins);
//		if (ins.mnem == X86_INS_NOP || isEffectiveNop(ins))
//		{
//			std::println("nop");
//			; // just continue
//		}
//		else if (isFlagsOnly(ins))
//		{
//			std::println("flags-only");
//			if (ins.mnem == X86_INS_CLC)
//				flags.setFlag(ConditionMask::CF, false);
//			else if (ins.mnem == X86_INS_STC)
//				flags.setFlag(ConditionMask::CF, true);
//			else
//				flags.setAll(ConditionMask::OF | ConditionMask::CF, ConditionMask::None);
//		}
//		else if (ins.mnem == X86_INS_JMP)
//		{
//			if (ins.ops[0].type != x86::OpType::Imm)
//				break; // indirect jump
//			// note: consider a following situation: jump chain -> test r1,r1 -> jz (diverging)
//			next = ins.ops[0].imm;
//			std::println("jmp {:X} (recurse)", next);
//			auto target = findJumpChainEnd(imageBytes, x86::disasm(imageBytes, next), flags, true);
//			return target ? target : next;
//		}
//		else if (ins.mnem.isConditionalJump())
//		{
//			if (ins.ops[0].type != x86::OpType::Imm)
//			{
//				std::println("indirect jcc");
//				return 0; // only direct jumps are supported
//			}
//			auto targetTaken = ins.ops[0].immediate<i32>();
//			auto targetNotTaken = ins.rva + ins.length;
//			auto [cond, value] = getJumpCondition(ins.mnem);
//			if (!flags.isKnown(cond))
//			{
//				std::println("jcc branch");
//
//				auto flagsTaken = flags;
//				flagsTaken.setConditional(cond, value);
//				auto endTaken = findJumpChainEnd(imageBytes, x86::disasm(imageBytes, targetTaken), flagsTaken, true);
//				if (!endTaken)
//					endTaken = targetTaken;
//
//				flags.setConditional(cond, !value);
//				auto endNT = findJumpChainEnd(imageBytes, x86::disasm(imageBytes, targetNotTaken), flags, true);
//				if (!endNT)
//					endNT = targetNotTaken;
//
//				auto converging = endTaken == endNT;
//				return converging ? endTaken : 0;
//			}
//			else
//			{
//				auto taken = flags.isSet(cond) == value;
//				auto target = taken ? targetTaken : targetNotTaken;
//				std::println("jcc always={} -> {:X}", taken, target);
//				auto end = findJumpChainEnd(imageBytes, x86::disasm(imageBytes, target), flags, true);
//				return end ? end : target;
//			}
//		}
//		else
//		{
//			// end of jump chain
//			break;
//		}
//
//		// if we're still here, continue following the chain...
//		ins = x86::disasm(imageBytes, next);
//	} while (true);
//	std::println("return {:X}", afterJump ? ins.rva : 0);
//	return afterJump ? ins.rva : 0;
//}

// returns jump chain end RVA if passed instruction is the start of the jump chain, or 0 if not
export i32 findJumpChainTarget(std::span<const u8> imageBytes, const x86::Instruction& ins)
{
	// jump chains can start with effective nops, flags-only instructions, or conditional jumps
	// conditional jumps and test are also encountered normally
	if (ins.mnem == X86_INS_TEST || isJccRel(ins))
		return findJumpChainEnd(imageBytes, ins);
	return isEffectiveNop(ins) || isFlagsOnly(ins) ? ensure(findJumpChainEnd(imageBytes, ins)) : 0;
}

// disassemble instruction at given offset, then check whether it's start of jump chain
// if it is not, return actual disassembled instruction
// otherwise, return fake jmp instruction with length 1 (real disassembled jumps are always longer)
export x86::Instruction disasmResolveJumpChains(std::span<const u8> imageBytes, i32 rva)
{
	auto ins = x86::disasm(imageBytes, rva);
	if (const auto chainTarget = findJumpChainTarget(imageBytes, ins))
	{
		// short jump is 2 bytes => -128 <= (target - rva - 2) <= 127
		//auto relShort = chainTarget - rva - 2;
		//bool canShortJump = relShort >= std::numeric_limits<i8>::min() && relShort <= std::numeric_limits<i8>::max();
		ins = { rva, X86_INS_JMP, 1, 1, { x86::Operand{ chainTarget, 4 } } };
	}
	return ins;
}

}
