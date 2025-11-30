export module unpack.analysis.jump_chain;

export import unpack.x86.disasm;

namespace analysis {

// debug logging
enum class LogLevel { None, Important, Verbose, Nops };
Logger log{ "JumpChain", LogLevel::None };
void logIns(LogLevel level, const x86::Instruction& ins, std::string_view message, const NestingTracker& nesting) { log(level, "{} {:X}: {} = {}", nesting, ins.rva, ins, message); }

// a set of known values for condition flags
class ConditionState
{
public:
	static constexpr u8 mask(x86::Condition c) { return 1 << std::to_underlying(c); }

	ConditionState() = default;
	ConditionState(x86::ConditionTest cc) { setConditional(cc); }

	ConditionState(u8 known, u8 values)
	{
		ensure((values & ~known) == 0);
		mKnown = known;
		mValue = values;
	}

	bool isKnown(x86::Condition flag) const { return (mKnown & mask(flag)) != 0; }
	bool isSet(x86::Condition flag) const { return (mValue & mask(flag)) != 0; }

	void forget(x86::Condition flag)
	{
		auto m = mask(flag);
		mKnown &= ~m;
		mValue &= ~m;
	}

	void setConditional(x86::ConditionTest cc)
	{
		// TODO: current code doesn't account for the fact that eg jbe taken followed by jc not taken implies jz will be taken...
		setRaw(cc.condition(), !cc.negated());
	}

	void setFlag(x86::Condition flag, bool value)
	{
		setRaw(flag, value);
		if (flag == x86::Condition::CF || flag == x86::Condition::ZF)
			updateOrPseudoflag(x86::Condition::CZ, x86::Condition::CF, x86::Condition::ZF);
		if (flag == x86::Condition::OF || flag == x86::Condition::SF)
			updateXorPseudoflag(x86::Condition::SO, x86::Condition::OF, x86::Condition::SF);
		if (flag == x86::Condition::OF || flag == x86::Condition::SF || flag == x86::Condition::ZF)
			updateXorPseudoflag(x86::Condition::LE, x86::Condition::ZF, x86::Condition::SO);
	}

private:
	void setRaw(x86::Condition flag, bool value)
	{
		auto m = mask(flag);
		mKnown |= m;
		if (value)
			mValue |= m;
		else
			mValue &= ~m;
	}

	void updateXorPseudoflag(x86::Condition flag, x86::Condition f1, x86::Condition f2)
	{
		if (isKnown(f1) && isKnown(f2))
			setRaw(flag, isSet(f1) != isSet(f2));
		else
			forget(flag);
	}

	void updateOrPseudoflag(x86::Condition flag, x86::Condition f1, x86::Condition f2)
	{
		if (isSet(f1) || isSet(f2)) // set implies known
			setRaw(flag, true);
		else if (isKnown(f1) && isKnown(f2))
			setRaw(flag, false);
		else
			forget(flag);
	}

private:
	u8 mKnown = 0;
	u8 mValue = 0; // invariant: mValue & ~mKnown == 0 (ie all unknown bits are zero)
};

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

bool isJmpRel(const x86::Instruction& ins) { return ins.mnem == X86_INS_JMP && ins.ops[0].type == x86::OpType::Imm; }
bool isJccRel(const x86::Instruction& ins) { return ins.mnem.isConditionalJump() && ins.ops[0].type == x86::OpType::Imm; }
i32 relTarget(const x86::Instruction& ins) { return ins.ops[0].immediate<i32>(); }
bool isTestConditionNormal(x86::Condition cond) { return cond != x86::Condition::OF && cond != x86::Condition::CF && cond != x86::Condition::PF; } // these condition are meaningful after test (SF is proxy for SO, for < 0)

// update condition state for specific instruction
ConditionState updateConditionFlagsOnly(ConditionState cond, x86::Mnem mnem)
{
	static constexpr u8 maskOFCF = ConditionState::mask(x86::Condition::OF) | ConditionState::mask(x86::Condition::CF);
	if (mnem == X86_INS_CLC)
		cond.setFlag(x86::Condition::CF, false);
	else if (mnem == X86_INS_STC)
		cond.setFlag(x86::Condition::CF, true);
	else
		cond = { maskOFCF, 0 };
	return cond;
}

// find next 'interesting' (non-nop) instruction
x86::Instruction disasmNextNonNop(std::span<const u8> imageBytes, i32 rva, const NestingTracker& nesting)
{
	while (true)
	{
		auto next = x86::disasm(imageBytes, rva);
		ensure(next.length);
		if (next.mnem != X86_INS_NOP && !isEffectiveNop(next))
			return next;
		logIns(LogLevel::Nops, next, "nop", nesting);
		rva = next.endRVA();
	}
}

// TODO: this is an old version, it kinda supports recursive chains, but it's ugly
// at least, explain afterJump meaning and return values in different circumstances...
/*
i32 findJumpChainEnd(std::span<const u8> imageBytes, const x86::Instruction& firstIns, x86::ConditionState flags, const NestingTracker& nesting, bool afterJump = false)
{
	auto ins = firstIns;
	do {
		auto next = ins.endRVA(); // by default, continue with the flow
		if (ins.mnem == X86_INS_NOP || isEffectiveNop(ins))
		{
			logIns(LogLevel::Nops, ins, "nop", nesting);
			; // just continue
		}
		else if (isFlagsOnly(ins))
		{
			logIns(LogLevel::Verbose, ins, "flags", nesting);
			flags = updateConditionFlagsOnly(flags, ins.mnem);
		}
		else if (isJmpRel(ins))
		{
			// note: consider a following situation: jump chain -> test r1,r1 -> jz (diverging)
			next = ins.ops[0].immediate<i32>();
			logIns(LogLevel::Verbose, ins, "jmp", nesting);
			auto target = findJumpChainEnd(imageBytes, x86::disasm(imageBytes, next), flags, nesting, true);
			return target ? target : next;
		}
		else if (isJccRel(ins))
		{
			auto targetTaken = ins.ops[0].immediate<i32>();
			auto targetNotTaken = next;
			auto cc = ins.mnem.conditionCode();
			if (!flags.isKnown(cc.condition()))
			{
				logIns(LogLevel::Verbose, ins, "jcc branch", nesting);

				auto flagsTaken = flags;
				flagsTaken.setConditional(cc.condition(), !cc.negated());
				auto endTaken = findJumpChainEnd(imageBytes, x86::disasm(imageBytes, targetTaken), flagsTaken, nesting.push(true), true);
				if (!endTaken)
					endTaken = targetTaken;

				flags.setConditional(cc.condition(), cc.negated());
				auto endNT = findJumpChainEnd(imageBytes, x86::disasm(imageBytes, targetNotTaken), flags, nesting.push(false), true);
				if (!endNT)
					endNT = targetNotTaken;

				auto converging = endTaken == endNT;
				logIns(LogLevel::Important, ins, converging ? "*** converging branch!" : "*** diverging branch!", nesting);
				return converging ? endTaken : 0;
			}
			else
			{
				auto taken = flags.isSet(cc.condition()) != cc.negated();
				auto target = taken ? targetTaken : targetNotTaken;
				logIns(LogLevel::Verbose, ins, taken ? "always taken" : "never taken", nesting);
				auto end = findJumpChainEnd(imageBytes, x86::disasm(imageBytes, target), flags, nesting, true);
				return end ? end : target;
			}
		}
		else
		{
			// end of jump chain
			logIns(LogLevel::Verbose, ins, "chain end", nesting);
			break;
		}

		// if we're still here, continue following the chain...
		ins = x86::disasm(imageBytes, next);
	} while (true);
	return afterJump ? ins.rva : 0;
}
*/

// follow the jump chain: skip nops and never-taken jumps, follow unconditional and always-taken conditional jumps
// returns starting addresses of blocks, first being the target of last always-taken jcc, the rest are targets of subsequent jmps
SmallVector<i32, 2> followJumpChain(std::span<const u8> imageBytes, i32 rva, ConditionState cond, NestingTracker nesting)
{
	SmallVector<i32, 2> result;
	result.push_back(rva);
	while (true)
	{
		auto next = disasmNextNonNop(imageBytes, rva, nesting);
		if (isJmpRel(next))
		{
			logIns(LogLevel::Verbose, next, "continue chain maybe", nesting);
			// follow the jump chain...
			rva = relTarget(next);
			result.push_back(rva);
			continue;
		}
		else if (!isJccRel(next))
		{
			// end the jump chain
			// note: the instruction could be flags-only, we consider it to be a jump to a new jump chain - but theoretically it could be a nested one instead
			logIns(LogLevel::Verbose, next, "chain end", nesting);
			break;
		}
		else if (auto cc = next.mnem.conditionCode(); !cond.isKnown(cc.condition()))
		{
			// end the jump chain - the target might be a normal jump or start of a new jump chain
			// note: theoretically we might wanna recurse, if obfuscator can do it...
			logIns(LogLevel::Verbose, next, "chain end (jcc)", nesting);
			break;
		}
		else if (cond.isSet(cc.condition()) != cc.negated())
		{
			logIns(LogLevel::Verbose, next, "jcc always-taken", nesting);
			// follow the jump chain, but reset the output, because we definitely know that the chain continues up to here
			rva = relTarget(next);
			result.clear();
			result.push_back(rva);
			continue;
		}
		else
		{
			logIns(LogLevel::Verbose, next, "jcc never-taken", nesting);
			// just skip this, probably other branch jumps here too...
			// TODO: do we want to restart the chain?..
			rva = next.endRVA();
			continue;
		}
	}
	return result;
}

// given two jump chains, find convergence point; return 0 if they fully diverge
i32 findConvergencePoint(const SmallVector<i32, 2>& l, const SmallVector<i32, 2>& r)
{
	ensure(!l.empty() && !r.empty());
	// assumption - if one of the branches proceeded further after convergence point, other would stop at it
	if (std::ranges::contains(l | std::views::reverse, r.back()))
		return r.back();
	if (std::ranges::contains(r | std::views::reverse, l.back()))
		return l.back();
	return 0;
}

// returns jump chain end RVA if passed instruction is the start of the jump chain, or 0 if not
// we support two distinct types of jump chains:
// - flags-only instruction followed by a series of always-taken jumps
// - jcc + jncc ultimately converging to the same address
// we want to be efficient and not spend time disassembling too many instructions when it's obviously not a jump chain
i32 findJumpChainTarget(std::span<const u8> imageBytes, const x86::Instruction& ins)
{
	auto nesting = NestingTracker{}.push();
	if (isFlagsOnly(ins))
	{
		log(LogLevel::Important, "Starting from {:X} (flags-only)", ins.rva);
		logIns(LogLevel::Verbose, ins, "flags", nesting);
		auto cond = updateConditionFlagsOnly({}, ins.mnem);
		auto next = disasmNextNonNop(imageBytes, ins.endRVA(), nesting);
		if (!isJccRel(next))
		{
			// note: technically we could have a sequence on flags-only instructions, does this ever happen?..
			logIns(LogLevel::Important, next, "uninteresting", nesting);
			ensure(ins.mnem == X86_INS_TEST); // this one can appear a few instructions before jcc
			return 0;
		}
		else if (auto cc = next.mnem.conditionCode(); !cond.isKnown(cc.condition()))
		{
			logIns(LogLevel::Verbose, next, "jcc undefined", nesting);
			ensure(ins.mnem == X86_INS_TEST && isTestConditionNormal(cc.condition())); // test + jcc is very common and reasonable sequence in normal code, other flags-only should not appear in normal code or other conditional checks are not
			// note: theoretically we might have a condition-only followed by converging chain followed by a set of always-taken jcc
			// if we ever find an example, this would resolve converging chain, but then fail to understand that jcc is always-taken - hopefully we'd then trigger some error when disassembling junk in never-taken chain
			return 0;
		}
		else if (cond.isSet(cc.condition()) != cc.negated())
		{
			logIns(LogLevel::Verbose, next, "jcc always-taken", nesting);
			auto targets = followJumpChain(imageBytes, relTarget(next), cond, nesting.push(true));
			logIns(LogLevel::Important, ins, "*** always-taken chain", nesting);
			return targets.back(); // note - technically, we could select any ...
		}
		else
		{
			// never-taken branch - technically it's reasonable for obfuscation to insert one (pointing to junk), in that case we would want to skip it, I've just not seen it happen yet
			logIns(LogLevel::Important, next, "jcc never-taken?", nesting);
			__debugbreak();
			return 0;
		}
	}
	else if (isJccRel(ins))
	{
		log(LogLevel::Important, "Starting from {:X} (jcc)", ins.rva);
		logIns(LogLevel::Verbose, ins, "jcc", nesting);
		// note: all conditions can legitimately appear in the code; SF and OF are somewhat rare, and PF is even more rare (used for float comparison to signify unordered result)
		auto icc = ins.mnem.conditionCode();
		auto next = disasmNextNonNop(imageBytes, ins.endRVA(), nesting);
		if (!isJccRel(next))
		{
			// this is a normal situation, jcc followed by code on not-taken branch
			// note about jmp - there's legitimate code that does jcc->jmp
			// in obfuscation, theoretically the second branch could start with a jmp rather than jncc, can it happen?
			// note that if next is flags-only, it could be jcc followed by a jump chain (or theoretically recursive jumpchain)
			logIns(LogLevel::Verbose, next, "uninteresting", nesting);
			return 0;
		}
		else if (auto jcc = next.mnem.conditionCode(); jcc.condition() != icc.condition() || jcc.negated() == icc.negated())
		{
			// jcc->jcc or jcc1->jcc2, likely first jcc is normal, and second starts jump chain
			// technically this could also happen if one of the braches has a recursive chain, can it happen?
			logIns(LogLevel::Verbose, next, "mismatching jcc sequence", nesting);
			return 0;
		}
		else
		{
			logIns(LogLevel::Verbose, next, "jncc", nesting);
			// note: branches will diverge if a normal jcc is followed by cc-based jump chain
			// note that technically the second jump is always taken, so we can patch it even now - but this would require propagating this information back to function block analysis somehow
			// don't think it matters...
			auto targetsTaken = followJumpChain(imageBytes, relTarget(ins), { icc }, nesting.push(true));
			auto targetsNotTaken = followJumpChain(imageBytes, relTarget(next), { jcc }, nesting.push(false));
			auto target = findConvergencePoint(targetsTaken, targetsNotTaken);
			ensure(!target || target == targetsTaken.back() && target == targetsNotTaken.back()); // TODO: i just want to catch an example of this...
			logIns(LogLevel::Important, ins, target ? "*** converging branches" : "*** diverging branches", nesting);
			return target;
		}
	}
	else
	{
		// doesn't look interesting
		return 0;
	}
}

// disassemble instruction at given offset, then check whether it's start of jump chain
// if it is not, return actual disassembled instruction
// otherwise, return fake jmp instruction with length 1 (real disassembled jumps are always longer)
export x86::Instruction disasmResolveJumpChains(std::span<const u8> imageBytes, i32 rva)
{
	auto ins = x86::disasm(imageBytes, rva);
	ensure(ins.length); // if disasm failed, we most likely fucked up with some jump chain detection
	if (ins.prefix != x86::Prefix::none)
		return ins; // don't fuck with prefixed instructions
	// some notes:
	// - sometimes jump chains start with effective nops, in that case we skip them here and pass first real instruction to the function we call
	// - we do *not* skip actual nops - reason being that they are sometimes used to align jump chains
	//   if we were to use them as jump chain starts, we might replace single-byte nop with a real jump, and then have some other block that jumps to the actual aligned jump chain start jump into the middle of instruction we create
	if (const auto chainTarget = findJumpChainTarget(imageBytes, isEffectiveNop(ins) ? disasmNextNonNop(imageBytes, ins.endRVA(), {}) : ins))
	{
		ins = { rva, X86_INS_JMP, 1, 1, x86::Prefix::none, { x86::Operand{ chainTarget, 4 } } };
	}
	return ins;
}

export void unittestJumpChains()
{
	// all tests end with 0xF4 (hlt)
	static const std::vector<std::vector<u8>> positive = {
		{ 0x24, 0xff, 0x73, 0x01, 0x00, 0x66, 0x87, 0xDB, 0x71, 0x01, 0x00, 0xF4 }, // <clear-cf-of> jae junk nop junk end
		{ 0x78, 0x06, 0x66, 0x87, 0xDB, 0x79, 0x0B, 0x00, 0x78, 0x01, 0x00, 0x66, 0xC1, 0xE0, 0x00, 0xEB, 0x04, 0x00, 0x79, 0x01, 0x00, 0xF4 }, // js nop jns junk, converge
		{ 0x78, 0x05, 0x86, 0xC9, 0x79, 0x04, 0x00, 0x78, 0x01, 0x00, 0x79, 0x06, 0x78, 0x01, 0x00, 0x78, 0x04, 0x00, 0x79, 0x01, 0x00, 0xF4 }, // js twist
		{ 0x78, 0x06, 0x66, 0x87, 0xDB, 0x79, 0x0D, 0x00, 0x78, 0x01, 0x00, 0x66, 0xC1, 0xE0, 0x00, 0x70, 0x06, 0x71, 0x0D, 0x00, 0x79, 0x10, 0x00, 0xC0, 0xEB, 0x00, 0x70, 0x01, 0x00, 0x70, 0x07, 0x00, 0x71, 0x01, 0x00, 0xEB, 0x01, 0x00, 0xF4 }, // nested converging chains
		// TODO: jz/jnz converging to jz
	};

	// TODO: negative tests:
	// - test + jz
	// - jmp to jumpchain?

	for (auto& test : positive)
	{
		auto ins = disasmResolveJumpChains(test, 0);
		ensure(ins.mnem == X86_INS_JMP && ins.length == 1 && ins.ops[0].immediate<u64>() == test.size() - 1);
	}
}

}
