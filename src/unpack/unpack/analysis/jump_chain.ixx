export module unpack.analysis.jump_chain;

export import unpack.x86.disasm;

namespace analysis {

// debug logging
enum class LogLevel { None, Important, Verbose, Nops };
Logger log{ "JumpChain", LogLevel::None };
void logIns(LogLevel level, const x86::Instruction& ins, std::string_view message, const NestingTracker& nesting) { log(level, "{} {:X}: {} = {}", nesting, ins.rva, ins, message); }

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

/*
// find next 'interesting' (non-nop) instruction
x86::Instruction disasmNextNonNop(std::span<const u8> imageBytes, const x86::Instruction& firstIns, bool considerFirst, const NestingTracker& nesting)
{
	auto interesting = [&](const x86::Instruction& ins) {
		if (ins.mnem != X86_INS_NOP && !isEffectiveNop(ins))
			return true;
		logIns(LogLevel::Nops, ins, "nop", nesting);
		return false;
	};

	if (considerFirst && interesting(firstIns))
		return firstIns;
	auto rva = firstIns.endRVA();
	while (true)
	{
		auto next = x86::disasm(imageBytes, rva);
		if (interesting(next))
			return next;
		rva = next.endRVA();
	}
}

i32 followJumpChain(std::span<const u8> imageBytes, const x86::Instruction& jcc, std::span<const x86::Mnem> expected, const NestingTracker& nesting)
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
	auto nesting = NestingTracker().push();
	auto first = disasmNextNonNop(imageBytes, firstIns, true, nesting);
	if (isFlagsOnly(first))
	{
		log(LogLevel::Verbose, first, "flags-only");
		auto second = disasmNextNonNop(imageBytes, first, false);
		auto expected = getGuaranteedConditions(first.mnem).taken;
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
*/

// TODO: this is quite ugly, refactor...
// at least, explain afterJump meaning and return values in different circumstances...
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
			logIns(LogLevel::Verbose, ins, "nop", nesting);
			if (ins.mnem == X86_INS_CLC)
				flags.setFlag(x86::Condition::CF, false);
			else if (ins.mnem == X86_INS_STC)
				flags.setFlag(x86::Condition::CF, true);
			else
				flags.setAll(x86::ConditionState::mask(x86::Condition::OF) | x86::ConditionState::mask(x86::Condition::CF), 0);
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

// returns jump chain end RVA if passed instruction is the start of the jump chain, or 0 if not
export i32 findJumpChainTarget(std::span<const u8> imageBytes, const x86::Instruction& ins)
{
	// jump chains can start with effective nops, flags-only instructions, or conditional jumps
	if (!isEffectiveNop(ins) && !isFlagsOnly(ins) && !isJccRel(ins))
		return 0;
	log(LogLevel::Verbose, "Starting from {:X}", ins.rva);
	auto target = findJumpChainEnd(imageBytes, ins, {}, NestingTracker().push());
	//ensure(target || ins.mnem == X86_INS_TEST || isJccRel(ins)); // jcc and test are encountered normally, i've also seen effective-nops in constant obfuscation code, really we should only complain if we've seen some always/never-taken jccs...
	return target;
}

// disassemble instruction at given offset, then check whether it's start of jump chain
// if it is not, return actual disassembled instruction
// otherwise, return fake jmp instruction with length 1 (real disassembled jumps are always longer)
export x86::Instruction disasmResolveJumpChains(std::span<const u8> imageBytes, i32 rva)
{
	auto ins = x86::disasm(imageBytes, rva);
	ensure(ins.length); // if disasm failed, we most likely fucked up with some jump chain detection
	if (const auto chainTarget = findJumpChainTarget(imageBytes, ins))
	{
		ins = { rva, X86_INS_JMP, 1, 1, { x86::Operand{ chainTarget, 4 } } };
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
