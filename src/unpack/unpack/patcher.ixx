export module unpack.patcher;

export import unpack.analysis.function_block;
export import unpack.pe_binary;

// debug logging
enum class LogLevel { None, Important, Verbose };
Logger logger{ "Patch", LogLevel::Verbose };

// utility for patching the binary
// some patches are 'ida-only' - they break some functionality of the binary, but make it easier to analyze in ida
// some patches are 'runtime-only' - they remove some pieces of runtime code (eg various random fills), but you might want to see them in ida
export class Patcher
{
public:
	Patcher(PEBinary& binary, bool applyIDAOnlyPatches, bool applyRuntimeOnlyPatches)
		: mBinary(binary)
		, mApplyIDAOnlyPatches(applyIDAOnlyPatches)
		, mApplyRuntimeOnlyPatches(applyRuntimeOnlyPatches)
	{
	}

	// primitive write operation
	void write(std::span<const u8> patch, rva_t rva) { std::memcpy(mBinary.bytes().data() + rva, patch.data(), patch.size()); }

	// primitive fill operation (typical fill values are zero, nops (0x90) and int3 (0xCC)
	void fill(rva_t rva, rva_t end, u8 fill) { ensure(end >= rva); std::memset(mBinary.bytes().data() + rva, fill, end - rva); }

	// apply generic patch, and fill the rest with zeros/nops
	void patch(std::span<const u8> patch, rva_t rva, rva_t end, u8 fillByte = 0x90)
	{
		logger(LogLevel::Verbose, "> {:X}-{:X}: {}", rva, end, patch);
		write(patch, rva);
		fill(rva + patch.size(), end, fillByte);
	}

	// write unconditional relative jump at specified rva
	// returns written instruction size (depending on distance to target, can be 2 or 5)
	int writeJmp(rva_t rva, rva_t target)
	{
		// short jump is 2 bytes => -128 <= (target - rva - 2) <= 127
		auto relShort = target - rva - 2;
		auto isShort = relShort >= std::numeric_limits<i8>::min() && relShort <= std::numeric_limits<i8>::max();
		logger(LogLevel::Verbose, "jmp {:X}->{:X} - {}", rva, target, isShort ? "short" : "near");
		mBinary.bytes()[rva] = isShort ? 0xEB : 0xE9;
		if (isShort)
			*mBinary.structAtRVA<i8>(rva + 1) = static_cast<i8>(relShort);
		else
			*mBinary.structAtRVA<i32>(rva + 1) = target - rva - 5;
		return isShort ? 2 : 5;
	}

	// apply universal function patches:
	// - replace parsed jump chains with real jumps
	// - fill space between blocks (and, if end is known, between last block end and function end) with nops/int3
	// - if doing ida-only patches, remove rbp overalign for avx (ida can't cope with it)
	void patchFunction(analysis::Function& func, rva_t end = 0)
	{
		// patch jumps
		int numPatchedJumps = 0;
		for (auto block = func.blocks.begin(); block != func.blocks.end(); ++block)
		{
			if (!block->insCount())
				continue;
			auto& lastIns = func.blockInstructions(*block).back();
			if (lastIns.mnem != X86_INS_JMP || lastIns.length != 1)
				continue;
			// found a jump chain - real jumps can't have length 1
			lastIns.length = writeJmp(lastIns.rva, lastIns.ops[0].immediate<i32>());
			func.blocks.extend(block->end, lastIns.rva + lastIns.length, block + 1);
			++numPatchedJumps;
		}

		// fill space between blocks
		int numNopFillsMid = 0, numNopFillsEnd = 0;
		u8 nop = mApplyIDAOnlyPatches ? 0x90 : 0xCC; // ida prefers nop fill, for runtime int3 allows us to find where I fucked up
		for (auto&& [from, to] : func.blocks | std::views::pairwise)
		{
			if (to.begin != from.end)
			{
				logger(LogLevel::Verbose, "nop fill between {:X} and {:X}", from.end, to.begin);
				fill(from.end, to.begin, nop);
				++numNopFillsMid;
			}
		}
		if (end)
		{
			auto& last = func.blocks.back();
			if (end != last.end)
			{
				logger(LogLevel::Verbose, "nop fill between {:X} and {:X}", last.end, end);
				fill(last.end, end, nop);
				++numNopFillsEnd;
			}
		}

		if (numPatchedJumps + numNopFillsMid + numNopFillsEnd)
			logger(LogLevel::Important, "Patched {} jumps, {}+{} nops", numPatchedJumps, numNopFillsMid, numNopFillsEnd);

		if (mApplyIDAOnlyPatches)
		{
			// if a function uses AVX instructions, compiler aligns rbp to 0x20, so that it can then use aligned versions
			// unfortunately hexrays really struggles with it
			// so for analysis, patch `and rbp, ~0x1F` with effective nop
			// assume if it's there, it's in first block
			auto instructions = func.blockInstructions(0);
			auto rbpOveralign = std::ranges::find_if(instructions, [](const x86::Instruction& ins) { return ins.mnem == X86_INS_AND && ins.ops[0] == x86::Reg::rbp && ins.ops[1] == ~0x1F; });
			if (rbpOveralign != instructions.end())
			{
				logger(LogLevel::Important, "rbp overalign: {:X} {}", rbpOveralign->rva, *rbpOveralign);
				auto& immByte = mBinary.bytes()[rbpOveralign->rva + rbpOveralign->length - 1];
				ensure(immByte == 0xE0);
				immByte = 0xFF;
			}
		}
	}

	// some specific functions in bootstrap code use hlt instruction to communicate with VEH handler
	// unfortunately, IDA considers hlt to be ret-like instruction, so it doesn't create flow xref to next instruction
	// even if fixed manually, hex-rays then considers hlt intrinsic to be no-return
	// a replacement can be any single-byte instruction that isn't used much in normal code, eg. icebp (0xF1)
	void patchHlts(const analysis::Function& func, u8 replacement = 0xF1)
	{
		if (mApplyIDAOnlyPatches)
		{
			for (auto& ins : func.instructions | std::views::filter([](const auto& ins) { return ins.mnem == X86_INS_HLT; }))
			{
				logger(LogLevel::Important, "hlt at {:X}", ins.rva);
				mBinary.bytes()[ins.rva] = replacement;
			}
		}
	}

private:
	PEBinary& mBinary;
	bool mApplyIDAOnlyPatches;
	bool mApplyRuntimeOnlyPatches;
};
