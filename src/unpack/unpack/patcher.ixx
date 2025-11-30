export module unpack.patcher;

export import unpack.analysis.function_block;
export import unpack.pe_binary;

// debug logging
enum class LogLevel { None, Important, Common, Verbose };
Logger logger{ "Patch", LogLevel::Important };

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

	bool applyIDAOnlyPatches() const { return mApplyIDAOnlyPatches; }
	bool applyRuntimeOnlyPatches() const { return mApplyRuntimeOnlyPatches; }

	// apply universal function patches:
	// - replace parsed jump chains with real jumps
	// - fill space between blocks (and, if end is known, between last block end and function end) with nops/int3
	// - if doing ida-only patches, remove rbp overalign for avx (ida can't cope with it)
	void patchFunction(analysis::Function& func, rva_t end)
	{
		// patch jumps and fill space between blocks
		u8 nop = mApplyIDAOnlyPatches ? 0x90 : 0xCC; // ida prefers nop fill, for runtime int3 allows us to find where I fucked up
		int numPatchedJumps = 0;
		for (auto block = func.blocks.begin(); block != func.blocks.end(); ++block)
		{
			auto iNext = block + 1;
			auto nextStart = iNext != func.blocks.end() ? iNext->begin : end;

			auto lastIns = block->insCount() ? &func.blockInstructions(*block).back() : nullptr;
			if (lastIns && lastIns->mnem == X86_INS_JMP && lastIns->length == 1)
			{
				// found jump to patch - real jumps can't have length 1
				auto target = lastIns->ops[0].immediate<i32>();
				logger(LogLevel::Common, "jump chain {:X}->{:X}, next block at {:X}", lastIns->rva, target, nextStart);
				lastIns->length = writeJmp(lastIns->rva, target);
				func.blocks.extend(block->end, lastIns->endRVA(), iNext);
				fill(block->end, nextStart, nop);
				++numPatchedJumps;
			}
			else if (nextStart > block->end)
			{
				// TODO: do we really want to nop-fill this?.. might be analysis errors rather than genuine trash instructions...
				for (auto rva = block->end; rva < nextStart; )
				{
					auto ins = x86::disasm(mBinary.bytes(), rva);
					ensure(ins.mnem == X86_INS_NOP || ins.mnem == X86_INS_INT3);
					rva += ins.length;
					ensure(rva <= nextStart);
				}
			}
		}

		if (numPatchedJumps)
			logger(LogLevel::Important, "Patched {} jumps in function {:X}", numPatchedJumps, func.blocks.front().begin);

		// if a function uses AVX instructions, compiler aligns rbp to 0x20, so that it can then use aligned versions
		// unfortunately hexrays really struggles with it
		// so for analysis, patch `and rbp, ~0x1F` with effective nop
		// assume if it's there, it's in first block
		auto instructions = func.blockInstructions(0);
		auto rbpOveralign = std::ranges::find_if(instructions, [](const x86::Instruction& ins) {
			return ins.mnem == X86_INS_AND && ins.ops[0] == x86::Reg::rbp && ins.ops[1] == ~0x1Fll; });
		if (rbpOveralign != instructions.end())
		{
			logger(LogLevel::Important, "rbp overalign at {:X}: {} ({})", rbpOveralign->rva, *rbpOveralign, mApplyIDAOnlyPatches ? "applying" : "skipping"); // TODO: lower log level
			auto& immByte = mBinary.bytes()[rbpOveralign->rva + rbpOveralign->length - 1];
			ensure(immByte == 0xE0);
			if (mApplyIDAOnlyPatches)
				immByte = 0xFF;
		}
	}

	// some specific functions in bootstrap code use hlt instruction to communicate with VEH handler
	// unfortunately, IDA considers hlt to be ret-like instruction, so it doesn't create flow xref to next instruction
	// even if fixed manually, hex-rays then considers hlt intrinsic to be no-return
	// a replacement can be any single-byte instruction that isn't used much in normal code, eg. icebp (0xF1)
	void patchHlts(const analysis::Function& func, u8 replacement = 0xF1)
	{
		for (auto& ins : func.instructions | std::views::filter([](const auto& ins) { return ins.mnem == X86_INS_HLT; }))
		{
			logger(LogLevel::Important, "hlt at {:X} ({})", ins.rva, mApplyIDAOnlyPatches ? "applying" : "skipping");
			if (mApplyIDAOnlyPatches)
				mBinary.bytes()[ins.rva] = replacement;
		}
	}

	// patch conditional jump to unconditional, on runtime only
	void patchJumpToUnconditional(rva_t rva, std::string_view reason)
	{
		auto* address = &mBinary.bytes()[rva];
		if ((address[0] & 0xF0) == 0x70)
		{
			logger(LogLevel::Important, "jcc->jmp (short) at {:X} for {} ({})", rva, reason, mApplyRuntimeOnlyPatches ? "applying" : "skipping");
			if (mApplyRuntimeOnlyPatches)
				address[0] = 0xEB;
		}
		else if (address[0] == 0x0F && (address[1] & 0xF0) == 0x80)
		{
			logger(LogLevel::Important, "jcc->jmp (near) at {:X} for {} ({})", rva, reason, mApplyRuntimeOnlyPatches ? "applying" : "skipping");
			if (mApplyRuntimeOnlyPatches)
			{
				address[0] = 0x90;
				address[1] = 0xE9;
			}
		}
		else
		{
			throw std::runtime_error(std::format("Failed to patch jump at {:X}: {:02X}", rva, address[0]));
		}
	}

	// patch xor to mov, on runtime only
	void patchXorToMov(rva_t rva, std::string_view reason)
	{
		auto* address = &mBinary.bytes()[rva];
		if (address[0] == 0x30)
		{
			logger(LogLevel::Important, "xor->mov r/m8, r8 at {:X} for {} ({})", rva, reason, mApplyRuntimeOnlyPatches ? "applying" : "skipping");
			if (mApplyRuntimeOnlyPatches)
				address[0] = 0x88;
		}
	}

	// log and apply generic patch
	void patchGeneric(std::span<const u8> code, rva_t rva, rva_t end, std::string_view reason, bool runtimeOnly = true)
	{
		auto apply = !runtimeOnly || mApplyRuntimeOnlyPatches;
		logger(LogLevel::Important, "patching {} at {:X} ({})", reason, rva, apply ? "applying" : "skipping");
		if (apply)
			patch(code, rva, end);
	}

	// decrypt modified-RC4-encrypted data (can also encrypt, since it's symmetric)
	// see https://en.wikipedia.org/wiki/RC4 - but note that some customized version of PRGA is used (different key generation scheme)
	void decryptModifiedRC4(std::span<const u8> key, std::span<u8> data)
	{
		// KSA: build permutation array s
		std::array<u8, 256> s;
		std::ranges::iota(s, 0);
		u8 j = 0;
		for (int i = 0; i < s.size(); ++i)
		{
			j += s[i] + key[i % key.size()];
			std::swap(s[i], s[j]);
		}

		// modified PRGA: generate pseudo-random stream of xor keys
		u8 i = 0;
		j = 0;
		for (auto& b : data)
		{
			j += s[++i];
			b ^= s[i]; // note: this is a customization! normally it would be s[s[i] + s[j]]
			std::swap(s[i], s[j]);
		}
	}
	template<typename T> void decryptModifiedRC4(std::span<const u8> key, T& data) { decryptModifiedRC4(key, { reinterpret_cast<u8*>(&data), sizeof data }); }

private:
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


private:
	PEBinary& mBinary;
	bool mApplyIDAOnlyPatches;
	bool mApplyRuntimeOnlyPatches;
};
