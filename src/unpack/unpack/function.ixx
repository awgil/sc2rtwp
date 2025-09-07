module;

#include <common/bitfield_ops.h>
#include <common/win_headers.h>
#include <capstone/capstone.h>

export module unpack.function;

import std;
import common;
import unpack.pe_binary;

// Conditionals (first instruction is 'jump when set', second is 'jump if not set')
enum class Conditional : u8
{
	None = 0,
	OF = 1 << 0, // jo - jno
	SF = 1 << 1, // js - jns
	ZF = 1 << 2, // je/jz - jne/jnz
	CF = 1 << 3, // jc/jb/jnae - jnc/jnb/jae
	PF = 1 << 4, // jp/jpe - jnp/jpo
	BE = 1 << 5, // jbe/jna - jnbe/ja (CF | ZF)
	SO = 1 << 6, // jl/jnge - jnl/jge (SF ^ OF)
	LE = 1 << 7, // jle/jng - jnle/jg (ZF | (SF ^ OF))
};
ADD_BITFIELD_OPS(Conditional);

// a set of known values for conditional flags
class FlagState
{
public:
	void setAll(Conditional known, Conditional mask)
	{
		ensure((mask & ~known) == Conditional::None);
		mKnown = known;
		mValue = mask;
	}

	bool isKnown(Conditional flag) const { return (mKnown & flag) != Conditional::None; }
	bool isSet(Conditional flag) const { return (mValue & flag) != Conditional::None; }

	void forget(Conditional flag)
	{
		mKnown &= ~flag;
		mValue &= ~flag;
	}

	void setConditional(Conditional flag, bool value)
	{
		// TODO: current code doesn't account for the fact that eg jbe taken followed by jc not taken implies jz will be taken...
		setRaw(flag, value);
	}

	void setFlag(Conditional flag, bool value)
	{
		setRaw(flag, value);
		if (flag == Conditional::OF || flag == Conditional::SF)
			updateXorPseudoflag(Conditional::SO, Conditional::OF, Conditional::SF);
		if (flag == Conditional::ZF || flag == Conditional::CF)
			updateOrPseudoflag(Conditional::BE, Conditional::ZF, Conditional::CF);
		if (flag == Conditional::OF || flag == Conditional::SF || flag == Conditional::ZF)
			updateXorPseudoflag(Conditional::LE, Conditional::ZF, Conditional::SO);
	}

private:
	void setRaw(Conditional flag, bool value)
	{
		mKnown |= flag;
		if (value)
			mValue |= flag;
		else
			mValue &= ~flag;
	}

	void updateXorPseudoflag(Conditional flag, Conditional f1, Conditional f2)
	{
		if (isKnown(f1) && isKnown(f2))
			setRaw(flag, isSet(f1) != isSet(f2));
		else
			forget(flag);
	}

	void updateOrPseudoflag(Conditional flag, Conditional f1, Conditional f2)
	{
		if (isSet(f1) || isSet(f2)) // set implies known
			setRaw(flag, true);
		else if (isKnown(f1) && isKnown(f2))
			setRaw(flag, false);
		else
			forget(flag);
	}

private:
	Conditional mKnown = Conditional::None;
	Conditional mValue = Conditional::None; // invariant: mValue & ~mKnown == 0 (ie all unknown bits are zero)
};

export enum EdgeFlags : u8
{
	None,
	Unconditional = 1 << 0, // the only edge in a block
	PatchedChain = 1 << 1, // this is a jump that was represented by a chain in original code
	Flow = 1 << 2, // immediately following instruction
	Loop = 1 << 3, // jump to next iteration of a loop
	Indirect = 1 << 4, // part of switch statement
};
ADD_BITFIELD_OPS(EdgeFlags);

export class FunctionInfo
{
public:
	enum class InstructionType
	{
		Normal,
		ActualNop, // some form of real nop instruction
		EffectiveNop, // special form of nop used as filler in jump chains: "s[ha][lr] x,0", "xchg/mov reg,reg"
		FlagsOnly, // instructions that only modify flags and are used in jump chains: "[x]or x,0", "and x,~0", "test x,y", "clc/stc"
		Ret, // ret
		JumpUnconditional, // jmp
		JumpConditional, // jcc
		CallDirect, // call addr
		Halt, // hlt - this is used by bootstrap code to kick off VEH operation
	};

	// edge between two blocks
	struct Edge
	{
		rva_t rva;
		EdgeFlags flags;
	};

	struct Block : RangeMapEntry<rva_t>
	{
		std::vector<rva_t> instructions;
		std::vector<Edge> successors; // can be empty (if block ends with return / tail recursion jump), contain 1 entry (unconditional jump), 2 entries (conditional jump, first entry is implicit flow) or multiple entries (switch)
	};

	enum class ReferenceType
	{
		Unknown,
		Address, // lea
		Read, // operand 1+
		Write, // operand 0 (can be read-write)
		Call, // normal call or tail-recursion jmp
	};

	// a RIP-relative reference to some external executable item (function, piece of data, etc)
	struct Reference
	{
		rva_t insnRVA;
		rva_t refRVA;
		ReferenceType type;
	};

	FunctionInfo(PEBinary& src, rva_t funcStartRVA, std::string_view name)
		: mBinary(src)
		, mName(name)
		, mSEHEntry(src.findSEHEntry(funcStartRVA))
		, mStartRVA(funcStartRVA)
		, mEndRVA(mSEHEntry ? mSEHEntry->end : src.bytes().size())
	{
		if (name.length() > 0)
			std::println("Processing function {} at {}", name, src.formatRVA(funcStartRVA));

		if (mSEHEntry && mSEHEntry->begin != funcStartRVA)
			throw std::exception("RVA is mid function");

		std::vector<rva_t> blockStartRVAs{ funcStartRVA };
		auto queueJumpTargetRVA = [&](Block& block, rva_t rva, EdgeFlags flags, rva_t predecessorRVA) {
			//std::println("> scheduling [{:X}] {:X} -> {:X}", block.startRVA, predecessorRVA, rva);
			blockStartRVAs.push_back(rva);
			block.successors.push_back({ rva, flags });
		};
		auto queueJumpTarget = [&](Block& block, cs_insn* insn) {
			if (insn->detail->x86.operands[0].type == X86_OP_IMM)
			{
				// TODO: process tail recursion jumps...
				auto flags = insn->id == X86_INS_JMP ? EdgeFlags::Unconditional : EdgeFlags::None;
				queueJumpTargetRVA(block, mBinary.vaToRVA(insn->detail->x86.operands[0].imm), flags, mBinary.vaToRVA(insn->address));
			}
			else
			{
				// TODO: process switches...
				__debugbreak();
			}
		};

		std::vector<rva_t> hltRVAs, jumpPatchRVAs;
		while (!blockStartRVAs.empty())
		{
			auto rva = blockStartRVAs.back();
			blockStartRVAs.pop_back();

			auto nextBlock = mBlocks.findNext(rva);
			auto existing = mBlocks.getPrevIfContains(nextBlock, rva);
			if (existing == mBlocks.end())
			{
				// disassemble new block...
				auto maxBlockEnd = nextBlock != mBlocks.end() ? nextBlock->begin : mEndRVA;
				Block newBlock{ rva, rva };
				while (true)
				{
					auto isn = ensure(src.disasm(rva));

					for (int iOp = 0; iOp < isn->detail->x86.op_count; ++iOp)
					{
						auto& op = isn->detail->x86.operands[iOp];
						if (op.type == X86_OP_MEM && op.mem.base == X86_REG_RIP)
						{
							auto type = iOp == 0 ? ReferenceType::Write : isn->id == X86_INS_LEA ? ReferenceType::Address : ReferenceType::Read;
							mRefs.push_back({ rva, static_cast<rva_t>(rva + isn->size + op.mem.disp), type });
						}
					}

					newBlock.instructions.push_back(rva);
					newBlock.end = rva + isn->size;
					auto cat = categorizeInstruction(isn);
					if (cat == InstructionType::Ret)
					{
						break;
					}
					if (cat == InstructionType::JumpUnconditional)
					{
						queueJumpTarget(newBlock, isn);
						break;
					}
					if (cat == InstructionType::EffectiveNop || cat == InstructionType::FlagsOnly || cat == InstructionType::JumpConditional)
					{
						auto chainEnd = findJumpChainEnd(rva, isn, {});
						if (chainEnd != 0)
						{
							queueJumpTargetRVA(newBlock, chainEnd, EdgeFlags::Unconditional | EdgeFlags::PatchedChain, rva);
							jumpPatchRVAs.push_back(rva);
							newBlock.end = rva + 1; // will be patched; keeping it as 1 ensures that next byte can be reused for some other jump chain
							break;
						}
					}
					if (cat == InstructionType::JumpConditional)
					{
						// re-decode instruction, since it was overwritten while exploring jump chains
						queueJumpTargetRVA(newBlock, newBlock.end, EdgeFlags::Flow, rva);
						queueJumpTarget(newBlock, src.disasm(rva));
						break;
					}

					if (cat == InstructionType::CallDirect)
					{
						mRefs.push_back({ rva, mBinary.vaToRVA(isn->detail->x86.operands[0].imm), ReferenceType::Call });
					}
					if (cat == InstructionType::Halt)
					{
						hltRVAs.push_back(rva);
					}

					if (nextBlock != mBlocks.end() && newBlock.end == nextBlock->begin)
					{
						// we've reached a point where someone else jumped to, end the block now
						newBlock.successors.push_back({ newBlock.end, EdgeFlags::Flow });
						break;
					}

					rva = newBlock.end; // decode next instruction
				}
				// insert new block
				if (newBlock.end > maxBlockEnd)
					throw std::exception("Overlap between blocks");
				mBlocks.insert(std::move(newBlock), nextBlock);
			}
			else if (existing->begin != rva)
			{
				// split existing block
				auto isn = std::ranges::find(existing->instructions, rva);
				if (isn == existing->instructions.end())
					throw std::exception("Found jump mid instruction...");

				Block pred{ existing->begin, rva };
				pred.instructions.assign(existing->instructions.begin(), isn);
				mBlocks.edit(existing).instructions.erase(existing->instructions.begin(), isn);
				pred.successors.push_back({ rva, EdgeFlags::Flow });
				mBlocks.shrink(rva, existing->end, existing);
				mBlocks.insert(std::move(pred), nextBlock - 1);
			}
			// else: this block was already processed, nothing to do here...
		}

		if (!mSEHEntry)
			mEndRVA = mBlocks.back().end;

		// sort references
		std::ranges::sort(mRefs, std::less(), [](const Reference& ref) { return ref.insnRVA; });

		applyPatches(hltRVAs, jumpPatchRVAs);
	}

	const Block* findBlock(rva_t rva) const { return mBlocks.find(rva); }
	const auto& refs() const { return mRefs; }

	auto calls() const { return mRefs | std::ranges::views::filter([](const Reference& ref) { return ref.type == ReferenceType::Call; }); }
	auto refsToSection(const PEBinary::Section& section) const { return mRefs | std::ranges::views::filter([&section](const Reference& ref) { return section.contains(ref.refRVA); }); }

	void gatherCodeRefs(std::vector<rva_t>& refs, const PEBinary::Section& codeSection) const
	{
		refs.append_range(refsToSection(codeSection) | std::ranges::views::transform([&](const Reference& ref) { return ref.refRVA; }));
	}

private:
	// returns jump chain end RVA if passed instruction is the start of the jump chain, or 0 if not
	rva_t findJumpChainEnd(rva_t rva, cs_insn* insn, FlagState flags, bool afterJump = false)
	{
		do {
			auto next = rva + insn->size; // by default, continue with the flow
			auto cat = categorizeInstruction(insn);
			if (cat == InstructionType::ActualNop || cat == InstructionType::EffectiveNop)
			{
				; // just continue
			}
			else if (cat == InstructionType::FlagsOnly)
			{
				if (insn->id == X86_INS_CLC)
					flags.setFlag(Conditional::CF, false);
				else if (insn->id == X86_INS_STC)
					flags.setFlag(Conditional::CF, true);
				else
					flags.setAll(Conditional::OF | Conditional::CF, Conditional::None);
			}
			else if (cat == InstructionType::JumpUnconditional)
			{
				if (insn->detail->x86.operands[0].type != X86_OP_IMM)
					break; // indirect jump
				// note: consider a following situation: jump chain -> test r1,r1 -> jz (diverging)
				next = mBinary.vaToRVA(insn->detail->x86.operands[0].imm);
				auto target = findJumpChainEnd(next, mBinary.disasm(next), flags, true);
				return target ? target : next;
			}
			else if (cat == InstructionType::JumpConditional)
			{
				switch (insn->id)
				{
				case X86_INS_JO:
					return findJumpChainEndCond(Conditional::OF, true, flags, rva, insn);
				case X86_INS_JNO:
					return findJumpChainEndCond(Conditional::OF, false, flags, rva, insn);
				case X86_INS_JS:
					return findJumpChainEndCond(Conditional::SF, true, flags, rva, insn);
				case X86_INS_JNS:
					return findJumpChainEndCond(Conditional::SF, false, flags, rva, insn);
				case X86_INS_JE:
					return findJumpChainEndCond(Conditional::ZF, true, flags, rva, insn);
				case X86_INS_JNE:
					return findJumpChainEndCond(Conditional::ZF, false, flags, rva, insn);
				case X86_INS_JB:
					return findJumpChainEndCond(Conditional::CF, true, flags, rva, insn);
				case X86_INS_JAE:
					return findJumpChainEndCond(Conditional::CF, false, flags, rva, insn);
				case X86_INS_JP:
					return findJumpChainEndCond(Conditional::PF, true, flags, rva, insn);
				case X86_INS_JNP:
					return findJumpChainEndCond(Conditional::PF, false, flags, rva, insn);
				case X86_INS_JBE:
					return findJumpChainEndCond(Conditional::BE, true, flags, rva, insn);
				case X86_INS_JA:
					return findJumpChainEndCond(Conditional::BE, false, flags, rva, insn);
				case X86_INS_JL:
					return findJumpChainEndCond(Conditional::SO, true, flags, rva, insn);
				case X86_INS_JGE:
					return findJumpChainEndCond(Conditional::SO, false, flags, rva, insn);
				case X86_INS_JLE:
					return findJumpChainEndCond(Conditional::LE, true, flags, rva, insn);
				case X86_INS_JG:
					return findJumpChainEndCond(Conditional::LE, false, flags, rva, insn);
				default:
					throw std::exception("Unexpected Jcc");
				}
			}
			else
			{
				// end of jump chain
				break;
			}

			// if we're still here, continue following the chain...
			rva = next;
			insn = mBinary.disasm(rva);
		} while (true);
		return afterJump ? rva : 0;
	}

	rva_t findJumpChainEndCond(Conditional cond, bool value, FlagState flags, rva_t rva, cs_insn* insn)
	{
		if (insn->detail->x86.operands[0].type != X86_OP_IMM)
			return 0; // only direct jumps are supported
		auto targetTaken = mBinary.vaToRVA(insn->detail->x86.operands[0].imm);
		auto targetNotTaken = rva + insn->size;
		if (!flags.isKnown(cond))
		{
			auto flagsTaken = flags;
			flagsTaken.setConditional(cond, value);
			auto endTaken = findJumpChainEnd(targetTaken, mBinary.disasm(targetTaken), flagsTaken, true);
			if (!endTaken)
				endTaken = targetTaken;

			flags.setConditional(cond, !value);
			auto endNT = findJumpChainEnd(targetNotTaken, mBinary.disasm(targetNotTaken), flags, true);
			if (!endNT)
				endNT = targetNotTaken;

			auto converging = endTaken == endNT;
			return converging ? endTaken : 0;
		}
		else
		{
			auto taken = flags.isSet(cond) == value;
			auto target = taken ? targetTaken : targetNotTaken;
			auto end = findJumpChainEnd(target, mBinary.disasm(target), flags, true);
			return end ? end : target;
		}
	}

	InstructionType categorizeInstruction(cs_insn* insn)
	{
		switch (insn->id)
		{
		case X86_INS_NOP:
			return InstructionType::ActualNop;
		case X86_INS_SAL:
		case X86_INS_SAR:
		case X86_INS_SHL:
		case X86_INS_SHR:
			ensure(insn->detail->x86.op_count == 2);
			return insn->detail->x86.operands[1].type == X86_OP_IMM && insn->detail->x86.operands[1].imm == 0 ? InstructionType::EffectiveNop : InstructionType::Normal;
		case X86_INS_MOV:
		case X86_INS_XCHG:
			ensure(insn->detail->x86.op_count == 2);
			return insn->detail->x86.operands[0].type == X86_OP_REG && insn->detail->x86.operands[1].type == X86_OP_REG && insn->detail->x86.operands[0].reg == insn->detail->x86.operands[1].reg ? InstructionType::EffectiveNop : InstructionType::Normal;
		case X86_INS_OR:
		case X86_INS_XOR:
			ensure(insn->detail->x86.op_count == 2);
			return insn->detail->x86.operands[1].type == X86_OP_IMM && insn->detail->x86.operands[1].imm == 0 ? InstructionType::FlagsOnly : InstructionType::Normal;
		case X86_INS_AND:
		{
			ensure(insn->detail->x86.op_count == 2);
			auto size = insn->detail->x86.operands[1].size;
			i64 mask = size == 1 ? 0xFF : size == 2 ? 0xFFFF : size == 4 ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF;
			return insn->detail->x86.operands[1].type == X86_OP_IMM && insn->detail->x86.operands[1].imm == mask ? InstructionType::FlagsOnly : InstructionType::Normal;
		}
		case X86_INS_TEST:
		case X86_INS_CLC:
		case X86_INS_STC:
			return InstructionType::FlagsOnly;
		case X86_INS_RET:
			return InstructionType::Ret;
		case X86_INS_CALL:
			ensure(insn->detail->x86.op_count == 1);
			ensure(insn->detail->x86.operands[0].type != X86_OP_MEM);
			return insn->detail->x86.operands[0].type == X86_OP_IMM ? InstructionType::CallDirect : InstructionType::Normal;
		case X86_INS_JMP:
			ensure(insn->detail->x86.op_count == 1);
			ensure(insn->detail->x86.operands[0].type == X86_OP_IMM);
			return InstructionType::JumpUnconditional;
		case X86_INS_JO:
		case X86_INS_JNO:
		case X86_INS_JS:
		case X86_INS_JNS:
		case X86_INS_JE:
		case X86_INS_JNE:
		case X86_INS_JB:
		case X86_INS_JAE:
		case X86_INS_JP:
		case X86_INS_JNP:
		case X86_INS_JBE:
		case X86_INS_JA:
		case X86_INS_JL:
		case X86_INS_JGE:
		case X86_INS_JLE:
		case X86_INS_JG:
			ensure(insn->detail->x86.op_count == 1);
			ensure(insn->detail->x86.operands[0].type == X86_OP_IMM);
			return InstructionType::JumpConditional;
		case X86_INS_INT:
			ensure(insn->detail->x86.op_count == 1 && insn->detail->x86.operands[0].type == X86_OP_IMM);
			return insn->detail->x86.operands[0].imm == 0x29 ? InstructionType::Ret : InstructionType::Normal;
		case X86_INS_HLT:
			return InstructionType::Halt;
		case X86_INS_INT1:
			throw std::exception("Unexpected icebp instruction"); // we use this as an ida-friendly replacement for hlt
		default:
			return InstructionType::Normal;
		}
	}

	void applyPatches(const std::vector<rva_t>& hltRVAs, const std::vector<rva_t>& jumpPatchRVAs)
	{
		// help ida - replace 'hlt' with 'icebp'
		for (auto rva : hltRVAs)
		{
			mBinary.bytes()[rva] = 0xF1;
		}

		// patch jumps
		for (auto rva : jumpPatchRVAs)
		{
			auto next = mBlocks.findNext(rva);
			auto block = mBlocks.getPrevIfContains(next, rva);
			ensure(block != mBlocks.end() && block->end == rva + 1 && !block->instructions.empty() && block->instructions.back() == rva && block->successors.size() == 1 && block->successors.front().flags == (EdgeFlags::Unconditional | EdgeFlags::PatchedChain));
			auto target = block->successors.front().rva;
			auto longJmp = target > rva + 129 || target < rva - 126;
			auto actualEnd = block->end + (longJmp ? sizeof(int) : sizeof(char));
			i32 jumpDelta = target - actualEnd;
			if (longJmp)
			{
				mBinary.bytes()[rva] = 0xE9;
				*(i32*)(mBinary.bytes().data() + block->end) = jumpDelta;
			}
			else
			{
				mBinary.bytes()[rva] = 0xEB;
				*(i8*)(mBinary.bytes().data() + block->end) = jumpDelta;
			}
			mBlocks.extend(block->end, actualEnd, next);
		}

		// patch space between blocks with nops
		auto junkStart = mStartRVA;
		auto junkify = [&](rva_t goodRVA) {
			ensure(goodRVA >= junkStart);
			memset(mBinary.bytes().data() + junkStart, 0x90, goodRVA - junkStart);
		};
		for (auto& block : mBlocks)
		{
			junkify(block.begin);
			junkStart = block.end;
		}
		junkify(mEndRVA);
	}

private:
	PEBinary& mBinary;
	std::string mName;
	const SEHInfo::Entry* mSEHEntry = nullptr;
	rva_t mStartRVA = 0;
	rva_t mEndRVA = 0;
	RangeMap<Block> mBlocks;
	std::vector<Reference> mRefs; // rip-relative references, sorted by instruction RVAs
};

export class FunctionTable
{
public:
	FunctionTable(PEBinary& binary) : mBinary(binary) {}

	FunctionInfo* get(rva_t rva)
	{
		auto it = mFunctions.find(rva);
		return it != mFunctions.end() ? &it->second : nullptr;
	}

	FunctionInfo& process(rva_t rva, std::string_view name)
	{
		return mFunctions.try_emplace(rva, mBinary, rva, name).first->second;
	}

	//FunctionInfo& processRecursively(rva_t rva, std::string_view name)
	//{
	//	auto& root = process(rva, name);
	//	std::vector<rva_t> pending;
	//	root.gatherCodeRefs(pending, mCodeSection);
	//	while (!pending.empty())
	//	{
	//		auto next = pending.back();
	//		pending.pop_back();
	//		if (!mFunctions.contains(next))
	//			process(next, "").gatherCodeRefs(pending, mCodeSection);
	//	}
	//	return root;
	//}

private:
	PEBinary& mBinary;
	std::map<rva_t, FunctionInfo> mFunctions;
};
