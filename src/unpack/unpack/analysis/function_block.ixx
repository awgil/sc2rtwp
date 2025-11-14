export module unpack.analysis.function_block;

export import unpack.range_map;
export import unpack.analysis.jump_chain;

namespace analysis {

export struct FunctionBlock : RangeMapEntry<i32>
{
	i32 insBegin; // index of the first instruction belonging to this block
	i32 insEnd; // index of the first instruction after this block
	SmallVector<i32, 2> successors; // indices of successor blocks

	auto insCount() const { return insEnd - insBegin; }
};

export struct Function
{
	std::vector<x86::Instruction> instructions; // sorted by rva
	RangeMap<FunctionBlock> blocks;

	i32 begin() const { return blocks.front().begin; }
	i32 end() const { return blocks.back().end; }
	auto blockInstructions(this auto&& self, const FunctionBlock& block) { return std::span(self.instructions).subspan(block.insBegin, block.insCount()); }
	auto blockInstructions(this auto&& self, int blockIndex) { return self.blockInstructions(self.blocks[blockIndex]); }
	auto findInstruction(this auto&& self, i32 rva) { return std::ranges::find_if(instructions, [rva](const auto& ins) { return ins.rva == rva; }); }
};

// debug logging
enum class LogLevel { None, Important, Verbose };
Logger log{ "FuncBlock", LogLevel::None };
void logIns(LogLevel level, const x86::Instruction& ins, std::string_view message) { log(level, ">> {:X}: {} = {}", ins.rva, ins, message); }

// utility for finding all blocks in a function
// consider reusing the instance of this class for analyzing multiple functions, to save on some allocations
export template<typename Func = Function> requires std::is_base_of_v<Function, Func>
class FunctionBlockAnalysis
{
public:
	FunctionBlockAnalysis(std::span<const u8> bytes) : mBytes(bytes) {}

	// the standard entry point: perform full analysis
	// limit is optional, zero means 'unknown, function can extend up to the end of the binary'
	Func analyze(i32 rva, i32 limit = 0)
	{
		start(rva, limit);
		scheduleAndAnalyze(rva);
		return finish();
	}

	// observe current analysis state
	bool inProgress() const { return mCurStart != 0; }
	auto& currentBlocks() { return mBlocks; }
	auto& currentInstructions() { return mInstructions; }
	std::span<x86::Instruction> instructions(const FunctionBlock& block) { return std::span(mInstructions).subspan(block.insBegin, block.insCount()); }

	// cancel any current incremental analysis
	void clear()
	{
		mCurStart = mCurLimit = 0;
		mInstructions.clear();
		mBlocks.clear();
		mSwitchBlocks.clear();
		mPendingBlockStarts.clear();
	}

	// start new incremental analysis
	// useful if there are some blocks that are normally unreachable but we still want them to be considered part of the function
	void start(i32 rva, i32 limit = 0)
	{
		ensure(!inProgress());
		mCurStart = rva;
		mCurLimit = limit ? limit : static_cast<i32>(mBytes.size());
		log(LogLevel::Important, "analyzing {:X}-{:X}", mCurStart, mCurLimit);
	}

	// analyze block starting at specified address and all blocks it refers to
	void scheduleAndAnalyze(i32 rva)
	{
		ensure(inProgress());
		ensure(rva >= mCurStart && rva < mCurLimit);
		mPendingBlockStarts.push_back(rva);
		while (!mPendingBlockStarts.empty())
		{
			auto rva = mPendingBlockStarts.back();
			mPendingBlockStarts.pop_back();
			analyzeBlock(rva);
		}
	}

	// finish the analysis, get results and clear internal state
	Func finish()
	{
		ensure(inProgress());
		Func result;
		result.instructions.reserve(mInstructions.size());
		for (auto& block : mBlocks)
		{
			auto blockInstructions = instructions(block);
			block.insBegin = static_cast<i32>(result.instructions.size());
			result.instructions.append_range(blockInstructions);
			block.insEnd = static_cast<i32>(result.instructions.size());
			for (auto& succ : block.successors)
				succ = mBlocks.findIndex(succ);
		}
		result.blocks = std::move(mBlocks);
		for (auto& b : mSwitchBlocks)
			result.blocks.insert(std::move(b));
		clear();
		return result;
	}

private:
	void analyzeBlock(i32 rva)
	{
		auto nextBlock = mBlocks.findNext(rva);
		auto existing = mBlocks.getPrevIfContains(nextBlock, rva);
		if (existing == mBlocks.end())
		{
			// disassemble new block...
			auto blockLimit = nextBlock != mBlocks.end() ? nextBlock->begin : mCurLimit;
			log(LogLevel::Important, "> block {:X}-{:X}", rva, blockLimit);
			auto newBlock = analyzeNewBlock(rva, blockLimit);
			ensure(newBlock.end <= blockLimit);
			mBlocks.insert(std::move(newBlock), nextBlock);
		}
		else if (existing->begin != rva)
		{
			// split existing block
			log(LogLevel::Important, "> splitting {:X}-{:X} at {:X}", existing->begin, existing->end, rva);
			auto ispan = instructions(*existing);
			auto isplit = std::ranges::find(ispan, rva, &x86::Instruction::rva);
			ensure(isplit != ispan.end());
			auto splitIndex = existing->insBegin + static_cast<i32>(isplit - ispan.begin());

			FunctionBlock pred{ existing->begin, rva, existing->insBegin, splitIndex, { rva } };
			mBlocks.edit(existing).insBegin = splitIndex;
			mBlocks.shrink(rva, existing->end, existing);
			mBlocks.insert(std::move(pred), nextBlock - 1);
		}
		// else: this block was already processed, nothing to do here...
	}

	FunctionBlock analyzeNewBlock(i32 rva, i32 limit)
	{
		FunctionBlock newBlock{ rva, rva, static_cast<i32>(mInstructions.size()) };
		while (true)
		{
			auto& ins = mInstructions.emplace_back(disasmResolveJumpChains(mBytes, newBlock.end));
			newBlock.end += ins.length;
			if (ins.mnem == X86_INS_RET || ins.mnem == X86_INS_INT && ins.ops[0] == 0x29)
			{
				logIns(LogLevel::Verbose, ins, "ret");
				break; // ret or int 0x29 end the final blocks of the function
			}
			else if (ins.mnem == X86_INS_JMP)
			{
				logIns(LogLevel::Verbose, ins, "jmp");
				processJump(newBlock, ins);
				break; // unconditional jump ends the block
			}
			else if (ins.mnem.isConditionalJump())
			{
				logIns(LogLevel::Verbose, ins, "jcc");
				newBlock.successors.push_back(newBlock.end); // implicit flow edge should be first (before conditional jump)
				processJump(newBlock, ins);
				mPendingBlockStarts.push_back(newBlock.end); // process flow edge first...
				break;
			}
			else if (newBlock.end == limit)
			{
				// we've reached a point where someone else jumped to, end the block now
				logIns(LogLevel::Verbose, ins, "limit reached");
				newBlock.successors.push_back(newBlock.end);
				break;
			}
			else
			{
				logIns(LogLevel::Verbose, ins, "flow");
				ensure(newBlock.end < limit);
				// continue...
			}
		}
		newBlock.insEnd = static_cast<i32>(mInstructions.size());
		return newBlock;
	}

	void processJump(FunctionBlock& block, const x86::Instruction& ins)
	{
		if (ins.ops[0].type == x86::OpType::Imm)
		{
			auto target = ins.ops[0].immediate<i32>();
			if (target >= mCurStart && target < mCurLimit)
			{
				log(LogLevel::Important, "> scheduling [{:X}] {:X} -> {:X}", block.begin, ins.rva, target);
				//auto flags = isn.mnem == X86_INS_JMP ? EdgeFlags::Unconditional : EdgeFlags::None;
				//if (isn.rva + 1 == block.end)
				//	flags |= EdgeFlags::PatchedChain; // real jumps can't be 1-byte
				block.successors.push_back(target);
				mPendingBlockStarts.push_back(target);
			}
			// else: tail recursion jump, treat as if it were a call+ret
		}
		else if (ins.ops[0].type == x86::OpType::Reg)
		{
			// try to process switch
			// variant 1 (direct table):
			// <predecessor block>:
			//   cmp reg1, limit
			//   jbe <cur block> - or ja <default block>
			// <cur block>:
			//   [potentially some unrelated instructions]
			//   lea reg2, imagebase - might be optional? if it's already in register for unrelated reason
			//   mov reg3, dword ptr [reg2 + 4 * reg1 + jumptable_rva] - note that reg2/reg3 might as well be swapped here...
			//   add reg3, reg2
			//   jmp reg3
			auto branchReg = ins.ops[0].reg;
			ensure(branchReg.isGPR64());
			auto prevIns = &ins - 1;
			auto curBlockStart = &mInstructions[block.insBegin];
			while (prevIns >= curBlockStart && !(prevIns->mnem == X86_INS_ADD && prevIns->ops[0] == branchReg && prevIns->ops[1].type == x86::OpType::Reg))
				--prevIns;
			if (prevIns < curBlockStart)
				return; // not a switch statement
			auto imagebaseReg = prevIns->ops[1].reg;
			--prevIns;
			while (prevIns >= curBlockStart && !(prevIns->mnem == X86_INS_MOV && prevIns->ops[1].type == x86::OpType::Mem && prevIns->ops[0].type == x86::OpType::Reg && prevIns->ops[0].reg.isGPR32() && (prevIns->ops[0].reg.gprIndex() == branchReg.gprIndex() || prevIns->ops[0].reg.gprIndex() == imagebaseReg.gprIndex())))
				--prevIns;
			ensure(prevIns >= curBlockStart);
			if (prevIns->ops[0].reg.gprIndex() == imagebaseReg.gprIndex())
				std::swap(branchReg, imagebaseReg);
			ensure(prevIns->ops[1].mem.base == imagebaseReg && prevIns->ops[1].mem.scale == 4);
			auto indexReg = prevIns->ops[1].mem.index;
			auto jumpTableRVA = prevIns->ops[1].mem.displacement;
			// now look for optional indirect table load: movzx index32, byte [imagebase + indirect + indirectTableRVA]
			--prevIns;
			while (prevIns >= curBlockStart && !(prevIns->mnem == X86_INS_MOVZX && prevIns->ops[0].type == x86::OpType::Reg && prevIns->ops[0].reg.gprIndex() == indexReg.gprIndex() && prevIns->ops[1].type == x86::OpType::Mem))
				--prevIns;
			i32 indirectTableRVA = 0;
			if (prevIns >= curBlockStart)
			{
				ensure(prevIns->ops[1].size == 1 && prevIns->ops[1].mem.scale == 1);
				indexReg = prevIns->ops[1].mem.index;
				indirectTableRVA = prevIns->ops[1].mem.displacement;
			}
			auto prevBlock = std::ranges::find_if(mBlocks, [&](const auto& b) { return std::ranges::contains(b.successors, block.begin); });
			ensure(prevBlock != mBlocks.end() && prevBlock->insCount() > 1);
			auto& prevBlockJcc = instructions(*prevBlock).back();
			ensure(prevBlockJcc.mnem == X86_INS_JBE || prevBlockJcc.mnem == X86_INS_JA); // TODO: can it be something else? like jb?
			auto prevBlockCmp = &prevBlockJcc - 1;
			ensure(prevBlockCmp->mnem == X86_INS_CMP && prevBlockCmp->ops[0].type == x86::OpType::Reg /*&& prevBlockCmp->ops[0].reg.gprIndex() == indexReg.gprIndex()*/ && prevBlockCmp->ops[1].type == x86::OpType::Imm); // TODO: there could be renamings of index reg that we've skipped
			auto jumpTableSize = prevBlockCmp->ops[1].immediate<i32>() + 1;
			if (indirectTableRVA)
			{
				// the size is actually of the indirect table
				auto indirectTableSize = jumpTableSize;
				mSwitchBlocks.push_back({ indirectTableRVA, indirectTableRVA + indirectTableSize });
				jumpTableSize = 0;
				for (int i = 0; i < indirectTableSize; ++i)
					jumpTableSize = std::max(jumpTableSize, mBytes[indirectTableRVA + i] + 1);
				log(LogLevel::Important, "> found indirect switch at [{:X}] {:X}: indirect table at {:X}, size {}, jump table at {:X}, size {}", block.begin, ins.rva, indirectTableRVA, indirectTableSize, jumpTableRVA, jumpTableSize);
			}
			else
			{
				log(LogLevel::Important, "> found direct switch at [{:X}] {:X}: jump table at {:X}, size {}", block.begin, ins.rva, jumpTableRVA, jumpTableSize);
			}
			mSwitchBlocks.push_back({ jumpTableRVA, jumpTableRVA + jumpTableSize * 4 });
			auto jumpTable = reinterpret_cast<const i32*>(mBytes.data() + jumpTableRVA);
			for (int i = 0; i < jumpTableSize; ++i)
			{
				auto target = jumpTable[i];
				log(LogLevel::Important, ">> branch {} = {:X}", i, target);
				ensure(target >= mCurStart && target < mCurLimit);
				block.successors.push_back(target);
				mPendingBlockStarts.push_back(target);
			}
		}
		// else: jmp [mem], ignore?.. this is used for stuff like export thunks...
	}

private:
	std::span<const u8> mBytes;
	i32 mCurStart{};
	i32 mCurLimit{};
	std::vector<x86::Instruction> mInstructions;
	RangeMap<FunctionBlock> mBlocks;
	std::vector<FunctionBlock> mSwitchBlocks;
	std::vector<i32> mPendingBlockStarts; // blocks to be analyzed
};


}
