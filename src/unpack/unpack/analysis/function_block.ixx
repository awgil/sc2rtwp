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

	auto blockInstructions(this auto&& self, const FunctionBlock& block) { return std::span(self.instructions).subspan(block.insBegin, block.insCount()); }
	auto blockInstructions(this auto&& self, int blockIndex) { return self.blockInstructions(self.blocks[blockIndex]); }
};

// debug logging
enum class LogLevel { None, Important, Verbose };
Logger log{ "FuncBlock", LogLevel::None };
void logIns(LogLevel level, const x86::Instruction& ins, std::string_view message) { log(level, ">> {:X}: {} = {}", ins.rva, ins, message); }

// utility for finding all blocks in a function
// consider reusing the instance of this class for analyzing multiple functions, to save on some allocations
export class FunctionBlockAnalysis
{
public:
	FunctionBlockAnalysis(std::span<const u8> bytes) : mBytes(bytes) {}

	// the standard entry point: perform full analysis
	// limit is optional, zero means 'unknown, function can extend up to the end of the binary'
	Function analyze(i32 rva, i32 limit = 0)
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
		mPendingBlockStarts.push_back(rva);
		while (!mPendingBlockStarts.empty())
		{
			auto rva = mPendingBlockStarts.back();
			mPendingBlockStarts.pop_back();
			analyzeBlock(rva);
		}
	}

	// finish the analysis, get results and clear internal state
	Function finish()
	{
		ensure(inProgress());
		Function result;
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
			// TODO: process tail recursion jumps...
			ensure(target >= mCurStart && target < mCurLimit);
			log(LogLevel::Important, "> scheduling [{:X}] {:X} -> {:X}", block.begin, ins.rva, target);

			//auto flags = isn.mnem == X86_INS_JMP ? EdgeFlags::Unconditional : EdgeFlags::None;
			//if (isn.rva + 1 == block.end)
			//	flags |= EdgeFlags::PatchedChain; // real jumps can't be 1-byte
			block.successors.push_back(target);
			mPendingBlockStarts.push_back(target);
		}
		else
		{
			// TODO: process switches...
			__debugbreak();
		}
	}

private:
	std::span<const u8> mBytes;
	i32 mCurStart{};
	i32 mCurLimit{};
	std::vector<x86::Instruction> mInstructions;
	RangeMap<FunctionBlock> mBlocks;
	std::vector<i32> mPendingBlockStarts; // blocks to be analyzed
};


}
