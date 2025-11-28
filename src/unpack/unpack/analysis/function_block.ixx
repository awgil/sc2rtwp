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
	auto findInstruction(this auto&& self, i32 rva) { return std::ranges::find_if(instructions, [rva](const auto& ins) { return ins.rva == rva; }); }
};

struct SwitchMetadata
{
	i32 rvaJmp; // jmp reg instruction
	i32 rvaJumpTable;
	i32 sizeJumpTable;
	i32 rvaIndirectTable;
	i32 sizeIndirectTable;
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
		mSwitchMeta.clear();
		mPendingBlockStarts.clear();
		mPendingSwitches.clear();
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
		while (mPendingBlockStarts.size() + mPendingSwitches.size() > 0)
		{
			// note that we only want to start processing switches when all other blocks are analyzed
			// this is because we need to know all predecessors for a block containing the switch jump, so that we can accurately determine jump table size
			while (!mPendingBlockStarts.empty())
			{
				auto rva = mPendingBlockStarts.back();
				mPendingBlockStarts.pop_back();
				analyzeBlock(rva);
			}
			while (!mPendingSwitches.empty())
			{
				auto rva = mPendingSwitches.back();
				mPendingSwitches.pop_back();
				if (analyzeSwitch(rva))
					break; // on success, process all normal blocks before continuing to process switches
			}
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
			if (ins.mnem == X86_INS_RET)
			{
				// note: IDA treats int 0x29 (fastfail) as noreturn, but it seems there's code emitted after...
				logIns(LogLevel::Verbose, ins, "ret");
				break; // ret ends the final blocks of the function
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
			// delay processing switches until all pending blocks are processed
			mPendingSwitches.push_back(ins.rva);
		}
		// else: jmp [mem], ignore?.. this is used for stuff like export thunks...
	}

	bool analyzeSwitch(i32 rva)
	{
		log(LogLevel::Important, "> analyzing switch at {:X}", rva);
		// <predecessor block>:
		//   cmp reg1, limit
		//   jbe <cur block> - or ja <default block>
		// <cur block>:
		//   [potentially some unrelated instructions]
		//   lea reg2, imagebase - might be optional? if it's already in register for unrelated reason
		//   movzx reg1, byte ptr [reg2 + reg1 + indirect_rva] - optional, for tables with indirection
		//   mov reg3, dword ptr [reg2 + 4 * reg1 + jumptable_rva] - note that reg2/reg3 might as well be swapped here...
		//   add reg3, reg2 - note that sometimes imagebase is reloaded again into a different reg before this...
		//   jmp reg3
		SwitchMetadata meta{ rva };
		auto blockIndex = mBlocks.findIndex(rva);
		ensure(blockIndex < mBlocks.size());
		auto blockIns = instructions(mBlocks[blockIndex]);
		auto iIns = blockIns.rbegin();
		ensure(iIns != blockIns.rend() && iIns->rva == rva && iIns->mnem == X86_INS_JMP && iIns->ops[0].type == x86::OpType::Reg);
		auto branchReg = iIns->ops[0].reg;
		ensure(branchReg.isGPR64()); // expected to contain VA of the case

		// find add that converts case RVA from jump table into VA
		while (++iIns != blockIns.rend())
			if (iIns->mnem == X86_INS_ADD && iIns->ops[0] == branchReg && iIns->ops[1].type == x86::OpType::Reg)
				break;
		if (iIns == blockIns.rend())
		{
			log(LogLevel::Verbose, ">> not found 'add jumptable, imagebase'");
			return false; // not a switch statement
		}
		auto imagebaseReg = iIns->ops[1].reg; // note: imagebase and branch could be swapped

		// find mov that loads case RVA from jump table
		// TODO: theoretically there could be a mov that changes the register we're looking for...
		while (++iIns != blockIns.rend())
			if (iIns->mnem == X86_INS_MOV && iIns->ops[1].type == x86::OpType::Mem && iIns->ops[0].type == x86::OpType::Reg && iIns->ops[0].reg.isGPR32() && (iIns->ops[0].reg.gprIndex() == branchReg.gprIndex() || iIns->ops[0].reg.gprIndex() == imagebaseReg.gprIndex()))
				break;
		ensure(iIns != blockIns.rend());
		ensure(iIns->ops[1].mem.scale == 4);
		auto indexReg = iIns->ops[1].mem.index;
		meta.rvaJumpTable = iIns->ops[1].mem.displacement;

		// now look for optional indirect table load: movzx index32, byte [imagebase + indirect + indirectTableRVA]
		while (++iIns != blockIns.rend())
			if (iIns->mnem == X86_INS_MOVZX && iIns->ops[0].type == x86::OpType::Reg && iIns->ops[0].reg.gprIndex() == indexReg.gprIndex() && iIns->ops[1].type == x86::OpType::Mem)
				break;
		if (iIns != blockIns.rend())
		{
			ensure(iIns->ops[1].size == 1 && iIns->ops[1].mem.scale == 1);
			indexReg = iIns->ops[1].mem.index;
			meta.rvaIndirectTable = iIns->ops[1].mem.displacement;
		}

		// finally, find the jump table size - one of the predecessor blocks should have a jcc
		// note that some predecessors could set the case variable to a constant guaranteed to be in range and skip the bounds check!
		auto blockStart = mBlocks[blockIndex].begin;
		for (const auto& b : mBlocks)
		{
			if (!std::ranges::contains(b.successors, blockStart))
				continue; // not a predecessor
			log(LogLevel::Verbose, ">> considering predecessor {:X}", b.begin);
			auto prevIns = instructions(b);
			iIns = prevIns.rbegin();
			ensure(iIns != prevIns.rend()); // block with no instructions can't be a predecessor...
			if (iIns->mnem == X86_INS_JBE || iIns->mnem == X86_INS_JA) // TODO: can it be something else, like jb?
			{
				// this is what we're looking for - the block that checks switch variable against limit
				ensure(iIns->ops[0].type == x86::OpType::Imm);
				++iIns;
				ensure(iIns != prevIns.rend());
				ensure(iIns->mnem == X86_INS_CMP && iIns->ops[0].type == x86::OpType::Reg /*&& iIns->ops[0].reg.gprIndex() == indexReg.gprIndex()*/ && iIns->ops[1].type == x86::OpType::Imm); // TODO: there could be renamings of index reg that we've skipped
				if (meta.rvaIndirectTable)
				{
					// the size is actually of the indirect table
					meta.sizeIndirectTable = iIns->ops[1].immediate<i32>() + 1;
					mBlocks.insert({ meta.rvaIndirectTable, meta.rvaIndirectTable + meta.sizeIndirectTable });
					for (int i = 0; i < meta.sizeIndirectTable; ++i)
						meta.sizeJumpTable = std::max(meta.sizeJumpTable, mBytes[meta.rvaIndirectTable + i] + 1);
					log(LogLevel::Verbose, ">> found indirect switch at [{:X}] {:X}: indirect table at {:X}, size {}, jump table at {:X}, size {}", blockStart, rva, meta.rvaIndirectTable, meta.sizeIndirectTable, meta.rvaJumpTable, meta.sizeJumpTable);
				}
				else
				{
					meta.sizeJumpTable = iIns->ops[1].immediate<i32>() + 1;
					log(LogLevel::Verbose, ">> found direct switch at [{:X}] {:X}: jump table at {:X}, size {}", blockStart, rva, meta.rvaJumpTable, meta.sizeJumpTable);
				}
			}
			else if (iIns->mnem == X86_INS_JMP && iIns->ops[0].type == x86::OpType::Reg)
			{
				// nested switch on the same variable, this is cursed...
				ensure(!meta.rvaIndirectTable); // only direct
				auto parentSwitch = std::ranges::find_if(mSwitchMeta, [&](const auto& meta) { return meta.rvaJmp == iIns->rva; });
				ensure(parentSwitch != mSwitchMeta.end() && !parentSwitch->rvaIndirectTable);
				log(LogLevel::Verbose, ">> found nested direct-direct switch at [{:X}] {:X}, parent at {:X}", blockStart, rva, parentSwitch->rvaJmp);
				meta.sizeJumpTable = parentSwitch->sizeJumpTable;
			}
			else
			{
				// continue looking...
				continue;
			}

			mBlocks.insert({ meta.rvaJumpTable, meta.rvaJumpTable + meta.sizeJumpTable * 4 });
			mSwitchMeta.push_back(meta);
			auto jumpTable = reinterpret_cast<const i32*>(mBytes.data() + meta.rvaJumpTable);
			for (int i = 0; i < meta.sizeJumpTable; ++i)
			{
				auto target = jumpTable[i];
				log(LogLevel::Verbose, ">> branch {} = {:X}", i, target);
				ensure(target >= mCurStart && target < mCurLimit);
				mBlocks[blockIndex].successors.push_back(target);
				mPendingBlockStarts.push_back(target);
			}
			return true;
		}

		// we didn't find the good predecessor...
		__debugbreak();
		return false;
	}

private:
	std::span<const u8> mBytes;
	i32 mCurStart{};
	i32 mCurLimit{};
	std::vector<x86::Instruction> mInstructions;
	RangeMap<FunctionBlock> mBlocks;
	std::vector<SwitchMetadata> mSwitchMeta;
	std::vector<i32> mPendingBlockStarts; // blocks to be analyzed
	std::vector<i32> mPendingSwitches; // rvas of candidates to switch jumps
};


}
