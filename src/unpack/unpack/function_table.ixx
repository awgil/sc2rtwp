export module unpack.function_table;

export import unpack.analysis.function_block;
export import unpack.analysis.simple_refs;
export import unpack.range_map;
export import unpack.pe_binary;
export import unpack.patcher;

// debug logging
enum class LogLevel { None, Important, Verbose };
Logger logger{ "FuncTable", LogLevel::Verbose };

export enum class FunctionType
{
	Normal, // standard function
	SEHFilter, // SEH filter function, IDA considers it to be a chunk
	UnwindFunclet, // C++ unwind funclet, typically jumps to the destructor of the local
	CatchBlock, // C++ catch block, outlined, IDA considers it to be a chunk, returns continuation point in owning function
};

export struct FunctionInfo : analysis::Function
{
	rva_t begin;
	rva_t end;
	std::string name;
	std::vector<analysis::Reference> refs;
	const SEHInfo::Entry* seh = nullptr;
	FunctionType type = FunctionType::Normal;
	std::vector<rva_t> parents; // relevant for special functions
	std::vector<rva_t> extraEntryPoints;
	std::vector<rva_t> exceptionHandlers; // note: external functions (eg. SEH filters, catch blocks, unwind funclets)

	bool isAnalyzed() const { return !blocks.empty(); }
};

// table describing .text layout of the binary
// note: if you call analyze(), you're expected to then add entries for referenced functions too, otherwise analyzeRest() won't pick them up
export class FunctionTable
{
public:
	FunctionTable(PEBinary& binary, const PEBinary::Section& text, Patcher& patcher)
		: mBinary(binary)
		, mFBA(binary.bytes())
		, mTextBegin(text.begin)
		, mTextEnd(text.end)
		, mPatcher(patcher)
	{
		// build a list of function pointers
		std::vector<rva_t> funcStarts;
		funcStarts.reserve(binary.relocRVAs().size());

		// start with relocs
		// note: there are a few relocs that are pointing to something weird (imagebase and then not-a-function in bootstrap area)
		// these are all unaligned, so let's skip them
		for (auto reloc : binary.relocRVAs())
		{
			auto rva = binary.vaToRVA(*binary.structAtRVA<i64>(reloc));
			if (reloc & 7)
			{
				logger(LogLevel::Important, "Skipping weird reloc: {:X} -> {:X}", reloc, rva);
				continue;
			}

			if (text.contains(rva))
			{
				funcStarts.push_back(rva);
			}
		}

		// TODO: add exports

		std::ranges::sort(funcStarts);
		auto dupes = std::ranges::unique(funcStarts);
		funcStarts.erase(dupes.begin(), dupes.end());

		// create entries for functions covered by SEH & reloc
		// do that in order, so that we can use emplace_hint
		auto iFunc = funcStarts.begin();
		auto insertFuncsUpTo = [&](rva_t rva) {
			while (iFunc != funcStarts.end() && *iFunc < rva)
			{
				auto it = mTable.try_emplace(mTable.end(), *iFunc);
				it->second.begin = *iFunc;
				it->second.end = *iFunc + 1;
				++iFunc;
			}
		};
		for (auto& seh : binary.sehEntries())
		{
			// TODO: ignore if this entry covers catch block of other function?.. it has a ref to the middle of other func
			insertFuncsUpTo(seh.begin);
			auto it = mTable.try_emplace(mTable.end(), seh.begin);
			it->second.begin = seh.begin;
			it->second.end = seh.end;
			it->second.seh = &seh;
			if (iFunc != funcStarts.end() && *iFunc == seh.begin)
				++iFunc;
			ensure(iFunc == funcStarts.end() || *iFunc >= seh.end);
		}
		insertFuncsUpTo(std::numeric_limits<rva_t>::max());
	}

	// analyze single function that is assumed to be never analyzed before
	FunctionInfo& analyze(rva_t rva, std::string_view name)
	{
		auto [it, isNew] = getOrCreateEntry(rva);
		logger(LogLevel::Verbose, "Processing {} function '{}' at {:X}...", isNew ? "new" : "known", name, rva);

		ensure(it->second.name.empty());
		it->second.name = name;

		executeAnalysis(it);
		return it->second;
	}

	void analyzeSEHHandlers()
	{
		std::vector<std::reference_wrapper<FunctionInfo>> handlers;
		auto isKnownHandler = [&](rva_t rva) { return std::ranges::contains(handlers, rva, [](const FunctionInfo& h) { return h.begin; }); };

		for (auto& seh : mBinary.sehEntries())
			if (seh.value.rva && !isKnownHandler(seh.value.rva))
				handlers.push_back(analyze(seh.value.rva, ""));
		ensure(handlers.size() == 4); // these are all library ones - note that SC2 doesn't have the __GSHandlerCheck_SEH variant...
		// heuristics to classify handlers...
		for (FunctionInfo& handler : handlers)
		{
			switch (handler.refs.size())
			{
			case 1:
				// this one simply calls __GSHandlerCheckCommon
				logger(LogLevel::Important, "SEH handler at {:X} = __GSHandlerCheck", handler.begin);
				break;
			case 2:
				// this one calls __GSHandlerCheckCommon and __CxxFrameHandler3
				ensure(isKnownHandler(handler.refs[1].ref));
				mGSHandlerCheckEH = handler.begin;
				logger(LogLevel::Important, "SEH handler at {:X} = __GSHandlerCheck_EH", handler.begin);
				break;
			case 4:
				// this one calls __vcrt_getptd 3x and then __InternalCxxFrameHandler
				ensure(handler.refs[1].ref == handler.refs[0].ref && handler.refs[2].ref == handler.refs[0].ref);
				mCxxFrameHandler = handler.begin;
				logger(LogLevel::Important, "SEH handler at {:X} = __CxxFrameHandler3", handler.begin);
				break;
			case 8:
				// this one calls a whole lot of shit
				mCSpecificHandler = handler.begin;
				logger(LogLevel::Important, "SEH handler at {:X} = __C_specific_handler", handler.begin);
				break;
			default:
				__debugbreak();
			}
		}
		ensure(mCSpecificHandler && mCxxFrameHandler && mGSHandlerCheckEH);

		// now that we know handlers, we can process handler-specific data in SEH records
		std::vector<rva_t> extraBlocks, externalFuncs;
		for (auto& seh : mBinary.sehEntries())
		{
			if (!seh.value.rva)
				continue; // unwind only, nothing interesting...

			if (seh.value.rva == mCSpecificHandler)
			{
				for (auto& scope : seh.value.scopeRecords())
				{
					if (scope.HandlerAddress > 1)
					{
						// try-except filter and try-finally finally blocks are separate functions, mark them appropriately and analyze
						externalFuncs.push_back(scope.HandlerAddress);
						markAsSecondary(scope.HandlerAddress, FunctionType::SEHFilter, seh.begin);
					}
					if (scope.JumpTarget)
					{
						// try-except block has except body in function
						extraBlocks.push_back(scope.JumpTarget);
					}
				}
			}
			else if (seh.value.rva == mCxxFrameHandler || seh.value.rva == mGSHandlerCheckEH)
			{
				// TODO: consider adding unwind funclets as functions; there are tons of them and they are all trivial (usually tail-recursion jump), so not sure there's a point...
				for (auto& tryBlock : seh.value.tryBlocks(mBinary))
				{
					for (auto& catchBlock : seh.value.catchBlocks(mBinary, tryBlock))
					{
						// catch blocks are implemented as separate functions that return address of the block to continue execution at
						if (seh.begin != catchBlock.dispOfHandler)
						{
							externalFuncs.push_back(catchBlock.dispOfHandler);
							markAsSecondary(catchBlock.dispOfHandler, FunctionType::CatchBlock, seh.begin);
						}
					}
				}
			}
			else
			{
				continue; // some handler we don't care about, don't bother doing the lookup etc
			}

			auto& parentFunc = mTable[seh.begin];
			ensure(parentFunc.begin == seh.begin && !parentFunc.isAnalyzed() && parentFunc.extraEntryPoints.empty() && parentFunc.exceptionHandlers.empty());
			parentFunc.extraEntryPoints = std::move(extraBlocks);
			parentFunc.exceptionHandlers = std::move(externalFuncs);
			ensure(extraBlocks.empty() && externalFuncs.empty());
		}
	}

	void analyzeAllRemaining()
	{
		// first, process all C++ catch blocks - unless they rethrow unconditionally, they will return an address of the extra entry point in the parent function
		logger(LogLevel::Important, "Analyzing catch blocks");
		int numAnalyzed = 0;
		for (auto it = mTable.begin(); it != mTable.end(); ++it)
		{
			if (it->second.type != FunctionType::CatchBlock)
				continue;

			++numAnalyzed;
			executeAnalysis(it);
			for (auto& ref : it->second.refs)
			{
				if (ref.ref < mTextBegin || ref.ref >= mTextEnd)
					continue; // not a code reference, don't care

				if (ref.ins->mnem == X86_INS_LEA && ref.ins->ops[0] == x86::Reg::rax)
				{
					// note: catch blocks either rethrow or return rva to continue execution from, which is an extra entry point to one of the parents (the main one)
					if (auto parent = findParentContainingAddress(it->second, ref.ref))
					{
						ensure(!parent->isAnalyzed());
						parent->extraEntryPoints.push_back(ref.ref);
						break;
					}
				}

				// ensure we'll analyze this later
				getOrCreateEntry(ref.ref);
			}
		}
		logger(LogLevel::Important, "Analyzed {} catch blocks", numAnalyzed);

		// ok, now main pass - analyze all functions known so far and any referenced we find
		logger(LogLevel::Important, "Analyzing remaining functions");
		std::vector<rva_t> nextIteration;
		numAnalyzed = 0;
		for (auto it = mTable.begin(); it != mTable.end(); ++it)
		{
			if (it->second.isAnalyzed())
				continue;

			++numAnalyzed;
			executeAnalysis(it);
			for (auto& ref : it->second.refs)
			{
				if (ref.ref < mTextBegin || ref.ref >= mTextEnd)
					continue; // not a code reference, don't care

				// ensure we'll analyze this later; note that it will automatically be iterated over on this pass if the address is greater than current function
				if (getOrCreateEntry(ref.ref).second && ref.ref < it->first)
					nextIteration.push_back(ref.ref);
			}
		}

		while (!nextIteration.empty())
		{
			logger(LogLevel::Important, "Analyzing extra {} functions", nextIteration.size());
			auto pending = std::move(nextIteration);
			for (auto rva : pending)
			{
				++numAnalyzed;
				auto it = mTable.find(rva);
				ensure(it != mTable.end());
				executeAnalysis(it);
				for (auto& ref : it->second.refs)
				{
					if (ref.ref < mTextBegin || ref.ref >= mTextEnd)
						continue; // not a code reference, don't care

					if (getOrCreateEntry(ref.ref).second)
						nextIteration.push_back(ref.ref);
				}
			}
		}

		logger(LogLevel::Important, "Analyzed {} functions", numAnalyzed);
	}

	const auto& entries() const { return mTable; }

private:
	auto getOrCreateEntry(rva_t rva)
	{
		ensure(rva >= mTextBegin && rva < mTextEnd);
		auto [it, isNew] = mTable.try_emplace(rva);
		if (isNew)
		{
			it->second.begin = rva;
			it->second.end = rva + 1;
			if (it != mTable.begin())
			{
				auto prev = it;
				ensure(--prev->second.end <= rva);
			}
		}
		ensure(it->second.begin == rva);
		return std::make_pair(it, isNew);
	}

	auto markAsSecondary(rva_t rva, FunctionType type, rva_t parent)
	{
		// note: some catch blocks have themselves (???) or other catch blocks as parents
		ensure(parent != rva);
		auto& e = getOrCreateEntry(rva).first->second;
		ensure(!e.isAnalyzed());
		ensure(e.type == (e.parents.empty() ? FunctionType::Normal : type));
		e.type = type;
		if (!std::ranges::contains(e.parents, parent))
			e.parents.push_back(parent);
	}

	void executeAnalysis(auto it)
	{
		auto& func = it->second;
		ensure(!func.isAnalyzed()); // should never have been analyzed before
		mFBA.start(func.begin, guessFunctionLimit(it));
		mFBA.scheduleAndAnalyze(func.begin);
		for (auto extra : func.extraEntryPoints)
			mFBA.scheduleAndAnalyze(extra);

		auto limit = func.seh ? func.seh->end : mFBA.currentBlocks().back().end;
		if (limit == mFBA.currentBlocks().back().end + 1)
		{
			// note: for whatever reason, few functions have SEH entry covering one byte more than is real...
			--limit;
		}

		// note: new blocks are added during iteration, so index based iteration has to be used
		for (int i = 0; i < mFBA.currentBlocks().size() - 1; ++i)
			if (auto next = guessNextUnreachableBlock(mFBA.currentBlocks()[i], mFBA.currentBlocks()[i + 1].begin))
				mFBA.scheduleAndAnalyze(next);
		// and see if there's some unreachable tail...
		if (func.seh && limit > mFBA.currentBlocks().back().end)
			if (auto next = guessNextUnreachableBlock(mFBA.currentBlocks().back(), limit))
				mFBA.scheduleAndAnalyze(next);

		auto res = mFBA.finish();
		func.blocks = std::move(res.blocks);
		func.instructions = std::move(res.instructions);

		mPatcher.patchFunction(func, limit);

		func.refs = analysis::getSimpleRefs(func.instructions);

		if (limit > func.end)
		{
			func.end = limit;
			auto next = it;
			++next;
			ensure(next == mTable.end() || limit <= next->first);
		}
	}

	auto guessFunctionLimit(auto it)
	{
		if (it->second.seh)
			return it->second.seh->end;
		++it;
		return it != mTable.end() ? it->first : mTextEnd;
	}

	// some functions have unreachable blocks that we still want to analyze; this uses some heuristics to try to guess one - returns rva of the start if found, or 0 otherwise
	rva_t guessNextUnreachableBlock(const analysis::FunctionBlock& block, rva_t limit)
	{
		if (block.insCount() != 0)
		{
			auto& lastIns = mFBA.instructions(block).back();
			if (lastIns.mnem == X86_INS_JMP && lastIns.length == 1)
				return 0; // assume everything that's in the jump chain is junk
		}
		auto rva = block.end;
		while (rva < limit)
		{
			auto ins = x86::disasm(mBinary.bytes(), rva);
			if (ins.mnem != X86_INS_NOP && ins.mnem != X86_INS_INT3)
			{
				logger(LogLevel::Important, "Found unreachable block at 0x{:X}, starting with {}", rva, ins);
				return rva; // looks like a real block!
			}
			rva += ins.length;
		}
		return 0; // nope not found anything...
	}

	FunctionInfo* findParentContainingAddress(const FunctionInfo& function, rva_t rva)
	{
		for (auto p : function.parents)
		{
			auto& parent = mTable[p];
			if (rva >= parent.begin && rva < parent.end)
				return &parent;
		}
		return nullptr;
	}

private:
	PEBinary& mBinary;
	analysis::FunctionBlockAnalysis<> mFBA;
	rva_t mTextBegin;
	rva_t mTextEnd;
	Patcher& mPatcher;
	std::map<rva_t, FunctionInfo> mTable;
	// SEH top level handlers
	rva_t mCSpecificHandler = 0;
	rva_t mCxxFrameHandler = 0;
	rva_t mGSHandlerCheckEH = 0;
};

