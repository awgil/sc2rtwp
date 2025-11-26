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
	rva_t parent = 0; // relevant for special functions
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
	// all the exception handlers are also analyzed automatically (but not stuff they call)
	FunctionInfo& analyze(rva_t rva, std::string_view name, auto&& analyzeFunc)
	{
		auto [it, isNew] = getOrCreateEntry(rva);
		auto& e = it->second;
		ensure(e.name.empty() && !e.isAnalyzed()); // should never have been analyzed before
		logger(LogLevel::Verbose, "Processing {} function '{}' at {:X}...", isNew ? "new" : "known", name, rva);
		e.name = name;

		auto res = analyzeFunc(mFBA, rva, guessFunctionLimit(it), e.extraEntryPoints);
		e.blocks = std::move(res.blocks);
		e.instructions = std::move(res.instructions);

		auto limit = e.seh ? e.seh->end : e.blocks.back().end;
		if (e.type == FunctionType::SEHFilter && limit == e.blocks.back().end + 1)
		{
			// TODO: for whatever reason, some SEH filters have SEH entry covering one byte more than is real...
			--limit;
			__debugbreak();
		}
		mPatcher.patchFunction(e, limit);

		e.refs = analysis::getSimpleRefs(e.instructions);

		e.end = std::max(e.end, limit);
		if (limit > e.end)
		{
			e.end = limit;
			auto next = it;
			++next;
			ensure(next == mTable.end() || limit <= next->first);
		}

		return e;
	}

	auto& analyze(rva_t rva, std::string_view name)
	{
		return analyze(rva, name, [&](analysis::FunctionBlockAnalysis<>& analyzer, rva_t begin, rva_t limit, std::span<const rva_t> extraBlocks) {
			analyzer.start(begin, limit);
			analyzer.scheduleAndAnalyze(begin);
			for (auto rva : extraBlocks)
				analyzer.scheduleAndAnalyze(rva);
			return analyzer.finish();
		});
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
						externalFuncs.push_back(catchBlock.dispOfHandler);
						markAsSecondary(catchBlock.dispOfHandler, FunctionType::CatchBlock, seh.begin);
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
		std::vector<rva_t> pending, nextIteration;
		pending.reserve(mTable.size());
		for (auto& [_, func] : mTable)
			if (!func.isAnalyzed())
				pending.push_back(func.begin);

		int iPass = 0;
		while (!pending.empty())
		{
			logger(LogLevel::Important, "Analyzing remaining functions: pass {}, {} functions remaining", ++iPass, pending.size());
			for (size_t iFunc = 0; iFunc < pending.size(); ++iFunc)
			{
				auto [it, isNew] = getOrCreateEntry(pending[iFunc]);
				auto& entry = it->second;
				ensure(!isNew && !entry.isAnalyzed());
				auto needDefer = std::ranges::any_of(entry.exceptionHandlers, [&](rva_t secondary) {
					auto& e = mTable[secondary];
					return !e.isAnalyzed() && e.type == FunctionType::CatchBlock; // catch blocks need to be analyzed first, as they have extra block refs for parent func
				});
				if (needDefer)
				{
					nextIteration.push_back(pending[iFunc]);
					continue;
				}

				analyze(it->first, "");
				auto refs = std::span(entry.refs);
				if (entry.type == FunctionType::CatchBlock)
				{
					ensure(!refs.empty() && refs.back().ins->ops[0] == x86::Reg::rax);
					auto& parent = mTable[entry.parent];
					ensure(parent.begin == entry.parent && !parent.isAnalyzed());
					parent.extraEntryPoints.push_back(refs.back().ref);
					refs = refs.subspan(0, refs.size() - 1);
				}

				for (auto& ref : refs)
				{
					if (ref.ref >= mTextBegin && ref.ref < mTextEnd && getOrCreateEntry(ref.ref).second)
					{
						pending.push_back(ref.ref);
					}
				}
			}

			pending.clear();
			std::swap(pending, nextIteration);
		}
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

	auto guessFunctionLimit(auto it)
	{
		if (it->second.seh)
			return it->second.seh->end;
		++it;
		return it != mTable.end() ? it->first : mTextEnd;
	}

	auto markAsSecondary(rva_t rva, FunctionType type, rva_t parent)
	{
		auto& e = getOrCreateEntry(rva).first->second;
		ensure(!e.isAnalyzed());
		e.type = type;
		e.parent = parent;
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

