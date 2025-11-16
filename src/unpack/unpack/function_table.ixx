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

export struct FunctionData : analysis::Function
{
	std::vector<analysis::Reference> refs;
};

export struct FunctionTableEntryInfo
{
	std::unique_ptr<FunctionData> analyzed; // TODO: this is annoying - we really need to support analyzing new functions recursively though, meaning either this or diffent container that doesn't invalidate iterators...
	const SEHInfo::Entry* seh = nullptr;
	FunctionType type = FunctionType::Normal;
	rva_t parent = 0; // relevant for special functions
	std::vector<rva_t> extraEntryPoints;
	std::vector<rva_t> exceptionHandlers; // note: external functions (eg. SEH filters, catch blocks, unwind funclets)
};

// table describing .text layout of the binary
// note: if you call analyze(), you're expected to then add entries for referenced functions too, otherwise analyzeRest() won't pick them up
export class FunctionTable
{
public:
	using Entries = NamedRangeMap<rva_t, FunctionTableEntryInfo>;
	using Entry = Entries::Entry;

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
		// do that in order, to prevent costly reallocations when functions are inserted in the middle of the table
		mTable.reserve(binary.sehEntries().size() + funcStarts.size());
		auto iFunc = funcStarts.begin();
		auto insertFuncsUpTo = [&](rva_t rva) {
			while (iFunc != funcStarts.end() && *iFunc < rva)
			{
				mTable.insert({ *iFunc, *iFunc + 1 }, mTable.end());
				++iFunc;
			}
		};
		for (auto& seh : binary.sehEntries())
		{
			// TODO: ignore if this entry covers catch block of other function?.. it has a ref to the middle of other func
			insertFuncsUpTo(seh.begin);
			mTable.insert({ seh.begin, seh.end, {}, { {}, &seh } }, mTable.end());
			if (iFunc != funcStarts.end() && *iFunc == seh.begin)
				++iFunc;
		}
		insertFuncsUpTo(std::numeric_limits<rva_t>::max());
	}

	// analyze single function that is assumed to be never analyzed before
	// all the exception handlers are also analyzed automatically (but not stuff they call)
	FunctionData& analyze(rva_t rva, std::string_view name, auto&& analyzeFunc)
	{
		auto [existing, isNew] = getOrCreateEntry(rva);
		ensure(existing->name.empty() && !existing->value.analyzed); // should never have been analyzed before
		logger(LogLevel::Verbose, "Processing {} function '{}' at {:X}...", isNew ? "new" : "known", name, rva);
		mTable.edit(existing).name = name;
		auto& res = *(mTable.edit(existing).value.analyzed = std::make_unique<FunctionData>());
		auto next = existing + 1;
		auto seh = existing->value.seh;
		res = analyzeFunc(mFBA, rva, seh ? seh->end : next != mTable.end() ? next->begin : mTextEnd, existing->value.extraEntryPoints);
		auto limit = seh ? seh->end : res.end();
		if (existing->value.type == FunctionType::SEHFilter && limit == res.end() + 1)
		{
			// TODO: for whatever reason, some SEH filters have SEH entry covering one byte more than is real...
			--limit;
			__debugbreak();
		}
		mPatcher.patchFunction(res, limit);
		res.refs = analysis::getSimpleRefs(res.instructions);
		if (res.end() > existing->end)
			mTable.extend(existing->end, res.end(), next);
		return res;
	}

	auto& analyze(rva_t rva, std::string_view name)
	{
		return analyze(rva, name, [&](analysis::FunctionBlockAnalysis<FunctionData>& analyzer, rva_t begin, rva_t limit, std::span<const rva_t> extraBlocks) {
			analyzer.start(begin, limit);
			analyzer.scheduleAndAnalyze(begin);
			for (auto rva : extraBlocks)
				analyzer.scheduleAndAnalyze(rva);
			return analyzer.finish();
		});
	}

	void analyzeSEHHandlers()
	{
		std::vector<rva_t> handlerRVAs;
		for (auto& seh : mBinary.sehEntries())
			if (seh.value.rva && !std::ranges::contains(handlerRVAs, seh.value.rva))
				handlerRVAs.push_back(seh.value.rva);
		ensure(handlerRVAs.size() == 4); // these are all library ones - note that SC2 doesn't have the __GSHandlerCheck_SEH variant...
		auto handlers = handlerRVAs | std::views::transform([&](rva_t rva) -> auto& { return analyze(rva, ""); }) | std::ranges::to<std::vector<std::reference_wrapper<FunctionData>>>();
		// heuristics to classify handlers...
		for (FunctionData& handler : handlers)
		{
			switch (handler.refs.size())
			{
			case 1:
				// this one simply calls __GSHandlerCheckCommon
				logger(LogLevel::Important, "SEH handler at {:X} = __GSHandlerCheck", handler.begin());
				break;
			case 2:
				// this one calls __GSHandlerCheckCommon and __CxxFrameHandler3
				ensure(std::ranges::contains(handlerRVAs, handler.refs[1].ref));
				mGSHandlerCheckEH = handler.begin();
				logger(LogLevel::Important, "SEH handler at {:X} = __GSHandlerCheck_EH", handler.begin());
				break;
			case 4:
				// this one calls __vcrt_getptd 3x and then __InternalCxxFrameHandler
				ensure(handler.refs[1].ref == handler.refs[0].ref && handler.refs[2].ref == handler.refs[0].ref);
				mCxxFrameHandler = handler.begin();
				logger(LogLevel::Important, "SEH handler at {:X} = __CxxFrameHandler3", handler.begin());
				break;
			case 8:
				// this one calls a whole lot of shit
				mCSpecificHandler = handler.begin();
				logger(LogLevel::Important, "SEH handler at {:X} = __C_specific_handler", handler.begin());
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

			auto& parentFunc = editExisting(seh.begin);
			ensure(!parentFunc.analyzed && parentFunc.extraEntryPoints.empty() && parentFunc.exceptionHandlers.empty());
			parentFunc.extraEntryPoints = std::move(extraBlocks);
			parentFunc.exceptionHandlers = std::move(externalFuncs);
			ensure(extraBlocks.empty() && externalFuncs.empty());
		}
	}

	void analyzeAllRemaining()
	{
		std::vector<rva_t> pending, nextIteration;
		pending.reserve(mTable.size());
		for (auto& func : mTable)
			if (!func.value.analyzed)
				pending.push_back(func.begin);
		int iPass = 0;
		while (!pending.empty())
		{
			logger(LogLevel::Important, "Analyzing remaining functions: pass {}, {} functions remaining", ++iPass, pending.size());
			for (size_t iFunc = 0; iFunc < pending.size(); ++iFunc)
			{
				auto [entry, isNew] = getOrCreateEntry(pending[iFunc]);
				ensure(!isNew && !entry->value.analyzed);
				auto needDefer = std::ranges::any_of(entry->value.exceptionHandlers, [&](rva_t secondary) {
					auto e = ensure(mTable.find(secondary));
					return !e->value.analyzed && e->value.type == FunctionType::CatchBlock; // catch blocks need to be analyzed first, as they have extra block refs for parent func
				});
				if (needDefer)
				{
					nextIteration.push_back(pending[iFunc]);
					continue;
				}

				auto& func = analyze(pending[iFunc], "");
				auto refs = std::span(func.refs);
				if (entry->value.type == FunctionType::CatchBlock)
				{
					ensure(!func.refs.empty() && func.refs.back().ins->ops[0] == x86::Reg::rax);
					auto& parent = editExisting(entry->value.parent);
					ensure(!parent.analyzed);
					parent.extraEntryPoints.push_back(func.refs.back().ref);
					refs = refs.subspan(0, func.refs.size() - 1);
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
		auto next = mTable.findNext(rva);
		auto existing = mTable.getPrevIfContains(next, rva);
		auto isNew = existing == mTable.end();
		if (isNew)
			existing = mTable.insert({ rva, rva + 1 }, next);
		ensure(existing->begin == rva);
		return std::make_pair(existing, isNew);
	}

	auto markAsSecondary(rva_t rva, FunctionType type, rva_t parent)
	{
		auto& e = mTable.edit(getOrCreateEntry(rva).first);
		ensure(!e.value.analyzed);
		e.value.type = type;
		e.value.parent = parent;
	}

	auto& editExisting(rva_t rva)
	{
		auto iter = mTable.getPrevIfContains(mTable.findNext(rva), rva);
		ensure(iter != mTable.end() && iter->begin == rva);
		return mTable.edit(iter).value;
	}

private:
	PEBinary& mBinary;
	analysis::FunctionBlockAnalysis<FunctionData> mFBA;
	rva_t mTextBegin;
	rva_t mTextEnd;
	Patcher& mPatcher;
	Entries mTable;
	// SEH top level handlers
	rva_t mCSpecificHandler = 0;
	rva_t mCxxFrameHandler = 0;
	rva_t mGSHandlerCheckEH = 0;
};

