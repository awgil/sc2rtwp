export module unpack.function_table;

export import unpack.analysis.function_block;
export import unpack.analysis.simple_refs;
export import unpack.range_map;
export import unpack.pe_binary;
export import unpack.patcher;

export struct FunctionData : analysis::Function
{
	std::vector<analysis::Reference> refs;
	std::vector<rva_t> exceptionHandlers; // note: external functions (eg. SEH filters)
};

export struct FunctionTableEntryInfo
{
	std::unique_ptr<FunctionData> analyzed; // TODO: this is annoying - we really need to support analyzing new functions recursively though, meaning either this or diffent container that doesn't invalidate iterators...
	const SEHInfo::Entry* seh = nullptr;
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
				std::println("Skipping weird reloc: {:X} -> {:X}", reloc, rva);
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
			insertFuncsUpTo(seh.begin);
			mTable.insert({ seh.begin, seh.end, {}, { {}, &seh } }, mTable.end());
			if (iFunc != funcStarts.end() && *iFunc == seh.begin)
				++iFunc;
		}
		insertFuncsUpTo(std::numeric_limits<rva_t>::max());
	}

	// analyze single function that is assumed to be never analyzed before
	// all the exception handlers are also analyzed automatically (but not stuff they call)
	FunctionData& analyze(rva_t rva, std::string_view name, auto&& analyzeFunc, bool allowExisting = false)
	{
		ensure(rva >= mTextBegin && rva < mTextEnd);
		auto next = mTable.findNext(rva);
		auto existing = mTable.getPrevIfContains(next, rva);
		auto isNew = existing == mTable.end();
		if (isNew)
		{
			existing = mTable.insert({ rva, rva + 1 }, next);
			next = existing + 1;
		}
		if (allowExisting && existing->value.analyzed)
			return *existing->value.analyzed;
		ensure(existing->name.empty() && !existing->value.analyzed); // should never have been analyzed before
		ensure(existing->begin == rva); // should not start from the middle of the function
		mTable.edit(existing).name = name;
		auto& res = *(mTable.edit(existing).value.analyzed = std::make_unique<FunctionData>());

		// before analyzing the function itself, we need to analyze exception related functions - they might refer to blocks that are otherwise unreachable
		std::vector<rva_t> extraBlocks, externalFuncs;
		auto seh = existing->value.seh;
		if (seh && seh->value.rva)
		{
			if (seh->value.rva == mCSpecificHandler)
			{
				for (auto& scope : seh->value.scopeRecords())
				{
					if (scope.HandlerAddress > 1) // try-except filter and try-finally finally blocks are separate functions
						externalFuncs.push_back(scope.HandlerAddress);
					if (scope.JumpTarget) // try-except block has except body in function
						extraBlocks.push_back(scope.JumpTarget);
				}
			}
			else if (seh->value.rva == mCxxFrameHandler || seh->value.rva == mGSHandlerCheckEH)
			{
				// TODO: consider adding unwind funclets as functions; there are tons of them and they are all trivial (usually tail-recursion jump), so not sure there's a point...
				for (auto& tryBlock : seh->value.tryBlocks(mBinary))
				{
					for (auto& catchBlock : seh->value.catchBlocks(mBinary, tryBlock))
					{
						// catch blocks are implemented as separate functions that return external block address
						externalFuncs.push_back(catchBlock.dispOfHandler);
					}
				}
			}
		}

		for (int i = 0; auto handler : externalFuncs)
		{
			auto& external = analyze(handler, name.empty() ? "" : std::format("{}_seh{}", name, i++), true);
			if (!external.refs.empty() && external.refs.back().ref >= rva && external.refs.back().ref < seh->end)
			{
				ensure(external.refs.back().ins->ops[0] == x86::Reg::rax);
				extraBlocks.push_back(external.refs.back().ref);
			}
		}
		if (!externalFuncs.empty())
		{
			// we could have added new functions, so we need to re-fetch iterators
			next = mTable.findNext(rva);
			existing = next - 1;
			ensure(existing->begin == rva);
		}

		std::println("Processing {} function '{}' at {:X}...", isNew ? "new" : "known", name, rva);
		res = analyzeFunc(mFBA, rva, seh ? seh->end : next != mTable.end() ? next->begin : mTextEnd, extraBlocks);
		mPatcher.patchFunction(res, seh ? seh->end : 0);
		res.refs = analysis::getSimpleRefs(res.instructions);
		res.exceptionHandlers = std::move(externalFuncs);
		if (res.end() > existing->end)
			mTable.extend(existing->end, res.end(), next);
		return res;
	}

	auto& analyze(rva_t rva, std::string_view name, bool allowExisting = false)
	{
		return analyze(rva, name, [&](analysis::FunctionBlockAnalysis<FunctionData>& analyzer, rva_t begin, rva_t limit, std::span<const rva_t> extraBlocks) {
			analyzer.start(begin, limit);
			analyzer.scheduleAndAnalyze(begin);
			for (auto rva : extraBlocks)
				analyzer.scheduleAndAnalyze(rva);
			return analyzer.finish();
		}, allowExisting);
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
				std::println("SEH handler at {:X} = __GSHandlerCheck", handler.begin());
				break;
			case 2:
				// this one calls __GSHandlerCheckCommon and __CxxFrameHandler3
				ensure(std::ranges::contains(handlerRVAs, handler.refs[1].ref));
				mGSHandlerCheckEH = handler.begin();
				std::println("SEH handler at {:X} = __GSHandlerCheck_EH", handler.begin());
				break;
			case 4:
				// this one calls __vcrt_getptd 3x and then __InternalCxxFrameHandler
				ensure(handler.refs[1].ref == handler.refs[0].ref && handler.refs[2].ref == handler.refs[0].ref);
				mCxxFrameHandler = handler.begin();
				std::println("SEH handler at {:X} = __CxxFrameHandler3", handler.begin());
				break;
			case 8:
				// this one calls a whole lot of shit
				mCSpecificHandler = handler.begin();
				std::println("SEH handler at {:X} = __C_specific_handler", handler.begin());
				break;
			default:
				__debugbreak();
			}
		}
	}

	const auto& entries() const { return mTable; }

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

