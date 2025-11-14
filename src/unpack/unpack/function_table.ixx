export module unpack.function_table;

export import unpack.analysis.function_block;
export import unpack.analysis.simple_refs;
export import unpack.range_map;
export import unpack.pe_binary;
export import unpack.patcher;

export struct FunctionData : analysis::Function
{
	std::vector<analysis::Reference> refs;
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
		: mFBA(binary.bytes())
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
	auto& analyze(rva_t rva, std::string_view name, auto&& analyzeFunc)
	{
		ensure(rva >= mTextBegin && rva < mTextEnd);
		auto next = mTable.findNext(rva);
		auto existing = mTable.getPrevIfContains(next, rva);
		std::println("Processing {} function '{}' at {:X}...", existing == mTable.end() ? "new" : "known", name, rva);
		if (existing == mTable.end())
		{
			existing = mTable.insert({ rva, rva + 1 }, next);
			next = existing + 1;
		}

		ensure(existing->name.empty() && !existing->value.analyzed); // should never have been analyzed before
		ensure(existing->begin == rva); // should not start from the middle of the function
		mTable.edit(existing).name = name;
		auto& res = *(mTable.edit(existing).value.analyzed = std::make_unique<FunctionData>());
		auto seh = existing->value.seh;
		res = analyzeFunc(mFBA, rva, seh ? seh->end : next != mTable.end() ? next->begin : mTextEnd, seh);
		mPatcher.patchFunction(res, seh ? seh->end : 0);
		res.refs = analysis::getSimpleRefs(res.instructions);
		// add references to SEH filters
		if (mPrimarySEHHandler && seh && seh->value.rva == mPrimarySEHHandler)
			for (auto& scope : seh->value.scopeRecords())
				if (scope.HandlerAddress > 1)
					res.refs.push_back({ nullptr, 0, static_cast<rva_t>(scope.HandlerAddress) });
		if (res.end() > existing->end)
			mTable.extend(existing->end, res.end(), next);
		return res;
	}

	auto& analyze(rva_t rva, std::string_view name)
	{
		return analyze(rva, name, [&](analysis::FunctionBlockAnalysis<FunctionData>& analyzer, rva_t begin, rva_t limit, const SEHInfo::Entry* seh) {
			analyzer.start(begin, limit);
			analyzer.scheduleAndAnalyze(begin);
			if (mPrimarySEHHandler && seh && seh->value.rva == mPrimarySEHHandler)
			{
				for (auto& scope : seh->value.scopeRecords())
				{
					if (scope.JumpTarget)
					{
						analyzer.scheduleAndAnalyze(scope.JumpTarget);
					}
					// else: null for finally blocks
				}
			}
			return analyzer.finish();
		});
	}

	void analyzeSEHHandlers(PEBinary& binary)
	{
		std::vector<rva_t> handlers;
		for (auto& seh : binary.sehEntries())
			if (seh.value.rva && !std::ranges::contains(handlers, seh.value.rva))
				handlers.push_back(seh.value.rva);
		ensure(handlers.size() == 4); // these are all library ones; we care about one with >4 calls
		for (auto rva : handlers)
		{
			auto& handler = analyze(rva, "");
			auto isPrimary = handler.refs.size() > 4;
			std::println("Found {} SEH handler: {:X}", isPrimary ? "primary" : "secondary", rva);
			if (isPrimary)
			{
				ensure(!mPrimarySEHHandler);
				mPrimarySEHHandler = rva;
			}
		}
	}

	const auto& entries() const { return mTable; }

private:
	analysis::FunctionBlockAnalysis<FunctionData> mFBA;
	rva_t mTextBegin;
	rva_t mTextEnd;
	Patcher& mPatcher;
	Entries mTable;
	rva_t mPrimarySEHHandler = 0; // IDA calls it __C_specific_handler
};

