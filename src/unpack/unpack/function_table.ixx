export module unpack.function_table;

export import unpack.analysis.function_block;
export import unpack.range_map;
export import unpack.pe_binary;
export import unpack.patcher;

export struct FunctionTableEntryInfo
{
	analysis::Function analyzed;
	const SEHInfo::Entry* seh = nullptr;
};

// table describing .text layout of the binary
// note: if you call analyze(), you're expected to then add entries for referenced functions too, otherwise analyzeRest() won't pick them up
export class FunctionTable
{
public:
	using Entries = NamedRangeMap<rva_t, FunctionTableEntryInfo>;
	using Entry = Entries::Entry;

	FunctionTable(PEBinary& binary, const PEBinary::Section& text, Patcher& patcher) : mFBA(binary.bytes()), mTextEnd(text.end), mPatcher(patcher)
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

		// TODO: add exports, SEH handlers/filters (this probably would need identifying real handler)

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
		auto next = mTable.findNext(rva);
		auto existing = mTable.getPrevIfContains(next, rva);
		std::println("Processing {} function '{}' at {:X}...", existing == mTable.end() ? "new" : "known", name, rva);
		if (existing == mTable.end())
		{
			existing = mTable.insert({ rva, rva + 1 }, next);
			next = existing + 1;
		}

		ensure(existing->name.empty() && existing->value.analyzed.instructions.empty()); // should never have been analyzed before
		ensure(existing->begin == rva); // should not start from the middle of the function
		mTable.edit(existing).name = name;
		auto& res = mTable.edit(existing).value.analyzed;
		res = analyzeFunc(mFBA, rva, existing->value.seh ? existing->value.seh->end : next != mTable.end() ? next->begin : mTextEnd);
		mPatcher.patchFunction(res, existing->value.seh ? existing->value.seh->end : 0);
		mPatcher.patchHlts(res); // TODO: don't do this here, it's only relevant for a small subset of bootstrap functions...
		if (res.blocks.back().end > existing->end)
			mTable.extend(existing->end, res.blocks.back().end, next);
		return res;
	}

	auto& analyze(rva_t rva, std::string_view name)
	{
		return analyze(rva, name, [](analysis::FunctionBlockAnalysis& analyzer, rva_t begin, rva_t limit) {
			return analyzer.analyze(begin, limit);
		});
	}

private:
	analysis::FunctionBlockAnalysis mFBA;
	rva_t mTextEnd;
	Patcher& mPatcher;
	Entries mTable;
};

