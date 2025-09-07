export module unpack.range_map;

import std;
import common;

// Entry type should have at fields 'begin' and 'end' at least (and can have optional payload)
export template<typename K> struct RangeMapEntry
{
	using Key = K;

	K begin;
	K end;

	bool contains(const K& key) const { return key >= begin && key < end; }
};

// a sorted list of non-intersecting ranges
// argument should be derived from RangeMapEntry
export template<typename E> class RangeMap
{
public:
	using Entry = E;
	using Key = typename Entry::Key;
	static_assert(std::is_base_of_v<RangeMapEntry<Key>, Entry>);

	auto begin() const { return mEntries.begin(); }
	auto end() const { return mEntries.end(); }
	auto size() const { return mEntries.size(); }
	auto empty() const { return mEntries.empty(); }
	auto& front() const { return mEntries.front(); }
	auto& back() const { return mEntries.back(); }
	void clear() { mEntries.clear(); }
	auto& operator[](size_t i) const { return mEntries[i]; }

	// return mutable reference to the entry iterator points to; note that begin/end should not be modified, to ensure invariant is preserved
	auto& edit(auto iter) { return mEntries[iter - begin()]; }

	// find iterator pointing to next entry - if given key does not belong to any existing entries, this would be an insertion point
	auto findNext(const Key& key) const
	{
		return std::ranges::upper_bound(mEntries, key, std::less(), [](const Entry& e) { return e.begin; });
	}

	// if the iterator (assumed to be returned by findNext) points to the entry right after entry containing the key, return preceeding iterator; otherwise return end()
	auto getPrevIfContains(auto next, const Key& key) const
	{
		if (next == begin())
			return end();
		--next;
		return next->contains(key) ? next : end();
	}

	// find entry containing specified key, return null if not found
	const Entry* find(const Key& key) const
	{
		auto it = getPrevIfContains(findNext(key), key);
		return it != end() ? &*it : nullptr;
	}

	// insert new entry; ensures it does not overlap with anything else
	// if hint is provided, it should point to the next entry
	void insert(Entry&& e, auto hint)
	{
		ensure(e.begin < e.end);
		ensure(hint == mEntries.end() || hint->begin >= e.end);
		ensure(hint == mEntries.begin() || (hint - 1)->end <= e.begin);
		mEntries.emplace(hint, std::move(e));
	}

	void insert(Entry&& e)
	{
		auto next = findNext(e.begin);
		insert(std::move(e), next);
	}

	// extend preceeding entry to include new range
	// gaps are not allowed: added range should start right as entry-to-be-extended ends
	// ensures no overlap is created
	// if specified, hint should be an iterator for next entry (i.e. equal to findNext(begin))
	void extend(const Key& begin, const Key& end, auto hint)
	{
		ensure(begin < end);
		ensure(hint != mEntries.begin()); // should have something to extend
		ensure(hint == mEntries.end() || hint->begin >= end); // should not create overlap
		auto& extended = mEntries[hint - mEntries.begin() - 1];
		ensure(extended.end == begin);
		extended.end = end;
	}
	void extend(const Key& begin, const Key& end) { extend(begin, end, findNext(begin)); }

	// shrink entry pointed by an iterator
	void shrink(const Key& begin, const Key& end, auto iter)
	{
		ensure(begin >= iter->begin);
		ensure(end <= iter->end);
		ensure(begin < end);
		edit(iter).begin = begin;
		edit(iter).end = end;
	}

private:
	std::vector<Entry> mEntries; // invariant: [i].begin < [i].end <= [i+1].begin
};

// simple range map with optional payload
template<typename K, typename V> struct SimpleRangeMapEntry : RangeMapEntry<K>
{
	[[no_unique_address]] V value;
};
export template<typename K, typename V = std::monostate> class SimpleRangeMap : public RangeMap<SimpleRangeMapEntry<K, V>> {};

// range map with named ranges
// has some extra utilities for pretty-printing offsets
template<typename K, typename N, typename V> struct NamedRangeMapEntry : RangeMapEntry<K>
{
	N name;
	[[no_unique_address]] V value;
};
export template<typename K, typename V = std::monostate, typename N = std::string> class NamedRangeMap
	: public RangeMap<NamedRangeMapEntry<K, N, V>>
{
public:
	auto& getByName(std::string_view name) const
	{
		auto it = std::ranges::find_if(*this, [name](const auto& e) { return e.name == name; });
		ensure(it != this->end());
		return *it;
	}

	std::string formatOffset(const K& key, const auto& fallback) const
	{
		auto e = this->find(key);
		return std::format("{} + 0x{:X}", e ? e->name : fallback, key - (e ? e->begin : 0));
	}
};
