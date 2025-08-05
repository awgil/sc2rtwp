module common:requery;

import std;

// there's a common pattern in win32 api: when a function might want to fill a buffer, and the size is not known beforehand,
// the user is expected to call a function with some initial buffer size (potentially zero), read the actual number, and retry
// we wrap this in a 'requery' pattern
// functor is expected to accept std::span<T> and return number of filled elements (<= size) on success or span size for retry (> size)
template<typename T, typename Fn> std::vector<T> requery(size_t initial, Fn&& func)
{
	std::vector<T> result(initial);
	while (true)
	{
		size_t count = func(result);
		if (count <= result.size())
		{
			result.resize(count);
			break;
		}
		result.resize(count);
	}
	return result;
}
