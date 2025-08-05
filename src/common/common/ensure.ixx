module;

#include <common/win_headers.h>

export module common:ensure;

import std;

export template<typename T> T&& ensure(T&& condition)
{
	if (!condition)
	{
		const auto error = GetLastError();
		__debugbreak();
	}
	return std::forward<T>(condition);
}
