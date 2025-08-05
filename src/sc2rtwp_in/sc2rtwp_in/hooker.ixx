module;

#include <common/win_headers.h>

export module injected.hooker;

import common;
import injected.logger;

// leaks memory, but that's fine, unhooking is hard
export class Hooker
{
public:
	char* alloc(size_t size)
	{
		if (m_free + size > m_limit)
		{
			m_free = static_cast<char*>(VirtualMemoryBlock(65536, PAGE_EXECUTE_READWRITE).leak());
			m_limit = m_free + 65536;
		}
		auto ptr = m_free;
		m_free = ptr + size;
		return ptr;
	}

	// relocLen has to be >= 14
	template<typename T> T* hook(char* func, size_t relocLen, T* detour)
	{
		auto* original = alloc(relocLen + 6 + 8); // jmp [rip+0] + ptr
		memcpy(original, func, relocLen);
		*reinterpret_cast<u16*>(original + relocLen) = 0x25FF;
		*reinterpret_cast<u32*>(original + relocLen + 2) = 0;
		*reinterpret_cast<char**>(original + relocLen + 6) = func + relocLen;
		*reinterpret_cast<u16*>(func) = 0x25FF;
		*reinterpret_cast<u32*>(func + 2) = 0;
		*reinterpret_cast<void**>(func + 6) = detour;
		return reinterpret_cast<T*>(original);
	}

	static void patchJumpToUnconditional(char* address)
	{
		if ((address[0] & 0xF0) == 0x70)
		{
			// near
			address[0] = 0xEB;
		}
		else if (address[0] == 0x0F && (address[1] & 0xF0) == 0x80)
		{
			address[0] = 0x90;
			address[1] = 0xE9;
		}
		else
		{
			Logger::log("Failed to patch jump at {}: {:02X}", address, address[0]);
		}
	}

private:
	char* m_free = nullptr;
	char* m_limit = nullptr;
};
