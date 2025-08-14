module;

#include <common/win_headers.h>

export module injected.debug.veh;

import std;
import common;
import injected.logger;
import injected.app;

// debug utility that registers a veh callback and monitors any exceptions
// in addition, it provides a makeshift memory breakpoint utility (implemented by setting page protections)
// it doesn't really work well if multiple pages can access same page concurrently, but oh well
// TODO: consider just using HW bp's and patching antidebug checks for them
// TODO: support read bps?
// TODO: support normal execution bps?
export class DebugVEH
{
public:
	static DebugVEH& instance()
	{
		static DebugVEH inst;
		return inst;
	}

	void install()
	{
		if (mHandle)
			uninstall();
		mHandle = AddVectoredExceptionHandler(true, vehHandler);
	}

	void uninstall()
	{
		if (!mHandle)
			return;
		RemoveVectoredExceptionHandler(mHandle);
		mHandle = nullptr;
	}

	void setWriteBreakpoint(void* address, std::function<void(void*)>&& callback)
	{
		auto addr = reinterpret_cast<u64>(address);
		Log::msg("Setting breakpoint at 0x{:016X}", addr);
		auto pageStart = roundToPage(addr);
		auto [it, newPage] = mWriteBPs.emplace(pageStart, Page{});
		if (newPage)
		{
			it->second.originalProtection = protectPage(pageStart, PAGE_READONLY);
		}
		it->second.breakpoints.push_back({ addr, std::move(callback) });
	}

private:
	struct Breakpoint
	{
		u64 address;
		std::function<void(void*)> callback;
	};

	struct Page
	{
		u32 originalProtection;
		std::vector<Breakpoint> breakpoints;
	};

	static u64 roundToPage(u64 ptr)
	{
		return ptr & ~0xFFF;
	}

	static u32 protectPage(u64 address, u32 protection)
	{
		return Process::protectMemoryFor(reinterpret_cast<void*>(address), protection);
	}

	bool handleAV(bool write, u64 address)
	{
		if (!write)
			return false;
		auto pageStart = roundToPage(address);
		auto it = mWriteBPs.find(pageStart);
		if (it == mWriteBPs.end())
			return false;

		//bool relevant = std::ranges::any_of(it->second.breakpoints, [address](const auto& bp) { return bp.address == address; });
		//Log::msg("Write breakpoint: {}", relevant ? "watched" : "irrelevant");
		mExpectedSingleSteps[GetCurrentThreadId()] = address;
		protectPage(pageStart, PAGE_READWRITE);
		install(); // reinstall VEH handler to ensure it's called first for single-step
		return true;
	}

	bool handleSingleStep()
	{
		auto itSS = mExpectedSingleSteps.find(GetCurrentThreadId());
		if (itSS == mExpectedSingleSteps.end())
			return false;

		auto address = itSS->second;
		auto pageStart = roundToPage(address);
		protectPage(pageStart, PAGE_READONLY);
		mExpectedSingleSteps.erase(itSS);

		auto itBP = mWriteBPs.find(pageStart);
		if (itBP == mWriteBPs.end())
			return false; // should not happen?..

		//bool relevant = std::ranges::any_of(itBP->second.breakpoints, [address](const auto& bp) { return bp.address == address; });
		//Log::msg("Expected single-step: {}", relevant ? "watched" : "irrelevant");
		for (auto& bp : itBP->second.breakpoints)
			if (bp.address == address)
				bp.callback(reinterpret_cast<void*>(address));
		return true;
	}

	static bool isKnownHarmlessUD2Address(i64 rva)
	{
		return rva == 0x154a6af // this one checks whether any bits in dr7 are set
			|| rva == 0x20eb06; // this one is done by TLS callback for any new threads
	}

	static LONG vehHandler(_EXCEPTION_POINTERS* ExceptionInfo)
	{
		switch (ExceptionInfo->ExceptionRecord->ExceptionCode)
		{
		case EXCEPTION_SINGLE_STEP:
			if (instance().handleSingleStep())
			{
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else
			{
				Log::exception("veh single-step", ExceptionInfo);
				return EXCEPTION_CONTINUE_SEARCH;
			}
		case EXCEPTION_ACCESS_VIOLATION:
		{
			auto rw = ExceptionInfo->ExceptionRecord->ExceptionInformation[0];
			auto addr = ExceptionInfo->ExceptionRecord->ExceptionInformation[1];
			if (instance().handleAV(rw == 1, addr))
			{
				ExceptionInfo->ContextRecord->EFlags |= 0x100; // enable single-step
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else
			{
				Log::exception("veh av", ExceptionInfo);
				return EXCEPTION_CONTINUE_SEARCH;
			}
		}
		case EXCEPTION_ILLEGAL_INSTRUCTION:
			// ignore if coming from one of the known-harmless places
			if (!isKnownHarmlessUD2Address(reinterpret_cast<char*>(ExceptionInfo->ExceptionRecord->ExceptionAddress) - App::instance().imagebase()))
			{
				Log::exception("veh", ExceptionInfo);
			}
			return EXCEPTION_CONTINUE_SEARCH;
		case EXCEPTION_BREAKPOINT:
			return EXCEPTION_CONTINUE_SEARCH; // this happens routinely with antidebug, not interesting
		default:
			Log::exception("veh", ExceptionInfo);
			return EXCEPTION_CONTINUE_SEARCH;
		}
	}

private:
	void* mHandle = nullptr;
	std::unordered_map<u64, Page> mWriteBPs;
	std::unordered_map<u32, u64> mExpectedSingleSteps;
};
