module;

#include <common/win_headers.h>

export module injected.logger;

import std;
import common;

export class Log
{
public:
	explicit operator bool() const { return !!mPipe; }

	template<typename... Args>
	static void msg(std::format_string<Args...> fmt, Args&&... args)
	{
		if (auto& inst = instance())
		{
			auto res = std::format_to_n(inst.mBuffer, sizeof(inst.mBuffer) - 1, fmt, std::forward<Args>(args)...);
			*res.out = 0;
			inst.logRaw(res.size);
		}
	}

	static void stack()
	{
		if (auto& inst = instance())
		{
			void* stack[128];
			auto numFrames = CaptureStackBackTrace(0, ARRAYSIZE(stack), stack, nullptr);
			for (int i = 0; i < numFrames; ++i)
			{
				auto mi = Process::queryMemoryInfoFor(stack[i]);
				char buf[1024];
				auto fnLen = GetModuleFileNameA((HMODULE)mi.AllocationBase, buf, sizeof(buf));
				msg("> [{}] 0x{:016X} ({} + {:#x})", i, reinterpret_cast<u64>(stack[i]), std::string_view{ buf, fnLen }, static_cast<char*>(stack[i]) - static_cast<char*>(mi.AllocationBase));
			}
		}
	}

	static void exception(const char* tag, EXCEPTION_POINTERS* info)
	{
		msg("{}: {:08X} @ {} (thread {})", tag, info->ExceptionRecord->ExceptionCode, info->ExceptionRecord->ExceptionAddress, GetCurrentThreadId());
		for (auto i = 0; i < info->ExceptionRecord->NumberParameters; ++i)
			msg("param [{}]: {:016X}", i, info->ExceptionRecord->ExceptionInformation[i]);
		msg("rax: {:016X}, rcx: {:016X}, rdx: {:016X}, rbx: {:016X}, rsp: {:016X}, rbp: {:016X}, rsi: {:016X}, rdi: {:016X}",
			info->ContextRecord->Rax, info->ContextRecord->Rcx, info->ContextRecord->Rdx, info->ContextRecord->Rbx, info->ContextRecord->Rsp, info->ContextRecord->Rbp, info->ContextRecord->Rsi, info->ContextRecord->Rdi);
		msg(" r8: {:016X},  r9: {:016X}, r10: {:016X}, r11: {:016X}, r12: {:016X}, r13: {:016X}, r14: {:016X}, r15: {:016X}",
			info->ContextRecord->R8, info->ContextRecord->R9, info->ContextRecord->R10, info->ContextRecord->R11, info->ContextRecord->R12, info->ContextRecord->R13, info->ContextRecord->R14, info->ContextRecord->R15);
		stack();
	}

	static void dump(void* address, u64 size)
	{
		if (auto& inst = instance())
		{
			auto p = inst.mBuffer;
			auto dump = [&](bool cond) {
				if (cond && p != inst.mBuffer)
				{
					*p = 0;
					inst.logRaw(p - inst.mBuffer);
					p = inst.mBuffer;
				}
			};
			for (u64 i = 0; i < size; ++i)
			{
				dump((i & 0xF) == 0);
				p = std::format_to(p, "{:02X} ", reinterpret_cast<unsigned char*>(address)[i]);
			}
			dump(true);
		}
	}

private:
	static Log& instance()
	{
		static Log inst;
		return inst;
	}

	Log() : mPipe(R"(\\.\pipe\sc2rtwp_log)") {}

	void logRaw(size_t len)
	{
		if (len > 0)
			mPipe.write({ mBuffer, len + 1 });
	}

private:
	PipeClient mPipe;
	char mBuffer[4096];
};
