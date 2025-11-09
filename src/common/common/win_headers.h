#pragma once

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>

extern "C"
{
	typedef long NTSTATUS;

	const NTSTATUS STATUS_SUCCESS = 0x00000000;

	typedef enum _SECTION_INHERIT
	{
		ViewShare = 1,
		ViewUnmap = 2
	} SECTION_INHERIT;

	NTSTATUS __declspec(dllexport) NTAPI NtCreateSection(_Out_ PHANDLE SectionHandle, _In_ ACCESS_MASK DesiredAccess, _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes, _In_opt_ PLARGE_INTEGER MaximumSize,
		_In_ ULONG SectionPageProtection, _In_ ULONG AllocationAttributes, _In_opt_ HANDLE FileHandle);

	NTSTATUS __declspec(dllexport) NTAPI NtMapViewOfSection(_In_ HANDLE SectionHandle, _In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _In_ SIZE_T CommitSize,
		_Inout_opt_ PLARGE_INTEGER SectionOffset, _Inout_ PSIZE_T ViewSize, _In_ SECTION_INHERIT InheritDisposition, _In_ ULONG AllocationType, _In_ ULONG Win32Protect);

	NTSTATUS __declspec(dllexport) NTAPI NtUnmapViewOfSection(_In_ HANDLE ProcessHandle, _In_opt_ PVOID BaseAddress);

	// see https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170
	typedef enum _UNWIND_OP_CODES {
		UWOP_PUSH_NONVOL = 0,	/* info == register number */
		UWOP_ALLOC_LARGE,		/* no info, alloc size in next 2 slots */
		UWOP_ALLOC_SMALL,		/* info == size of allocation / 8 - 1 */
		UWOP_SET_FPREG,			/* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
		UWOP_SAVE_NONVOL,		/* info == register number, offset in next slot */
		UWOP_SAVE_NONVOL_FAR,	/* info == register number, offset in next 2 slots */
		UWOP_SAVE_XMM128 = 8,	/* info == XMM reg number, offset in next slot */
		UWOP_SAVE_XMM128_FAR,	/* info == XMM reg number, offset in next 2 slots */
		UWOP_PUSH_MACHFRAME		/* info == 0: no error-code, 1: error-code */
	} UNWIND_CODE_OPS;

	typedef unsigned char UBYTE;

	typedef union _UNWIND_CODE {
		struct {
			UBYTE CodeOffset;
			UBYTE UnwindOp : 4;
			UBYTE OpInfo : 4;
		};
		USHORT FrameOffset;
	} UNWIND_CODE, *PUNWIND_CODE;

//#define UNW_FLAG_EHANDLER  0x01
//#define UNW_FLAG_UHANDLER  0x02
//#define UNW_FLAG_CHAININFO 0x04

	typedef struct _UNWIND_INFO {
		UBYTE Version : 3;
		UBYTE Flags : 5;
		UBYTE SizeOfProlog;
		UBYTE CountOfCodes;
		UBYTE FrameRegister : 4;
		UBYTE FrameOffset : 4;
		UNWIND_CODE UnwindCode[1];
	/*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
	*   union {
	*	   OPTIONAL ULONG ExceptionHandler;
	*	   OPTIONAL ULONG FunctionEntry;
	*   };
	*   OPTIONAL ULONG ExceptionData[]; */
	} UNWIND_INFO, *PUNWIND_INFO;

//	typedef struct _RUNTIME_FUNCTION {
//		ULONG BeginAddress;
//		ULONG EndAddress;
//		ULONG UnwindData;
//	} RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;
//
//#define GetUnwindCodeEntry(info, index) \
//	((info)->UnwindCode[index])
//
//#define GetLanguageSpecificDataPtr(info) \
//	((PVOID)&GetUnwindCodeEntry((info),((info)->CountOfCodes + 1) & ~1))
//
//#define GetExceptionHandler(base, info) \
//	((PEXCEPTION_HANDLER)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))
//
//#define GetChainedFunctionEntry(base, info) \
//	((PRUNTIME_FUNCTION)((base) + *(PULONG)GetLanguageSpecificDataPtr(info)))
//
//#define GetExceptionDataPtr(info) \
//	((PVOID)((PULONG)GetLanguageSpecificData(info) + 1))
}
