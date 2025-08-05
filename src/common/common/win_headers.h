#pragma once

#define WIN32_LEAN_AND_MEAN
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

}
