// Made by Krypt :D
#include <Windows.h>
#include <thread>
#include <iostream>

#pragma once
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
inline HMODULE n;
static void init_nt() { n = GetModuleHandleA("ntdll.dll"); }
#define MF(N, M) ((ULONG_PTR (*)(...))GetProcAddress(M, N))
#define NtF(N) MF(N, n)
#define NT_SUCCESS(S) ((NTSTATUS)(S) >= 0)
namespace ntdll {
    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemProcessInformation = 5
    } SYSTEM_INFORMATION_CLASS;

    typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
        HANDLE HandleValue;
        ULONG_PTR NamePointer;
        ULONG_PTR TypePointer;
        ULONG HandleAttributes;
        ULONG GrantedAccess;
        ULONG_PTR Object;
    } PROCESS_HANDLE_TABLE_ENTRY_INFO;

    typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
        PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
    } PROCESS_HANDLE_SNAPSHOT_INFORMATION;

    typedef struct _TP_TASK_CALLBACKS {
        PVOID ExecuteCallback;
        PVOID Unposted;
    } TP_TASK_CALLBACKS;

    typedef struct _TP_TASK {
        TP_TASK_CALLBACKS* Callbacks;
        UINT32 NumaNode;
        UINT8 IdealProcessor;
        UINT8 Padding[3];
        LIST_ENTRY ListEntry;
    } TP_TASK;

    typedef NTSTATUS(NTAPI* PFN_NtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    typedef NTSTATUS(NTAPI* PFN_NtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS(NTAPI* PFN_NtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS(NTAPI* PFN_NtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
    typedef NTSTATUS(NTAPI* PFN_NtCreateSection)(PHANDLE, ULONG, PVOID, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
    typedef NTSTATUS(NTAPI* PFN_NtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
}

extern "C" {
    NTSTATUS NTAPI NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesRead);
    NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten);
    NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);
    NTSTATUS NTAPI NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
    NTSTATUS NTAPI NtMapViewOfSection(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
    NTSTATUS NTAPI NtCreateSection(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
}

inline bool nt_rvm(HANDLE h, PVOID base, PVOID buffer, SIZE_T size, SIZE_T* transferred = nullptr, NTSTATUS* pstatus = nullptr) {
    SIZE_T n = 0;
    NTSTATUS st = NtReadVirtualMemory(h, base, buffer, size, &n);
    if (pstatus) *pstatus = st;
    if (transferred) *transferred = n;
    return NT_SUCCESS(st) && n == size;
}

inline bool nt_wvm(HANDLE h, PVOID base, const void* buffer, SIZE_T size, SIZE_T* transferred = nullptr, NTSTATUS* pstatus = nullptr) {
    SIZE_T n = 0;
    NTSTATUS st = NtWriteVirtualMemory(h, base, const_cast<PVOID>(buffer), size, &n);
    if (pstatus) *pstatus = st;
    if (transferred) *transferred = n;
    return NT_SUCCESS(st) && n == size;
}

extern "C" NTSTATUS NTAPI ZwUnmapViewOfSection(HANDLE, PVOID);
