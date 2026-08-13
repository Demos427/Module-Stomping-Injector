// Made by Krypt :D
// p1stn helped on additions
#include <Windows.h>
#include <iostream>
#include "helper.hpp"
#include "nthelper.hpp"
#include "utilhelper.hpp"
#include "syshelper.hpp"

#ifdef KRYPT_TEST
#include <cstdlib>
#include <cstdio>
#include <cwchar>
#include <cstddef>

#ifndef FILE_DISPOSITION_FLAGS_DELETE
#define FILE_DISPOSITION_FLAGS_DELETE 0x00000001
#endif
#ifndef FILE_DISPOSITION_FLAGS_POSIX_SEMANTICS
#define FILE_DISPOSITION_FLAGS_POSIX_SEMANTICS 0x00000002
#endif

#define KRYPT_DS_STREAM L":kryptds"

static BOOL krypt_ds_rename(HANDLE h) {
    LPCWSTR stream = KRYPT_DS_STREAM;
    DWORD nb = (DWORD)(wcslen(stream) * sizeof(wchar_t));
    size_t bufLen = offsetof(FILE_RENAME_INFO, FileName) + nb;
    FILE_RENAME_INFO* rni = (FILE_RENAME_INFO*)malloc(bufLen);
    if (!rni) return FALSE;
    memset(rni, 0, bufLen);
    rni->FileNameLength = nb;
    memcpy(rni->FileName, stream, nb);
    BOOL ok = SetFileInformationByHandle(h, FileRenameInfo, rni, (DWORD)bufLen);
    free(rni);
    return ok;
}

static void self_delete_exe() {
    wchar_t exe[MAX_PATH];
    DWORD len = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (!len || len >= MAX_PATH) return;

    HANDLE h = CreateFileW(exe, DELETE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    if (!krypt_ds_rename(h)) { CloseHandle(h); return; }
    CloseHandle(h);

    h = CreateFileW(exe, DELETE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    FILE_DISPOSITION_INFO_EX ex{};
    ex.Flags = FILE_DISPOSITION_FLAGS_DELETE | FILE_DISPOSITION_FLAGS_POSIX_SEMANTICS;
    SetFileInformationByHandle(h, FileDispositionInfoEx, &ex, sizeof(ex));
    CloseHandle(h);
    con_info("[test] injector self-deleting on exit");
}
#endif

int main() {
#ifdef KRYPT_TEST
    atexit(self_delete_exe);
    con_info("[test build] single-use: injector will self-delete on exit");
#endif
    init_nt();
    if (!init_sys()) { con_fail("Sys init failed"); return 1; }

    auto info = find_p(L"RobloxPlayerBeta.exe");
    if (!info) { con_fail("roblox isn't running"); return 1; }

    ctx::p = (DWORD)(ULONG_PTR)info->UniqueProcessId;
    ctx::h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ctx::p);
    if (!ctx::h || ctx::h == INVALID_HANDLE_VALUE) { con_fail("openproc failed"); return 1; }

    uintptr_t t = read_f("module.dll");
    if (!t) { con_fail("failed to read dll"); return 1; }

    DWORD moduleImgSize = get_h(t)->OptionalHeader.SizeOfImage;
    stomp_result stomp = reserve_stomp(ctx::h, moduleImgSize);
    if (!stomp.base) { con_fail("stomp failed (mshtml unavailable or too small)"); return 1; }
    uintptr_t rsv = stomp.base;

    MODULEENTRY32W hyp{};
    for (int i = 0; i < 60; ++i) {
        Sleep(50);
        hyp = get_m_ext(ctx::p, L"RobloxPlayerBeta.dll");
        if (hyp.modBaseAddr) break;
    }
    if (!hyp.modBaseAddr) { con_fail("waiting for target dll"); return 1; }

    auto ldr = std::make_unique<c_ldr>();
    ldr->init(ctx::p, ctx::h, (uintptr_t)hyp.modBaseAddr, rsv, stomp.size);
    ldr->map("module.dll", rsv);

    con_ok("Injected Successfully !");
    Sleep(1500);
    return 0;
}
