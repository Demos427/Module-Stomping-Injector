// Made by Krypt :D helped by p1stn :D
#pragma once
#include <Windows.h>
#include <Psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include "nthelper.hpp"
#include "helper.hpp"
#include <iostream>
#include <cstdio>
#include <cstdarg>

inline void kcon_emit(WORD attr, const char* fmt, va_list ap) {
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, ap);
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(h, attr);
    std::cout << buf << std::endl;
    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}
inline void con_ok(const char* fmt, ...)   { va_list ap; va_start(ap, fmt); kcon_emit(FOREGROUND_GREEN | FOREGROUND_INTENSITY, fmt, ap); va_end(ap); }
inline void con_fail(const char* fmt, ...) { va_list ap; va_start(ap, fmt); kcon_emit(FOREGROUND_RED   | FOREGROUND_INTENSITY, fmt, ap); va_end(ap); }
inline void con_info(const char* fmt, ...) { va_list ap; va_start(ap, fmt); kcon_emit(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY, fmt, ap); va_end(ap); }

inline void* conv_a(const void* a, const void* o, const void* n) {
    return (void*)((uintptr_t)a - (uintptr_t)o + (uintptr_t)n);
}
inline bool alloc_r(HANDLE p, const MODULEINFO& l, void*& r) {
    r = VirtualAllocEx(p, nullptr, l.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
+   if (!r) return false;
+   if (!nt_wvm(p, r, l.lpBaseOfDll, l.SizeOfImage)) {
+       VirtualFreeEx(p, r, 0, MEM_RELEASE);
+       return false;
+   }
+   DWORD old = 0;
+   VirtualProtectEx(p, r, l.SizeOfImage, PAGE_EXECUTE_READ, &old);
+   return true;
}
inline MODULEINFO get_r_m(HANDLE p, const char* n) {
    HMODULE m[1024];
    DWORD c;
    if (EnumProcessModulesEx(p, m, sizeof(m), &c, LIST_MODULES_ALL)) {
        for (unsigned int i = 0; i < c / sizeof(HMODULE); i++) {
            char b[MAX_PATH];
            if (GetModuleBaseNameA(p, m[i], b, sizeof(b))) {
                if (_stricmp(b, n) == 0) {
                    MODULEINFO f{};
                    GetModuleInformation(p, m[i], &f, sizeof(f));
                    return f;
                }
            }
        }
    }
    return { nullptr, 0, nullptr };
}
inline MODULEINFO get_l_m() {
    MODULEINFO i{};
    HMODULE m = GetModuleHandleA(nullptr);
    if (m) GetModuleInformation(GetCurrentProcess(), m, &i, sizeof(i));
    return i;
}
inline uintptr_t read_f(const char* p) {
    HANDLE h = CreateFileA(p, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;
    int s = GetFileSize(h, 0);
    PVOID b = VirtualAlloc(0, s, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    DWORD rd_n = 0;
    if (!b || !ReadFile(h, b, s, &rd_n, nullptr) || *(WORD*)(b) != IMAGE_DOS_SIGNATURE) {
        CloseHandle(h);
        VirtualFree(b, 0, MEM_RELEASE);
        return 0;
    }
    CloseHandle(h);
    return (uintptr_t)b;
}
inline PIMAGE_NT_HEADERS get_h(uintptr_t b) {
    return (PIMAGE_NT_HEADERS)(b + ((PIMAGE_DOS_HEADER)b)->e_lfanew);
}
inline HWND h_out;
inline BOOL CALLBACK enum_w(HWND h, LPARAM l) {
    DWORD p;
    GetWindowThreadProcessId(h, &p);
    if (p == (DWORD)l) {
        h_out = h;
        return FALSE;
    }
    return TRUE;
}
inline HWND get_w(int p) {
    EnumWindows(enum_w, (LPARAM)p);
    return h_out;
}
