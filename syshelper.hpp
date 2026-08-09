// Made by Krypt :D
// p1stn helped on additions
#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include "nthelper.hpp"
extern "C" {
	extern DWORD idx_rd, idx_wr, idx_al, idx_pr, idx_qs, idx_mv, idx_uv, idx_cs, idx_op, idx_cl;
	extern uintptr_t sys_rd, sys_wr, sys_al, sys_pr, sys_qs, sys_mv, sys_uv, sys_cs, sys_op, sys_cl;
}
inline DWORD get_idx(uintptr_t a) {
	BYTE* b = (BYTE*)a;
	for (int i = 0; i < 32; i++) if (b[i] == 0xb8) return *(DWORD*)(b + i + 1);
	return 0;
}
inline uintptr_t get_off(uintptr_t a) {
	BYTE* d = (BYTE*)a;
	for (int i = 0; i < 256; i++)
		if (d[i] == 0x0f && d[i + 1] == 0x05) return (uintptr_t)i;
	return 0;
}
inline bool init_sys() {
	HMODULE l = GetModuleHandleA("ntdll.dll");
	if (!l) return false;
	auto r = (uintptr_t)GetProcAddress(l, "NtReadVirtualMemory");
	auto w = (uintptr_t)GetProcAddress(l, "NtWriteVirtualMemory");
	auto p = (uintptr_t)GetProcAddress(l, "NtProtectVirtualMemory");
	auto q = (uintptr_t)GetProcAddress(l, "NtQuerySystemInformation");
	auto m = (uintptr_t)GetProcAddress(l, "NtMapViewOfSection");
	auto c = (uintptr_t)GetProcAddress(l, "NtCreateSection");
	if (!r || !w || !p || !q || !m || !c) return false;
	idx_rd = get_idx(r);
	idx_wr = get_idx(w);
	idx_pr = get_idx(p);
	idx_qs = get_idx(q);
	idx_mv = get_idx(m);
	idx_cs = get_idx(c);
	sys_rd = r + get_off(r);
	sys_wr = w + get_off(w);
	sys_pr = p + get_off(p);
	sys_qs = q + get_off(q);
	sys_mv = m + get_off(m);
	sys_cs = c + get_off(c);
	return idx_rd && idx_wr && idx_pr && idx_qs && idx_mv && idx_cs && sys_rd && sys_wr && sys_pr && sys_qs && sys_mv && sys_cs;
}
