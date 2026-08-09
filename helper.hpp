// Made by Krypt :D
// p1stn helped on additions
#pragma once
#include <iostream>
#include <string>
#include <Windows.h>
#include <winternl.h>
#include <cstdint>
#include <memory>
#include <TlHelp32.h>
#include <vector>

#pragma comment(lib, "Psapi.lib")

typedef struct _TLS_ENTRY {
	LIST_ENTRY TlsEntryLinks;
	IMAGE_TLS_DIRECTORY TlsDirectory;
	PVOID ModuleEntry;
	SIZE_T TlsIndex;
} TLS_E, * PTLS_E;
class c_ldr {
private:
	BYTE* tB;
	std::int32_t pI;
	HANDLE rP;
	std::uintptr_t hB;
	std::uintptr_t sB;
	std::uintptr_t stompSz;
	std::uintptr_t stubBase;
	std::uintptr_t tailOff;
	std::uintptr_t tailEnd;
	HANDLE iC;
	std::uintptr_t alloc_tail(SIZE_T size, SIZE_T align);
	void exec_stub(const BYTE* sc, SIZE_T scSize);
public:
	void init(std::int32_t pI, HANDLE rP, std::uintptr_t hB, std::uintptr_t sB, std::uintptr_t stompSz = 0);
	bool res_i(void* tI, IMAGE_NT_HEADERS* nH);
	void map(const std::string& mN, uintptr_t remoteBase);
	void run_remote(void* fn, void* data, size_t size);
};
namespace ctx {
	inline DWORD p;
	inline DWORD t;
	inline HANDLE h;
}
SYSTEM_PROCESS_INFORMATION* find_p(const wchar_t* target);
HMODULE get_m(const std::string& name);
MODULEENTRY32W get_m_ext(DWORD p, const wchar_t* name);
uintptr_t get_e(HANDLE h, DWORD p, const wchar_t* mod, const char* exp);
BOOL set_p(const wchar_t* priv, DWORD attr);
std::vector<BYTE> ext_sc(uintptr_t f);
void rep_sc(std::vector<BYTE>& d, uint64_t s, uint64_t r);
std::string gen_s(int l);
std::string gen_cs(int l, const std::string& f = {});
bool wr(uintptr_t a, const void* b, size_t s);
bool pr(uintptr_t a, SIZE_T s, DWORD n);
uintptr_t load_l(const char* p, HANDLE h);
struct stomp_result { uintptr_t base; uintptr_t size; };
stomp_result reserve_stomp(HANDLE h, uintptr_t imgSize);

class p_p {
protected:
	DWORD tP;
	HANDLE tH;
	unsigned char* sc;
	SIZE_T scS;
	PVOID scA;
public:
	p_p(DWORD tP, unsigned char* sc, SIZE_T scS);
	virtual void h_h() = 0;
	virtual void s_e() const = 0;
	void run();
};
class a_w : public p_p {
protected:
	HANDLE iC;
public:
	a_w(DWORD tP, unsigned char* sc, SIZE_T scS);
	void h_h() override;
};
class r_t_d : public a_w {
public:
	r_t_d(DWORD tP, unsigned char* sc, SIZE_T scS);
	void s_e() const override;
};
