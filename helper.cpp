// Made by Krypt :D
// p1stn helped on additions
#include <Windows.h>
#include <thread>
#include <iostream>
#include <unordered_set>
#include <cwchar>
#include <random>
#include <iostream>
#include <algorithm>
#include "helper.hpp"
#include "nthelper.hpp"
#include <Psapi.h>
#include "utilhelper.hpp"

struct SEH_DATA {
    void* table;
    DWORD count;
    uintptr_t base;
};

extern "C" {
	DWORD idx_rd = 0, idx_wr = 0, idx_al = 0, idx_pr = 0, idx_qs = 0, idx_mv = 0, idx_uv = 0, idx_cs = 0, idx_op = 0, idx_cl = 0;
	uintptr_t sys_rd = 0, sys_wr = 0, sys_al = 0, sys_pr = 0, sys_qs = 0, sys_mv = 0, sys_uv = 0, sys_cs = 0, sys_op = 0, sys_cl = 0;
}


template<typename T>
T rd(uintptr_t a) {
    T b{};
    NTSTATUS s = NtReadVirtualMemory(ctx::h, (PVOID)a, &b, sizeof(T), nullptr);
    if (!NT_SUCCESS(s)) return T{};
    return b;
}

bool rd(uintptr_t a, void* o, size_t s) {
    NTSTATUS st = NtReadVirtualMemory(ctx::h, (PVOID)a, o, s, nullptr);
    return NT_SUCCESS(st);
}

template<typename T>
bool wr(uintptr_t a, const T& v) {
    NTSTATUS s = NtWriteVirtualMemory(ctx::h, (PVOID)a, &v, sizeof(T), nullptr);
    return NT_SUCCESS(s);
}

bool wr(uintptr_t a, const void* b, size_t s) {
    NTSTATUS st = NtWriteVirtualMemory(ctx::h, (PVOID)a, (PVOID)b, s, nullptr);
    return NT_SUCCESS(st);
}

bool pr(uintptr_t a, SIZE_T s, DWORD n) {
    PVOID b = (PVOID)a;
    SIZE_T r = s;
    DWORD o = 0;
    NTSTATUS st = NtProtectVirtualMemory(ctx::h, &b, &r, n, &o);
    return NT_SUCCESS(st);
}

typedef enum _S_I {
    V_S = 1,
    V_U = 2
} S_I;

struct m_inf {
    uintptr_t b;
    SIZE_T s;
    const char* p;
};

__forceinline size_t min_sz(size_t a, size_t b) {
    return (a < b) ? a : b;
}

inline const std::string c_set = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
inline std::unordered_set<std::string> u_names;

static bool pe_name_matches(const UNICODE_STRING* u, const wchar_t* target) {
    if (!u || !u->Buffer || !u->Length) return false;
    const size_t nWchars = u->Length / sizeof(wchar_t);
    const size_t tLen = wcslen(target);
    if (nWchars != tLen) return false;
    return _wcsnicmp(u->Buffer, target, nWchars) == 0;
}

SYSTEM_PROCESS_INFORMATION* find_p(const wchar_t* target) {
    auto* ps = (SYSTEM_PROCESS_INFORMATION*)malloc(0x400000);
    if (!ps) {
        return nullptr;
    }
    using PfnQsi = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
    NTSTATUS st = reinterpret_cast<PfnQsi>(NtF("NtQuerySystemInformation"))(
        SystemProcessInformation, ps, 0x400000, nullptr);
    if (!NT_SUCCESS(st)) {
        free(ps);
        return nullptr;
    }
    for (SYSTEM_PROCESS_INFORMATION* c = ps;;) {
        if (pe_name_matches(&c->ImageName, target)) return c;
        if (c->NextEntryOffset == 0) break;
        c = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(reinterpret_cast<BYTE*>(c) + c->NextEntryOffset);
    }
    free(ps);
    return nullptr;
}

HMODULE get_m(const std::string& name) {
    if (name.empty() || !ctx::p) return 0;
    HMODULE m[1024];
    DWORD n;
    if (EnumProcessModules(ctx::h, m, sizeof(m), &n)) {
        for (unsigned int i = 0; i < (n / sizeof(HMODULE)); i++) {
            char b[MAX_PATH];
            if (GetModuleBaseNameA(ctx::h, m[i], b, sizeof(b) / sizeof(char))) {
                if (strcmp(b, name.data()) == 0) return m[i];
            }
        }
    }
    return 0;
}

MODULEENTRY32W get_m_ext(DWORD p, const wchar_t* name) {
    MODULEENTRY32W me{};
    me.dwSize = sizeof(MODULEENTRY32W);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, p);
    if (hSnap == INVALID_HANDLE_VALUE) return me;
    if (Module32FirstW(hSnap, &me)) {
        do {
            if (_wcsicmp(me.szModule, name) == 0) {
                CloseHandle(hSnap);
                return me;
            }
        } while (Module32NextW(hSnap, &me));
    }
    CloseHandle(hSnap);
    me.szModule[0] = 0;
    return me;
}

uintptr_t get_e(HANDLE h, DWORD p, const wchar_t* mod, const char* exp) {
    MODULEENTRY32W b_o = get_m_ext(p, mod);
    uintptr_t b = (uintptr_t)b_o.modBaseAddr;
    if (!b) return 0;
    IMAGE_DOS_HEADER dos{};
    if (!nt_rvm(h, (PVOID)b, &dos, sizeof(dos))) return 0;
    IMAGE_NT_HEADERS64 nt{};
    if (!nt_rvm(h, (PVOID)(b + dos.e_lfanew), &nt, sizeof(nt))) return 0;
    DWORD e_rva = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!e_rva) return 0;
    IMAGE_EXPORT_DIRECTORY e_d{};
    if (!nt_rvm(h, (PVOID)(b + e_rva), &e_d, sizeof(e_d))) return 0;
    std::vector<DWORD> ns(e_d.NumberOfNames);
    std::vector<WORD> os(e_d.NumberOfNames);
    std::vector<DWORD> fs(e_d.NumberOfFunctions);
    if (!nt_rvm(h, (PVOID)(b + e_d.AddressOfNames), ns.data(), ns.size() * sizeof(DWORD))) return 0;
    if (!nt_rvm(h, (PVOID)(b + e_d.AddressOfNameOrdinals), os.data(), os.size() * sizeof(WORD))) return 0;
    if (!nt_rvm(h, (PVOID)(b + e_d.AddressOfFunctions), fs.data(), fs.size() * sizeof(DWORD))) return 0;
    char buf[256]{};
    for (size_t i = 0; i < ns.size(); ++i) {
        if (!nt_rvm(h, (PVOID)(b + ns[i]), buf, sizeof(buf))) continue;
        if (!strcmp(buf, exp)) {
            WORD o = os[i];
            DWORD f_rva = fs[o];
            return b + f_rva;
        }
    }
    return 0;
}

std::vector<BYTE> ext_sc(uintptr_t f) {
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery((void*)f, &mbi, sizeof(mbi));
    size_t f_s = mbi.RegionSize;
    std::vector<BYTE> sc;
    for (size_t i = 0; i < f_s; ++i) {
        BYTE v = *(BYTE*)(f + i);
        sc.push_back(v);
        if (v == 0xCC && *(BYTE*)(f + i + 1) == 0xCC && *(BYTE*)(f + i + 2) == 0xCC) break;
    }
    return sc;
}

void rep_sc(std::vector<BYTE>& d, uint64_t s, uint64_t r) {
    const BYTE m_b_o = 0xB8;
    for (size_t i = 0; i <= d.size() - 10; ++i) {
        if ((d[i] == 0x48 || d[i] == 0x49) && d[i + 1] >= m_b_o && d[i + 1] <= m_b_o + 7) {
            uint64_t imm = *(uint64_t*)(&d[i + 2]);
            uint32_t off = *(uint32_t*)(&d[i + 2]);
            if (imm - off == s) {
                uintptr_t n_v = r + off;
                memcpy(&d[i + 2], &n_v, sizeof(n_v));
            }
        }
        uint64_t immQ = *(uint64_t*)(&d[i + 1]);
        uint32_t immO = *(uint32_t*)(&d[i + 1]);
        if ((d[i] == 0xA1 || d[i] == 0xA2 || d[i] == 0xA3) && immQ - immO == s) {
            uintptr_t n_v = r + immO;
            memcpy(&d[i + 1], &n_v, sizeof(n_v));
        }
    }
}

std::string gen_s(int l) {
    std::random_device rd;
    std::mt19937 g(rd());
    std::uniform_int_distribution<> d(0, c_set.size() - 1);
    std::string res;
    res.reserve(l);
    for (int i = 0; i < l; ++i) res += c_set[d(g)];
    res += ".bin";
    if (u_names.find(res) != u_names.end()) return gen_s(l);
    u_names.insert(res);
    return res;
}

std::string gen_cs(int l, const std::string& f) {
    if (!f.empty()) {
        if (u_names.find(f) != u_names.end()) return gen_cs(l, f);
        u_names.insert(f);
        return f;
    }
    std::random_device rd;
    std::mt19937 g(rd());
    std::uniform_int_distribution<> d(0, (int)c_set.size() - 1);
    std::string res;
    res.reserve(l);
    for (int i = 0; i < l; ++i) res += c_set[d(g)];
    res += ".dll";
    if (u_names.find(res) != u_names.end()) return gen_cs(l);
    u_names.insert(res);
    return res;
}

BOOL set_p(const wchar_t* p_v, DWORD a) {
    HANDLE t;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &t)) return FALSE;
    TOKEN_PRIVILEGES pr;
    if (!LookupPrivilegeValueW(nullptr, p_v, &pr.Privileges[0].Luid)) return FALSE;
    pr.PrivilegeCount = 1;
    pr.Privileges[0].Attributes = a;
    if (!AdjustTokenPrivileges(t, FALSE, &pr, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr) || GetLastError() == ERROR_NOT_ALL_ASSIGNED) return FALSE;
    return TRUE;
}

uintptr_t load_l(const char* p, HANDLE h_t) {
    HANDLE h_f = CreateFileA(p, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h_f == INVALID_HANDLE_VALUE) return 0;
    BYTE hd[4096]{};
    DWORD rd_v = 0;
    if (!ReadFile(h_f, hd, sizeof(hd), &rd_v, nullptr)) { CloseHandle(h_f); return 0; }
    auto dos = reinterpret_cast<PIMAGE_DOS_HEADER>(hd);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) { CloseHandle(h_f); return 0; }
    auto nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(hd + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) { CloseHandle(h_f); return 0; }
    HANDLE h_s = nullptr;
    LARGE_INTEGER s_z = { 0 };
    s_z.QuadPart = nt->OptionalHeader.SizeOfImage;
    NTSTATUS st = NtCreateSection(&h_s, SECTION_ALL_ACCESS, nullptr, &s_z, PAGE_READONLY, SEC_IMAGE, h_f);
    CloseHandle(h_f);
    if (!NT_SUCCESS(st)) return 0;
    PVOID r_b = nullptr;
    SIZE_T v_z = 0;
    st = NtMapViewOfSection(h_s, h_t, &r_b, 0, 0, nullptr, &v_z, static_cast<ULONG>(V_U), 0, PAGE_READONLY);
    NtClose(h_s);
    if (!NT_SUCCESS(st)) return 0;
    return reinterpret_cast<uintptr_t>(r_b);
}

static void nt_unmap(HANDLE h, PVOID base) {
    auto p = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID)>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"));
    if (p) p(h, base);
}

stomp_result reserve_stomp(HANDLE h, uintptr_t imgSize) {
    const char* path = "C:\\Windows\\System32\\mshtml.dll";
    uintptr_t base = load_l(path, h);
    if (!base) { con_fail("stomp target unavailable"); return { 0, 0 }; }
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    if (nt_rvm(h, (PVOID)base, &dos, sizeof(dos)) &&
        nt_rvm(h, (PVOID)(base + dos.e_lfanew), &nt, sizeof(nt))) {
        if ((uintptr_t)nt.OptionalHeader.SizeOfImage >= imgSize)
            return { base, (uintptr_t)nt.OptionalHeader.SizeOfImage };
        con_fail("stomp target is too small (%zu < %zu)", (size_t)nt.OptionalHeader.SizeOfImage, (size_t)imgSize);
    }
    nt_unmap(h, (PVOID)base);
    return { 0, 0 };
}

static bool unicode_string_ieq_lit(const UNICODE_STRING* u, const wchar_t* lit) {
    if (!u || !u->Buffer || u->Length == 0 || !lit) return false;
    const size_t uw = u->Length / sizeof(wchar_t);
    const size_t lw = wcslen(lit);
    if (uw != lw) return false;
    return _wcsnicmp(u->Buffer, lit, uw) == 0;
}

HANDLE op_p(DWORD p) { return OpenProcess(PROCESS_ALL_ACCESS, FALSE, p); }
HANDLE dup_h(HANDLE p, HANDLE h, DWORD a) {
    HANDLE r = nullptr;
    DuplicateHandle(p, h, GetCurrentProcess(), &r, a, FALSE, 0);
    return r;
}
HANDLE h_p_h(const wchar_t* t, HANDLE h, DWORD a) {
    DWORD buf_sz = 0x10000;
    std::vector<BYTE> buf;
    NTSTATUS st;
    do {
        buf.resize(buf_sz);
        DWORD ret = 0;
        st = NtQueryInformationProcess(h, (PROCESSINFOCLASS)51, buf.data(), buf_sz, &ret);
        if (st == (NTSTATUS)STATUS_INFO_LENGTH_MISMATCH) buf_sz <<= 1;
    } while (st == (NTSTATUS)STATUS_INFO_LENGTH_MISMATCH);
    if (!NT_SUCCESS(st)) {
        return nullptr;
    }
    auto info = (ntdll::PROCESS_HANDLE_SNAPSHOT_INFORMATION*)buf.data();
    for (ULONG_PTR i = 0; i < info->NumberOfHandles; i++) {
        HANDLE d = dup_h(h, info->Handles[i].HandleValue, a);
        if (!d) continue;
        ULONG on = 0;
        NtQueryObject(d, ObjectTypeInformation, nullptr, 0, &on);
        if (!on) { CloseHandle(d); continue; }
        std::vector<BYTE> ob(on);
        if (NT_SUCCESS(NtQueryObject(d, ObjectTypeInformation, ob.data(), on, &on))) {
            auto ot = (PUBLIC_OBJECT_TYPE_INFORMATION*)ob.data();
            if (unicode_string_ieq_lit(&ot->TypeName, t)) return d;
        }
        CloseHandle(d);
    }
    return nullptr;
}
p_p::p_p(DWORD tP, unsigned char* sc, SIZE_T scS) : tP(tP), sc(sc), scS(scS), tH(nullptr), scA(nullptr) {}
void p_p::run() {
    tH = op_p(tP);
    if (!tH || tH == INVALID_HANDLE_VALUE) {
        return;
    }
    h_h();
    scA = VirtualAllocEx(tH, nullptr, scS, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!scA) {
        return;
    }
    NTSTATUS wst{};
    if (!nt_wvm(tH, scA, sc, scS, nullptr, &wst)) {
        return;
    }
    DWORD oldP = 0;
    VirtualProtectEx(tH, scA, scS, PAGE_EXECUTE_READ, &oldP);
    s_e();
    VirtualProtectEx(tH, scA, scS, PAGE_EXECUTE_READWRITE, &oldP);
}
a_w::a_w(DWORD tP, unsigned char* sc, SIZE_T scS) : p_p(tP, sc, scS), iC(nullptr) {}
void a_w::h_h() { iC = h_p_h(L"IoCompletion", tH, IO_COMPLETION_ALL_ACCESS); }
r_t_d::r_t_d(DWORD tP, unsigned char* sc, SIZE_T scS) : a_w(tP, sc, scS) {}
void r_t_d::s_e() const {
    if (!iC) {
        return;
    }
    if (!scA) {
        return;
    }
    struct TP_D {
        ntdll::TP_TASK Task;
        UINT64 Lock;
        LIST_ENTRY Io;
        void* Callback;
        UINT32 Numa;
        UINT8 Ideal;
        char Pad[3];
    } Direct{ 0 };
    Direct.Callback = scA;
    void* r = VirtualAllocEx(tH, nullptr, sizeof(TP_D), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!r) {
        return;
    }
    NTSTATUS twst{};
    if (!nt_wvm(tH, r, &Direct, sizeof(TP_D), nullptr, &twst)) {
        return;
    }
    auto zw = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, ULONG)>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSetIoCompletion"));
    if (!zw) {
        return;
    }
    NTSTATUS st = zw(iC, r, nullptr, nullptr, 0);
    if (!NT_SUCCESS(st))
        con_fail("ZwSetIoCompletion failed");
    else
    std::cout << "ZwSetIoCompletion success" << "\n";
}
static void apply_relocs(BYTE* base, IMAGE_NT_HEADERS* nt, int64_t delta) {
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (!dir.VirtualAddress || !dir.Size) return;
    auto block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(base + dir.VirtualAddress);
    auto end = reinterpret_cast<BYTE*>(block) + dir.Size;
    while (reinterpret_cast<BYTE*>(block) < end && block->SizeOfBlock) {
        UINT count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        auto entry = reinterpret_cast<WORD*>(block + 1);
        for (UINT i = 0; i < count; i++) {
            if ((entry[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                auto patch = reinterpret_cast<uint64_t*>(base + block->VirtualAddress + (entry[i] & 0xFFF));
                *patch += delta;
            }
        }
        block = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(block) + block->SizeOfBlock);
    }
}
static bool apply_imports(BYTE* base, IMAGE_NT_HEADERS* nt) {
    auto& dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!dir.VirtualAddress || !dir.Size) return true;
    auto imp = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + dir.VirtualAddress);
    while (imp->Name) {
        auto mod = LoadLibraryA(reinterpret_cast<const char*>(base + imp->Name));
        if (!mod) { con_fail("Import load failed"); return false; }
        auto thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(base + imp->FirstThunk);
        auto orig = imp->OriginalFirstThunk ? reinterpret_cast<IMAGE_THUNK_DATA64*>(base + imp->OriginalFirstThunk) : thunk;
        while (orig->u1.AddressOfData) {
            if (IMAGE_SNAP_BY_ORDINAL64(orig->u1.Ordinal)) { thunk->u1.Function = reinterpret_cast<uint64_t>(GetProcAddress(mod, MAKEINTRESOURCEA(IMAGE_ORDINAL64(orig->u1.Ordinal)))); }
            else { auto by_name = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + orig->u1.AddressOfData); thunk->u1.Function = reinterpret_cast<uint64_t>(GetProcAddress(mod, by_name->Name)); }
            if (!thunk->u1.Function) { con_fail("Proc address failed"); return false; }
            thunk++; orig++;
        }
        imp++;
    }
    return true;
}

void c_ldr::run_remote(void* fn, void* data, size_t size) {
    if (!fn) { con_fail("Invalid fn"); return; }
    BYTE* remoteData = nullptr; SIZE_T written = 0; NTSTATUS wst{};
    if (size) {
        remoteData = reinterpret_cast<BYTE*>(VirtualAllocEx(rP, nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!remoteData) { con_fail("Alloc failed"); return; }
        if (!nt_wvm(rP, remoteData, data, size, &written, &wst) || written != size) { con_fail("Write failed"); return; }
    }
    BYTE sc[] = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0xB9, 0,0,0,0,0,0,0,0, 0x48, 0xB8, 0,0,0,0,0,0,0,0, 0xFF, 0xD0, 0x48, 0x83, 0xC4, 0x28, 0xC3 };
    uintptr_t dataVal = reinterpret_cast<uintptr_t>(remoteData), fnVal = reinterpret_cast<uintptr_t>(fn);
    memcpy(&sc[6], &dataVal, sizeof(dataVal)); memcpy(&sc[16], &fnVal, sizeof(fnVal));
    auto t = std::make_unique<r_t_d>(static_cast<DWORD>(this->pI), sc, sizeof(sc)); t->run();
}

void c_ldr::init(std::int32_t pI, HANDLE rP, std::uintptr_t hB, std::uintptr_t sB, std::uintptr_t stompSz) {
    this->pI = pI; this->rP = rP; this->hB = hB; this->sB = sB;
    this->stompSz = stompSz;
    this->stubBase = this->tailOff = this->tailEnd = 0;
    this->iC = nullptr;
}

uintptr_t c_ldr::alloc_tail(SIZE_T size, SIZE_T align) {
    tailOff = (tailOff + align - 1) & ~(align - 1);
    if (tailOff + size > tailEnd) { con_fail("tail arena exhausted"); return 0; }
    uintptr_t addr = tailOff;
    tailOff += size;
    return addr;
}

void c_ldr::exec_stub(const BYTE* sc, SIZE_T scSize) {
    if (!iC) {
        iC = h_p_h(L"IoCompletion", rP, IO_COMPLETION_ALL_ACCESS);
        if (!iC) { con_fail("no IoCompletion handle"); return; }
    }
    uintptr_t codeSlot = alloc_tail(scSize, 0x1000);
    if (!codeSlot) return;
    PVOID cb = reinterpret_cast<PVOID>(codeSlot); SIZE_T cz = scSize; DWORD old = 0;
    NtProtectVirtualMemory(rP, &cb, &cz, PAGE_READWRITE, &old);
    if (!nt_wvm(rP, reinterpret_cast<PVOID>(codeSlot), sc, scSize)) { con_fail("stub write failed"); return; }
    NtProtectVirtualMemory(rP, &cb, &cz, PAGE_EXECUTE_READ, &old);

    struct TP_D { ntdll::TP_TASK Task; UINT64 Lock; LIST_ENTRY Io; void* Callback; UINT32 Numa; UINT8 Ideal; char Pad[3]; };
    TP_D direct{ 0 };
    direct.Callback = reinterpret_cast<void*>(codeSlot);
    uintptr_t dataSlot = alloc_tail(sizeof(TP_D), 0x1000);
    if (!dataSlot) return;
    PVOID db = reinterpret_cast<PVOID>(dataSlot); SIZE_T dz = sizeof(TP_D);
    NtProtectVirtualMemory(rP, &db, &dz, PAGE_READWRITE, &old);
    if (!nt_wvm(rP, reinterpret_cast<PVOID>(dataSlot), &direct, sizeof(TP_D))) { con_fail("tpd write failed"); return; }

    static auto zw = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, ULONG)>(
        GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwSetIoCompletion"));
    if (!zw) { con_fail("ZwSetIoCompletion missing"); return; }
    NTSTATUS st = zw(iC, reinterpret_cast<PVOID>(dataSlot), nullptr, nullptr, 0);
    if (!NT_SUCCESS(st)) con_fail("ZwSetIoCompletion failed");
}
bool c_ldr::res_i(void* tI, IMAGE_NT_HEADERS* nH) { auto& imp_dir = nH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]; if (!imp_dir.VirtualAddress) return false; return apply_imports(reinterpret_cast<BYTE*>(tI), nH); }
void c_ldr::map(const std::string& mN, uintptr_t remoteBase) {
    if (!remoteBase) { con_fail("Invalid base"); return; }
    FILE* f = nullptr;
    if (fopen_s(&f, mN.c_str(), "rb") != 0 || !f) { con_fail("File open error"); return; }
    fseek(f, 0, SEEK_END); size_t fileSize = static_cast<size_t>(ftell(f)); rewind(f);
    auto rawBuf = std::make_unique<BYTE[]>(fileSize);
    if (fread(rawBuf.get(), 1, fileSize, f) != fileSize) { fclose(f); con_fail("File read error"); return; }
    fclose(f);
    auto* dosHdr = reinterpret_cast<IMAGE_DOS_HEADER*>(rawBuf.get());
    auto* ntHdr = reinterpret_cast<IMAGE_NT_HEADERS*>(rawBuf.get() + dosHdr->e_lfanew);
    DWORD imgSize = ntHdr->OptionalHeader.SizeOfImage;
    auto mapped = std::make_unique<BYTE[]>(imgSize); memset(mapped.get(), 0, imgSize);
    memcpy(mapped.get(), rawBuf.get(), ntHdr->OptionalHeader.SizeOfHeaders);
    auto* sec = IMAGE_FIRST_SECTION(ntHdr);
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
        if (!sec[i].SizeOfRawData) continue;
        memcpy(mapped.get() + sec[i].VirtualAddress, rawBuf.get() + sec[i].PointerToRawData, sec[i].SizeOfRawData);
    }
    auto* mDos = reinterpret_cast<IMAGE_DOS_HEADER*>(mapped.get());
    auto* mNt = reinterpret_cast<IMAGE_NT_HEADERS*>(mapped.get() + mDos->e_lfanew);
    int64_t delta = static_cast<int64_t>(remoteBase) - static_cast<int64_t>(mNt->OptionalHeader.ImageBase);
    apply_relocs(mapped.get(), mNt, delta);
    mNt->OptionalHeader.ImageBase = remoteBase;
    if (!apply_imports(mapped.get(), mNt)) { con_fail("Import error"); return; }

    this->tB = reinterpret_cast<BYTE*>(remoteBase);
    this->stubBase = remoteBase + imgSize;
    this->tailOff = this->stubBase;
    this->tailEnd = remoteBase + this->stompSz;
    if (this->tailEnd <= this->stubBase) { con_fail("no tail space for stubs"); return; }

    {
        PVOID wb = reinterpret_cast<PVOID>(remoteBase); SIZE_T wz = imgSize; DWORD old = 0;
        NtProtectVirtualMemory(rP, &wb, &wz, PAGE_READWRITE, &old);
    }
    SIZE_T written = 0; NTSTATUS wst{};
    if (!nt_wvm(rP, reinterpret_cast<PVOID>(remoteBase), mapped.get(), imgSize, &written, &wst) || written != imgSize) {
        con_fail("Write failed"); return;
    }
    {
        PVOID rb = reinterpret_cast<PVOID>(remoteBase); SIZE_T rz = imgSize; DWORD old = 0;
        NtProtectVirtualMemory(rP, &rb, &rz, PAGE_READONLY, &old);
    }
    sec = IMAGE_FIRST_SECTION(ntHdr);
    for (WORD i = 0; i < ntHdr->FileHeader.NumberOfSections; i++) {
        if (!sec[i].Misc.VirtualSize) continue;
        PVOID secBase = reinterpret_cast<PVOID>(remoteBase + sec[i].VirtualAddress);
        SIZE_T secSz = sec[i].Misc.VirtualSize; DWORD ch = sec[i].Characteristics;
        DWORD prot = PAGE_READONLY;
        if (ch & IMAGE_SCN_MEM_EXECUTE) prot = PAGE_EXECUTE_READ;
        else if (ch & IMAGE_SCN_MEM_WRITE) prot = PAGE_READWRITE;
        DWORD old = 0;
        NtProtectVirtualMemory(rP, &secBase, &secSz, prot, &old);
    }

    auto& exDir = mNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
    if (exDir.VirtualAddress) {
        uintptr_t tableAddr = remoteBase + exDir.VirtualAddress;
        uintptr_t count = exDir.Size / 12;
        void* AddFunctionTable = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlAddFunctionTable");
        BYTE sc_seh[] = {
            0x48,0x83,0xEC,0x28, 0x48,0xB9, 0,0,0,0,0,0,0,0, 0x48,0xBA, 0,0,0,0,0,0,0,0,
            0x49,0xB8, 0,0,0,0,0,0,0,0, 0x48,0xB8, 0,0,0,0,0,0,0,0, 0xFF,0xD0, 0x48,0x83,0xC4,0x28, 0xC3
        };
        memcpy(&sc_seh[6], &tableAddr, 8);
        memcpy(&sc_seh[16], &count, 8);
        memcpy(&sc_seh[26], &remoteBase, 8);
        memcpy(&sc_seh[36], &AddFunctionTable, 8);
        exec_stub(sc_seh, sizeof(sc_seh));
    }

    auto& tlsDir = mNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir.VirtualAddress) {
        auto* tls = reinterpret_cast<PIMAGE_TLS_DIRECTORY64>(mapped.get() + tlsDir.VirtualAddress);
        if (tls->AddressOfCallBacks) {
            uintptr_t cbArrayRva = (uintptr_t)tls->AddressOfCallBacks - remoteBase;
            uintptr_t* callbacks = reinterpret_cast<uintptr_t*>(mapped.get() + cbArrayRva);
            for (int i = 0; callbacks[i] != 0; i++) {
                BYTE sc_tls[] = {
                    0x48,0x83,0xEC,0x28, 0x48,0xB9, 0,0,0,0,0,0,0,0,
                    0x48,0xC7,0xC2,0x01,0x00,0x00,0x00, 0x4D,0x31,0xC0,
                    0x48,0xB8, 0,0,0,0,0,0,0,0, 0xFF,0xD0, 0x48,0x83,0xC4,0x28, 0xC3
                };
                uintptr_t cbAddr = callbacks[i];
                memcpy(&sc_tls[6], &remoteBase, 8);
                memcpy(&sc_tls[26], &cbAddr, 8);
                exec_stub(sc_tls, sizeof(sc_tls));
            }
        }
    }

    if (ntHdr->OptionalHeader.AddressOfEntryPoint) {
        uint64_t entryVA = remoteBase + ntHdr->OptionalHeader.AddressOfEntryPoint;
        uintptr_t baseVal = remoteBase;
        BYTE sc[] = {
            0x48,0x83,0xEC,0x28, 0x48,0xB9, 0,0,0,0,0,0,0,0,
            0x48,0xC7,0xC2,0x01,0x00,0x00,0x00, 0x4D,0x31,0xC0,
            0x48,0xB8, 0,0,0,0,0,0,0,0, 0xFF,0xD0, 0x48,0x83,0xC4,0x28, 0xC3
        };
        memcpy(&sc[6], &baseVal, sizeof(baseVal));
        memcpy(&sc[26], &entryVA, sizeof(entryVA));
        exec_stub(sc, sizeof(sc));
    }

    if (iC) { CloseHandle(iC); iC = nullptr; }
}
