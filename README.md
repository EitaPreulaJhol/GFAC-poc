# GFAC.sys - Local Privilege Escalation PoC

(Almost) fully reversed driver (.i64 included) from IDA and a working proof-of-concept for 
an **local privilege escalation** in **`GFAC.sys`**: an anti-cheat/process-protection **FltMgr
minifilter + OB-callback** driver.

A single `IOCTL` (`0x222000`) accepts an **raw, caller-supplied `_MDL` pointer**
with no validation. The caller fully controls the MDL (including `StartVa`,
`MdlFlags`, `ByteCount` and the PFN array) as well as `AccessMode`/`RequestedAddress`,
so the driver can be made to map **arbitrary kernel virtual memory** into the caller's 
own address space. In this PoC, this allows us to achieve **arbitrary kernel read/write** from an unprivileged caller.
Then, we can do an **SYSTEM** token swap to get an **SYSTEM shell**.

> Confirmed working on **Windows 11 build 26200**.

> **Research/authorized testing only.** This project is published for defensive
> research and education. Do **not** run the PoC against
> systems you do not own or are not explicitly authorized to test. See the
> [Disclaimer](#disclaimer).

## The vulnerability itself

| Field | Value |
|---|---|
| **Class** | Unvalidated caller-supplied MDL -> arbitrary kernel virtual R/W -> LPE |
| **Driver** | `GFAC.sys` (Windows kernel minifilter) |
| **Vulnerable IOCTL** | `0x222000` - `MAP_USER_BUFFER` (`CTL_CODE(0x22, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)`) |
| **Handler** | `IoctlMapUserBuffer`@`0x140005E20` |
| **Root API** | `MmMapLockedPagesSpecifyCache`/`MmProtectMdlSystemAddress` on an attacker-controlled `_MDL` |
| **Sibling bug** | `0x222004` - `UNMAP_USER_BUFFER` (`IoctlUnmapUserBuffer`@`0x140005F70`) - same defect on `MmUnmapLockedPages`/`MmUnlockPages` |
| **Reachability** | `\Device\GFAC` created with `IoCreateDevice` and **no explicit security descriptor**; reachable via the `\??\GFAC` symlink |
| **Impact** | Local Privilege Escalation to `NT AUTHORITY\SYSTEM` |

## Root cause

`IoctlMapUserBuffer`@`0x140005E20` reads a **raw MDL pointer from the
caller-supplied input buffer** and passes it with **no validation whatsoever**
to `MmMapLockedPagesSpecifyCache`/`MmProtectMdlSystemAddress`:

```
cmp  dword ptr [rcx+10h], 30h        ; InputBufferLength must be 48
cmp  dword ptr [rcx+14h], 8          ; OutputBufferLength must be 8
mov  rsi, [rcx]                      ; rsi = user input buffer
mov  r15, [rcx+8]                    ; r15 = user output buffer
...
mov  rcx, [rsi+10h]                  ; >>> Mdl = *(QWORD*)(input+0x10)  (user controlled)
mov  r8,  rdi                        ; process A
mov  r9,  rbp                        ; process B
mov  al,  [rsi+18h]                  ; a5 = LockPages   (0 => skip MmProbeAndLockPages)
mov  al,  [rsi+1Ch]                  ; AccessMode (0=kernel,1=user)
mov  eax, [rsi+20h]                  ; NewProtect
mov  eax, [rsi+24h]                  ; CacheType
mov  rax, [rsi+28h]                  ; RequestedAddress
call MapUserBufferMdl
```

`MapUserBufferMdl`@`0x140002C00` then does:

```c
if (a5)  MmProbeAndLockPages/MmProbeAndLockProcessPages(Mdl, ...);   // skipped when a5==0
if (a4 != current) KeStackAttachProcess(a4, &ApcState);
v18 = MmMapLockedPagesSpecifyCache(Mdl, AccessMode, CacheType,
                                   AccessMode==1 ? RequestedAddress : NULL, 0, prio);
MmProtectMdlSystemAddress(Mdl, NewProtect);
*out = v18;      // mapped VA returned to user via the 8-byte output buffer
```

Because the caller controls the whole `_MDL` **and** `AccessMode`/`RequestedAddress`, the primitive can be used two ways:

* **confirmed (used by the PoC):** `StartVa` (a **kernel VA**, `LockPages=1`, `AccessMode=1`):
  the driver locks the pages itself and maps them into the caller's own address space, so 
  we get **arbitrary kernel virtual read/write**.
* `LockPages=0` with a fully forged MDL (attacker-chosen PFN array): mapping of arbitrary 
  physical frames (fragile: a wrong `Mdl->Size` gives `PFN_LIST_CORRUPT (0x4E)`, an unmapped 
  VA gives `PAGE_FAULT_IN_NONPAGED_AREA (0x50)`, so BSODs can happen).

## PoC infos

Some build-specific `EPROCESS` offsets are used for the PoC:
`ImageFileName=0x338`, `UniqueProcessId=0x1d0`, `ActiveProcessLinks=0x1d8`,
with `Token=0x4b8` as the only hard-coded, build-dependent constant.

> **If `KRead(...)` does not print `0x5A4D`, the mapping primitive is not working
> on your Windows build. That line is the go/no-go: it proves we can read
> kernel memory through the forged MDL without crashing the system.

## Driver infos

| Field | Value |
|---|---|
| File | `GFAC.sys` |
| MD5 | `756873c861d94e4e78341da5ce7c0ea1` |
| SHA256 | `f30d01ee2e74accc077e8ced20a0e35f36953fab04b78f31e0cee36830da3008` |
| Arch/Base | x64, imagebase `0x140000000`, MSVC |
| Type | Windows kernel FltMgr minifilter + OB-callback driver (anti-cheat/process protection) |
| Functions | 232 (all renamed in the IDB) |
| Imports | `FLTMGR.SYS` (13), `ntoskrnl.exe` (87) |
| Identity | Device `\Device\GFAC` (devicetype `0x22`), symlink `\??\GFAC`, comm port `\GFAC`, altitude `389020` |


> The binary `GFAC.sys` itself is **not** included. `poc/GFAC_LPE_PoC.rc` embeds
> it from `../GFAC.sys` at build time. Supply the driver matching the hashes
> above to reproduce.

## Disclaimer

This material is provided **for research, education and defensive purposes
only**. It is intended for **authorized testing** on systems you own or have 
explicit written permission to test. The author takes no responsibility for 
any misuse or damage caused by this material.
