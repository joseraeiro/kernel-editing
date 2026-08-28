# KernelCallbackInspector

A read-only tool that enumerates kernel notification callbacks and Filter Manager minifilter registrations on the running Windows kernel. It attaches to the local kernel debugger, walks the internal callback arrays and Filter Manager state, and prints every registered callback with owner driver and symbol. No kernel memory writes are performed.

## What it does

The tool runs four enumeration passes.

### Process / thread / image callbacks

It resolves the following internal NT symbols and reads up to 64 slots from each array:

| Array | Symbol |
|-------|--------|
| Process | `nt!PspCreateProcessNotifyRoutine` |
| Thread | `nt!PspCreateThreadNotifyRoutine` |
| Image | `nt!PspLoadImageNotifyRoutine` |

For each populated slot, it prints:

| Column | Description |
|--------|-------------|
| **Slot** | Index in the array (0-63) |
| **Encoded entry** | Raw pointer value stored in the slot, including fast-reference tag bits in the low nibble |
| **Block** | `EX_CALLBACK_ROUTINE_BLOCK` address (encoded entry masked with `~0xF`) |
| **Callback** | Function pointer read from `Block + Function`, where the `Function` field offset is resolved from `nt!_EX_CALLBACK_ROUTINE_BLOCK` type info at runtime (falls back to `0x08` with a printed note if type info is unavailable) |
| **Owner** | Module (driver image) that owns the callback function |
| **Symbol** | Symbol name and displacement for the callback function |

### Filter Manager minifilters

It resolves `fltmgr!FltGlobals` and walks:

```
fltmgr!FltGlobals
  .FrameList (LIST_ENTRY head, inside _FLT_RESOURCE_LIST_HEAD)
    -> _FLTP_FRAME
       .RegisteredFilters (LIST_ENTRY head)
           -> _FLT_FILTER
              .Name (UNICODE_STRING)
              .DriverObject (_DRIVER_OBJECT*)
              .Operations   (_FLT_OPERATION_REGISTRATION*)
```

Every struct offset and size is looked up dynamically via `IDebugSymbols3::GetSymbolTypeId` + `GetFieldOffset` / `GetTypeSize`. A layout change between Windows builds surfaces as an explicit `could not resolve fltmgr!<Type>::<Field>` error rather than silent misinterpretation.

For each registered filter, it prints the filter name (from the embedded `UNICODE_STRING`, capped at 512 bytes), the owning driver (from `DriverObject->DriverStart`), and a per-IRP-major table:

| Column | Description |
|--------|-------------|
| **IRP major** | Symbolic name for the operation (standard `IRP_MJ_*` plus the Filter Manager pseudo-majors at `0xEC..0xFF`; unknown values print as `IRP_MJ_0x??`) |
| **PRE** | `PreOperation` callback address, or `-` if none |
| **POST** | `PostOperation` callback address, or `-` if none |
| **Owner** | Module (driver image) that owns the callback |
| **Symbol** | Symbol name and displacement for the callback |

Iteration of each filter's `Operations` array terminates on `MajorFunction == 0x80` (`IRP_MJ_OPERATION_END`).

## Prerequisites

- Windows 10/11 x64
- Visual Studio 2022 (v143 toolset) with the Windows SDK
- Local kernel debugging enabled (`bcdedit /debug on` then `bcdedit /dbgsettings local`, then reboot)
- Run as Administrator
- Public symbols for `nt` and `fltmgr.sys` reachable via the symbol path (defaults to Microsoft's public symbol server, cached under `C:\Symbols`)

## Building

**Visual Studio:** Open `KernelCallbackInspector.sln` and build the x64 Debug or Release configuration.

**Developer Command Prompt:**

```
cl /EHsc /W4 /std:c++17 /O2 KernelCallbackInspector\main.cpp /Fe:KernelCallbackInspector.exe
```

The `#pragma comment(lib, "dbgeng.lib")` directive handles linking automatically.

## Usage

```
KernelCallbackInspector.exe
```

No arguments are required. The tool:

1. Enables `SeDebugPrivilege` (required on Windows 11 24H2+ for `EnumDeviceDrivers` to return real kernel image bases).
2. Attaches to the local kernel debugger.
3. Loads `nt` and `fltmgr.sys` symbols (each reload is non-fatal on its own; a failed `fltmgr.sys` reload just degrades minifilter enumeration).
4. Resolves `_EX_CALLBACK_ROUTINE_BLOCK::Function` dynamically and enumerates the process, thread, and image callback arrays.
5. Enumerates every Filter Manager frame and every registered minifilter.

## Exit code

`0` on success. `1` on any of:

- Debug client / interface creation, kernel attach, or wait failure.
- One or more enumeration passes failed (the tool prints `N enumeration(s) failed` before exiting).

The stale `HRESULT` from a non-fatal symbol reload is cleared so it can't leak into the exit code.

## Example output

```
KernelCallbackInspector - read-only local kernel callback enumerator
No kernel memory writes are performed by this program.

[+] SeDebugPrivilege enabled.
[*] Loaded dbgeng.dll: C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\dbgeng.dll
[*] Symbol path: srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
[*] Attaching to the local kernel debugger...
[*] Waiting for local kernel session...
[+] Kernel session attached.
[*] Loading nt symbols...
[*] Enumerating loaded kernel drivers...
[+] PSAPI driver list: 238 loaded drivers
[+] Driver ranges resolved: 238 / 238
[+] _EX_CALLBACK_ROUTINE_BLOCK::Function resolved at offset 0x8.
[!] Assuming Windows uses 64 slots per process/thread/image callback array; this layout is undocumented and may change between builds.

=== Process callbacks ===
Symbol : nt!PspCreateProcessNotifyRoutine
Address: 0xfffff80012345000
Slots read: 64 / 64

Slot  Encoded entry      Block              Callback           Owner                       Symbol
--------------------------------------------------------------------------------------------------
0     0xffffaa8012340003 0xffffaa8012340000 0xfffff80056781234 driver.sys                  driver!CallbackFunc

Active entries: 3

...

=== Minifilters ===
Symbol : fltmgr!FltGlobals
Address: 0xfffff80054321000
Frames : 1

-- Frame 0 at 0xffff900001abc000 (5 filter(s)) --

Filter : WdFilter
Address    : 0xffff900001aaa000
Owner      : WdFilter.sys
Operations : 0xfffff805a1234000
IRP major                             PRE                POST               Owner                           Symbol
--------------------------------------------------------------------------------------------
IRP_MJ_CREATE                         0xfffff805a1234500 0xfffff805a1234a00 WdFilter.sys                    WdFilter!MpPreCreate
IRP_MJ_WRITE                          0xfffff805a1234600 -                  WdFilter.sys                    WdFilter!MpPreWrite
...
```

## Notes

- The internal callback array layout (`EX_CALLBACK_ROUTINE_BLOCK`, fast-reference encoding, function pointer offset) and the Filter Manager struct layout are undocumented and may change across Windows builds. Where possible the tool resolves offsets via `IDebugSymbols3` type info at runtime; the 64-slot count for process / thread / image arrays is still an assumption and is flagged at startup.
- Symbol resolution depends on the Microsoft public symbol server (and, for third-party filters, on whatever PDBs happen to be reachable). Callback owner is always resolved from the enumerated PSAPI driver list, so it is reported correctly even when a filter's private symbols are unavailable.
- Kernel `LIST_ENTRY` walks are bounded (16 frames, 256 filters per frame, 64 operations per filter) and tolerate unmapped memory, self-loops, and zero `Flink` values; a garbage list terminates the walk rather than looping or crashing.
- This tool performs no kernel memory writes.
