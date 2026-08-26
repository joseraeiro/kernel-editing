# KernelCallbackInspector

A read-only tool that enumerates kernel notification callbacks registered via `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, and `PsSetLoadImageNotifyRoutine`. It attaches to the local kernel debugger and reads the internal callback arrays without performing any writes.

## What it does

The tool resolves the following internal NT symbols and reads up to 64 slots from each array:

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
| **Callback** | Function pointer read from `Block + 0x08` |
| **Owner** | Module (driver image) that owns the callback function |
| **Symbol** | Symbol name and displacement for the callback function |

## Prerequisites

- Windows 10/11 x64
- Visual Studio 2022 (v143 toolset) with the Windows SDK
- Local kernel debugging enabled (`bcdedit /debug on`, then reboot)
- Run as Administrator

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

No arguments are required. The tool attaches to the local kernel debugger, downloads symbols from the Microsoft public symbol server (cached to `C:\Symbols`), and prints the callback tables.

## Example output

```
KernelCallbackInspector - read-only local kernel callback enumerator
No kernel memory writes are performed by this program.

[*] Attaching to the local kernel debugger...
[*] Waiting for the local kernel debugging session to initialize...
[*] Kernel session attached. Resolving symbols...

=== Process callbacks ===
Symbol : nt!PspCreateProcessNotifyRoutine
Address: 0xfffff80012345000
Slots read: 64 / 64

Slot  Encoded entry      Block              Callback           Owner                       Symbol
------------------------------------------------------------------------------------------------------------------------
0     0xffffaa8012340003  0xffffaa8012340000  0xfffff80056781234  \SystemRoot\...\driver.sys  driver!CallbackFunc
...

Active entries: 3
```

## Notes

- The internal callback array layout (`EX_CALLBACK_ROUTINE_BLOCK`, fast-reference encoding, function pointer at offset `+0x08`) is undocumented and may change across Windows builds.
- Symbol resolution depends on the Microsoft public symbol server. If `nt` symbols fail to load, the tool continues but `GetOffsetByName` calls will fail for the affected arrays.
- This tool performs no kernel memory writes.
