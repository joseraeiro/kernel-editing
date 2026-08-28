# KernelWriteLab

> **Disclaimer:** This tool is provided strictly for educational and authorized security research purposes. It is intended to be used only in isolated, snapshotted, disposable lab virtual machines. Do not use this tool on production systems, corporate networks, or any environment where unauthorized modification of kernel memory could cause harm, data loss, or violate applicable laws and regulations. The authors assume no liability for misuse. By using this software, you agree that you are solely responsible for ensuring you have proper authorization and that your use complies with all applicable laws and your organization's policies.

A lab tool that demonstrates constrained use of `IDebugDataSpaces::WriteVirtualUncached` through the Windows Debugging SDK. It attaches to the local kernel debugger, reads a 64-bit value at a target address (or a range of 8-byte slots), writes replacement values, and reads them back through the uncached path to verify.

## What it does

1. Attaches to the local kernel debugger via `DEBUG_ATTACH_LOCAL_KERNEL`.
2. Prints an explicit kernel-safety warning banner naming the synchronization / refcount hazard of writing directly to live kernel structures.
3. Resolves the target address (either via `MyLabDriver!g_LabValue` symbol lookup or an explicit `--address` argument).
4. For each of `--count` consecutive 8-byte slots (default 1):
   - Reads the current 64-bit value through `ReadVirtualUncached`.
   - Writes the requested value through `WriteVirtualUncached`.
   - Reads back through `ReadVirtualUncached` and verifies the value.
   - Records the original value so the slot can be rolled back on any later failure.
5. On any abort (short write, verify mismatch, HRESULT failure) the tool attempts a best-effort rollback of every slot it already modified, in reverse order.

## Prerequisites

- Windows 10/11 x64
- Visual Studio 2022 (v143 toolset) with the Windows SDK
- Local kernel debugging enabled (`bcdedit /debug on` then `bcdedit /dbgsettings local`, then reboot)
- Run as Administrator
- When using symbol resolution (default mode): `MyLabDriver.sys` loaded and its PDB reachable on the symbol path (default lookup path includes `C:\LabSymbols`)

## Building

**Visual Studio:** Open `KernelWriteLab.sln` and build the x64 Debug or Release configuration.

**Developer Command Prompt:**

```
cl /EHsc /W4 /std:c++17 /O2 KernelWriteLab\UserMode\main.cpp /Fe:KernelWriteLab.exe
```

The `#pragma comment(lib, "dbgeng.lib")` directive handles linking automatically.

## Usage

```
KernelWriteLab.exe [--address hex-addr] [--count N] [hex-value]
```

| Argument | Description |
|----------|-------------|
| `--address hex-addr` | Use a raw virtual address instead of resolving `MyLabDriver!g_LabValue` via symbols. Must be 8-byte aligned. |
| `--count N` | Write the value to `N` consecutive 8-byte slots starting from the target address. `1 ≤ N ≤ 64`. Requires `--address`. Defaults to 1. |
| `hex-value` | The 64-bit value to write. Defaults to `0xCAFEBABEDEADBEEF`. Only one positional value may be given. |
| `-h`, `--help` | Print usage information. |

### Examples

```bash
# Resolve MyLabDriver!g_LabValue, write the default value
KernelWriteLab.exe

# Resolve MyLabDriver!g_LabValue, write a specific value
KernelWriteLab.exe 0x1234567890ABCDEF

# Write the default value to an explicit address
KernelWriteLab.exe --address 0xFFFFF80012345670

# Write a specific value to an explicit address
KernelWriteLab.exe --address 0xFFFFF80012345670 0xCAFEBABE

# Zero-fill 8 consecutive 8-byte slots starting at the given address
KernelWriteLab.exe --address 0xFFFFF80012345670 --count 8 0x0
```

## Using addresses from KernelCallbackInspector

If you use addresses from `KernelCallbackInspector` output, only the **array base address** (the `Address:` row in the header of each callback table, e.g. `nt!PspCreateProcessNotifyRoutine`) is a valid write target. Compute the slot address as `Address + SlotIndex * 8`, or pass the base with `--count N` to sweep the first `N` slots.

The other columns are **not** safe write destinations:

| Column | Why it is unsafe |
|--------|------------------|
| **Encoded entry** | Contains fast-reference tag bits in the low nibble. The tool rejects these as misaligned and prints an additional hint pointing at the tag-bit issue. |
| **Block** | Points to an internal `EX_CALLBACK_ROUTINE_BLOCK` kernel structure. Writing there can corrupt synchronization state or reference counts. |
| **Callback** | Points to executable code. Writing there overwrites instructions rather than changing the callback registration. Code pages may not be writable, and corrupting them can crash the system. |

## Validation

The tool rejects several classes of bad input before any kernel write is attempted:

- **Bad hex parsing.** `ParseHexU64` rejects leading `-` / `+` (which `_strtoui64` would otherwise silently wrap to a large positive value) and detects `errno == ERANGE` on overflow. `--count` uses the same `ERANGE` check.
- **Duplicate positional values.** A second bare hex value on the command line is an explicit error, not silently used.
- **Misaligned `--address`.** Values whose low three bits are non-zero are rejected. If the low nibble is non-zero, the tool additionally warns that the address may be an encoded callback entry with fast-reference tag bits.
- **Wrap-around ranges.** `targetAddress + slotCount * 8` is bounds-checked against the top of the 64-bit address space so a range near `UINT64_MAX` cannot silently wrap into low memory.

## Uncached I/O and rollback

Every read and write uses the `Uncached` variants:

- `IDebugDataSpaces::WriteVirtualUncached` bypasses the DbgEng cache so the bytes actually reach the live target.
- `IDebugDataSpaces::ReadVirtualUncached` on the verification read pulls fresh bytes back rather than seeing the cached write.

This eliminates the false-positive scenario where a plain `WriteVirtual` + `ReadVirtual` pair would both hit the cache and report success even if the kernel never observed the write.

Writes are classified into three outcomes:

| Outcome | Meaning | Behaviour |
|---------|---------|-----------|
| **Success** | All 8 bytes written. | Slot recorded; loop continues. |
| **HardError** | HRESULT failure or 0 bytes written. | Loop aborts; rollback runs. |
| **TornWrite** | Partial write (some bytes reached the target, but fewer than 8). | Loop aborts; rollback runs; the torn slot is included in the rollback set so the original value is restored. |

On any non-`Success` outcome (or a verification mismatch on read-back), the tool walks the recorded slots in reverse and writes each original value back through `WriteVirtualUncached`. Rollback is best-effort: if any restore itself partial-fails, the tool prints an explicit warning naming which slot may still contain the attempted write. Exit code is non-zero on any abort.

## Kernel safety warning

At startup, before any COM interface is created, the tool prints:

```
    +--------------------------------------------------------------+
    |                     KERNEL SAFETY WARNING                    |
    +--------------------------------------------------------------+
    | This tool writes directly to live kernel virtual memory.     |
    | It does NOT take the kernel locks or reference counts that   |
    | protect the target structure. Clearing a live callback slot  |
    | is not equivalent to unregistering the callback: an          |
    | in-flight dispatch racing your write can crash the system,   |
    | leak references, or corrupt state that only shows up later.  |
    | Use only on lab systems you can afford to reboot.            |
    +--------------------------------------------------------------+
```

This is an intentional runtime reminder — the tool does not take the kernel synchronization primitives that a proper `Ps*NotifyRoutine` unregister codepath would.

## Exit code

`0` on success. `1` on any of:

- Argument parse error, misaligned address, or wrap-around range.
- Debug client / interface creation, `AttachKernel`, or `WaitForEvent` failure.
- `GetOffsetByName` failure in symbol-resolution mode.
- Any read / write / verify failure during the batch — the rollback runs before exit.

Non-fatal `Reload` warnings (`nt`, `MyLabDriver.sys`) clear the stale `HRESULT` so they cannot leak into the exit code when the actual writes succeed.

## Notes

- The default symbol path includes both the Microsoft public symbol server (`srv*C:\Symbols*https://msdl.microsoft.com/download/symbols`) and `C:\LabSymbols` for the lab driver PDB.
- `--count` is capped at 64 slots (`kMaxSlotCount`) to keep the blast radius of a single invocation bounded.
- The tool has no `--dry-run` mode: every invocation that reaches the write loop attempts real kernel writes. Use snapshots.
