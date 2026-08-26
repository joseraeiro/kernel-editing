# KernelWriteLab

> **Disclaimer:** This tool is provided strictly for educational and authorized security research purposes. It is intended to be used only in isolated, snapshotted, disposable lab virtual machines. Do not use this tool on production systems, corporate networks, or any environment where unauthorized modification of kernel memory could cause harm, data loss, or violate applicable laws and regulations. The authors assume no liability for misuse. By using this software, you agree that you are solely responsible for ensuring you have proper authorization and that your use complies with all applicable laws and your organization's policies.

A lab tool that demonstrates constrained use of `IDebugDataSpaces::WriteVirtual` through the Windows Debugging SDK. It attaches to the local kernel debugger, reads a 64-bit value at a target address, writes a replacement, and reads back the result to verify.

## What it does

1. Attaches to the local kernel debugger via `DEBUG_ATTACH_LOCAL_KERNEL`
2. Resolves the target address (either via symbol lookup or an explicit `--address` argument)
3. Reads the current 64-bit value at that address
4. Writes the requested replacement value
5. Reads the value back and verifies it matches

## Prerequisites

- Windows 10/11 x64
- Visual Studio 2022 (v143 toolset) with the Windows SDK
- Local kernel debugging enabled (`bcdedit /debug on`, then reboot)
- Run as Administrator
- When using symbol resolution (default mode): `MyLabDriver.sys` loaded and its PDB available at `C:\LabSymbols` or another path on the configured symbol path

## Building

**Developer Command Prompt:**

```
cl /EHsc /W4 /std:c++17 /O2 KernelWriteLab\UserMode\main.cpp /Fe:KernelWriteLab.exe
```

The `#pragma comment(lib, "dbgeng.lib")` directive handles linking automatically.

## Usage

```
KernelWriteLab.exe [--address hex-addr] [hex-value]
```

| Argument | Description |
|----------|-------------|
| `--address hex-addr` | Use a raw virtual address instead of resolving `MyLabDriver!g_LabValue` via symbols. Must be 8-byte aligned. |
| `hex-value` | The 64-bit value to write. Defaults to `0xCAFEBABEDEADBEEF`. |
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
```

## Using addresses from KernelCallbackInspector

If you use addresses from KernelCallbackInspector output, only the **array base address** (the `Address` row in the header of each callback table) is a valid write target. Compute the slot address as `Address + SlotIndex * 8`.

The other columns are **not** safe write destinations:

| Column | Why it is unsafe |
|--------|------------------|
| **Encoded entry** | Contains fast-reference tag bits in the low nibble. The tool rejects these as misaligned and hints at the tag-bit issue. |
| **Block** | Points to an internal `EX_CALLBACK_ROUTINE_BLOCK` kernel structure. Writing there can corrupt synchronization state or reference counts. |
| **Callback** | Points to executable code. Writing there overwrites instructions rather than changing the callback registration. Code pages may not be writable, and corrupting them can crash the system. |

## Validation

The tool rejects `--address` values that are not 8-byte aligned. When the low nibble is non-zero, it prints an additional hint that the address may be an encoded callback entry with fast-reference tag bits.

## Notes

- The default symbol path includes both the Microsoft public symbol server (`srv*C:\Symbols*https://msdl.microsoft.com/download/symbols`) and `C:\LabSymbols` for the lab driver PDB.
- The tool performs a read-write-verify cycle: if the read-back value does not match the written value, it reports a verification mismatch.
