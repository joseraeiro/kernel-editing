#include <windows.h>
#include <dbgeng.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "dbgeng.lib")

namespace {

constexpr const char* kTargetSymbol = "MyLabDriver!g_LabValue";
constexpr ULONG64 kDefaultWriteValue = 0xCAFEBABEDEADBEEFULL;
constexpr const char* kDefaultSymbolPath = "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols;C:\\LabSymbols";
constexpr ULONG64 kPointerAlignmentMask = 0x7;
constexpr ULONG64 kFastRefTagMask = 0xF;
constexpr int kMaxSlotCount = 64;

template <typename T>
void SafeRelease(T*& ptr) {
    if (ptr) {
        ptr->Release();
        ptr = nullptr;
    }
}

void PrintHr(const char* what, HRESULT hr) {
    std::cerr << "[-] " << what << " failed: HRESULT=0x"
              << std::hex << std::uppercase << static_cast<unsigned long>(hr)
              << std::dec << std::nouppercase << "\n";
}

// _strtoui64 silently accepts a leading '-' (wraps it to a large positive
// value) and returns _UI64_MAX on overflow with errno=ERANGE. Reject both.
bool ParseHexU64(const char* text, ULONG64& value) {
    if (!text || !*text) {
        return false;
    }

    const char* p = text;
    while (*p == ' ' || *p == '\t') {
        ++p;
    }
    if (*p == '\0' || *p == '-' || *p == '+') {
        return false;
    }

    errno = 0;
    char* end = nullptr;
    value = _strtoui64(p, &end, 0);
    if (errno == ERANGE) {
        return false;
    }
    return end && *end == '\0';
}

bool ReadU64Uncached(IDebugDataSpaces* dataSpaces, ULONG64 address, ULONG64& value) {
    value = 0;
    ULONG bytesRead = 0;
    HRESULT hr = dataSpaces->ReadVirtualUncached(
        address,
        &value,
        static_cast<ULONG>(sizeof(value)),
        &bytesRead);

    if (FAILED(hr)) {
        PrintHr("ReadVirtualUncached", hr);
        return false;
    }

    if (bytesRead != sizeof(value)) {
        std::cerr << "[-] ReadVirtualUncached returned a short read: " << bytesRead << " bytes\n";
        return false;
    }

    return true;
}

enum class WriteOutcome {
    Success,
    HardError,   // nothing was written, or HRESULT failure
    TornWrite,   // some bytes hit the target; the 64-bit pointer is now split
};

// WriteVirtual on the standard IDebugDataSpaces path can be satisfied from the
// engine's cache; the read-back would then be a false positive. Use the
// uncached variant so the write goes through to the live target and the
// verification read pulls fresh bytes back.
WriteOutcome WriteU64Uncached(IDebugDataSpaces* dataSpaces, ULONG64 address, ULONG64 value) {
    ULONG bytesWritten = 0;
    HRESULT hr = dataSpaces->WriteVirtualUncached(
        address,
        &value,
        static_cast<ULONG>(sizeof(value)),
        &bytesWritten);

    if (FAILED(hr)) {
        PrintHr("WriteVirtualUncached", hr);
        return WriteOutcome::HardError;
    }

    if (bytesWritten == 0) {
        std::cerr << "[-] WriteVirtualUncached wrote 0 bytes to 0x"
                  << std::hex << address << std::dec << "\n";
        return WriteOutcome::HardError;
    }

    if (bytesWritten != sizeof(value)) {
        std::cerr << "[!!!] WriteVirtualUncached wrote a PARTIAL " << bytesWritten
                  << " bytes to 0x" << std::hex << address << std::dec << "\n"
                  << "      A 64-bit kernel pointer is now torn. Aborting the batch\n"
                  << "      and attempting best-effort rollback.\n";
        return WriteOutcome::TornWrite;
    }

    return WriteOutcome::Success;
}

void PrintValue(const char* label, ULONG64 value) {
    std::cout << label << " 0x"
              << std::hex << std::setw(16) << std::setfill('0') << value
              << std::dec << std::setfill(' ') << "\n";
}

void PrintUsage(const char* exeName) {
    std::cout << "Usage: " << exeName << " [--address hex-addr] [--count N] [hex-value]\n\n"
              << "This lab tool attaches to the local kernel debugger, reads the current\n"
              << "64-bit value at the target, writes a replacement value, and reads it again.\n\n"
              << "Options:\n"
              << "  --address hex-addr  Use a raw virtual address instead of resolving\n"
              << "                      " << kTargetSymbol << " via symbols.\n"
              << "                      The address must be 8-byte aligned.\n"
              << "  --count N           Write the value to N consecutive 8-byte slots\n"
              << "                      starting from the target address (max "
              << kMaxSlotCount << ").\n"
              << "                      Requires --address.\n\n"
              << "Examples:\n"
              << "  " << exeName << "\n"
              << "  " << exeName << " 0x1234567890ABCDEF\n"
              << "  " << exeName << " --address 0xFFFFF80012345670\n"
              << "  " << exeName << " --address 0xFFFFF80012345670 0xCAFEBABE\n"
              << "  " << exeName << " --address 0xFFFFF80012345670 --count 8 0x0\n\n"
              << "When using addresses from KernelCallbackInspector output:\n"
              << "  * 'Address' (array base) is the correct column to target a slot.\n"
              << "    Compute the slot address as: Address + SlotIndex * 8.\n"
              << "    Use --count to write across multiple consecutive slots.\n"
              << "  * 'Encoded entry' contains fast-reference tag bits in the low nibble\n"
              << "    and must not be used directly as a write destination.\n"
              << "  * 'Block' points to an internal kernel structure; writing there can\n"
              << "    corrupt synchronization state or reference counts.\n"
              << "  * 'Callback' points to executable code; writing there would overwrite\n"
              << "    instructions rather than change the callback registration.\n\n"
              << "Notes:\n"
              << "  * Copy MyLabDriver.pdb to C:\\LabSymbols, or update kDefaultSymbolPath.\n"
              << "  * Run as Administrator after enabling local kernel debugging and rebooting.\n";
}

void PrintKernelSafetyWarning() {
    std::cout << "\n"
              << "    +--------------------------------------------------------------+\n"
              << "    |                     KERNEL SAFETY WARNING                    |\n"
              << "    +--------------------------------------------------------------+\n"
              << "    | This tool writes directly to live kernel virtual memory.     |\n"
              << "    | It does NOT take the kernel locks or reference counts that   |\n"
              << "    | protect the target structure. Clearing a live callback slot  |\n"
              << "    | is not equivalent to unregistering the callback: an          |\n"
              << "    | in-flight dispatch racing your write can crash the system,   |\n"
              << "    | leak references, or corrupt state that only shows up later.  |\n"
              << "    | Use only on lab systems you can afford to reboot.            |\n"
              << "    +--------------------------------------------------------------+\n\n";
}

struct WrittenSlot {
    ULONG64 address;
    ULONG64 originalValue;
};

// Best-effort restore of every slot we successfully modified. There is no
// guarantee the restore itself won't partial-fail; when that happens the tool
// reports it so the operator knows the kernel is still in a divergent state.
void RollbackWrittenSlots(IDebugDataSpaces* dataSpaces,
                          const std::vector<WrittenSlot>& modified) {
    if (modified.empty()) {
        return;
    }

    std::cerr << "[!] Attempting rollback of " << modified.size()
              << " previously written slot(s)...\n";

    std::size_t restored = 0;
    std::size_t rollbackFailed = 0;
    for (auto it = modified.rbegin(); it != modified.rend(); ++it) {
        WriteOutcome outcome = WriteU64Uncached(dataSpaces, it->address, it->originalValue);
        if (outcome == WriteOutcome::Success) {
            ++restored;
        } else {
            ++rollbackFailed;
            std::cerr << "[!!!] Rollback of slot at 0x" << std::hex << it->address
                      << std::dec << " failed.\n";
        }
    }

    if (rollbackFailed == 0) {
        std::cerr << "[+] Rolled back all " << restored << " slot(s).\n";
    } else {
        std::cerr << "[!!!] Rolled back " << restored << " / " << modified.size()
                  << " slot(s); " << rollbackFailed
                  << " slot(s) may still contain the attempted write.\n";
    }
}

} // namespace

int main(int argc, char** argv) {
    ULONG64 requestedValue = kDefaultWriteValue;
    ULONG64 explicitAddress = 0;
    ULONG64 targetAddress = 0;
    bool hasExplicitAddress = false;
    bool hasRequestedValue = false;
    int slotCount = 1;

    int argIndex = 1;
    while (argIndex < argc) {
        std::string arg(argv[argIndex]);

        if (arg == "-h" || arg == "--help") {
            PrintUsage(argv[0]);
            return 0;
        }

        if (arg == "--address") {
            if (argIndex + 1 >= argc) {
                std::cerr << "[-] --address requires a hex address argument.\n";
                PrintUsage(argv[0]);
                return 1;
            }
            if (!ParseHexU64(argv[argIndex + 1], explicitAddress)) {
                std::cerr << "[-] Could not parse the address as a 64-bit integer.\n";
                PrintUsage(argv[0]);
                return 1;
            }
            if (explicitAddress & kPointerAlignmentMask) {
                std::cerr << "[-] Address 0x" << std::hex << explicitAddress << std::dec
                          << " is not 8-byte aligned.\n";
                if (explicitAddress & kFastRefTagMask) {
                    std::cerr << "    The low nibble is non-zero, which suggests this may be an\n"
                              << "    encoded callback entry with fast-reference tag bits.\n"
                              << "    Use the array base address + slot offset instead.\n";
                }
                return 1;
            }
            hasExplicitAddress = true;
            argIndex += 2;
            continue;
        }

        if (arg == "--count") {
            if (argIndex + 1 >= argc) {
                std::cerr << "[-] --count requires a numeric argument.\n";
                PrintUsage(argv[0]);
                return 1;
            }
            errno = 0;
            char* end = nullptr;
            long parsed = strtol(argv[argIndex + 1], &end, 10);
            if (!end || *end != '\0' || errno == ERANGE ||
                parsed < 1 || parsed > kMaxSlotCount) {
                std::cerr << "[-] --count must be an integer between 1 and "
                          << kMaxSlotCount << ".\n";
                return 1;
            }
            slotCount = static_cast<int>(parsed);
            argIndex += 2;
            continue;
        }

        if (hasRequestedValue) {
            std::cerr << "[-] Multiple positional hex values are ambiguous; "
                      << "got both a prior value and '" << argv[argIndex] << "'.\n";
            PrintUsage(argv[0]);
            return 1;
        }
        if (!ParseHexU64(argv[argIndex], requestedValue)) {
            std::cerr << "[-] Could not parse the requested value as a 64-bit integer.\n";
            PrintUsage(argv[0]);
            return 1;
        }
        hasRequestedValue = true;
        ++argIndex;
    }

    if (slotCount > 1 && !hasExplicitAddress) {
        std::cerr << "[-] --count requires --address.\n";
        PrintUsage(argv[0]);
        return 1;
    }

    std::cout << "KernelWriteLab - constrained WriteVirtual demonstration\n";
    if (hasExplicitAddress) {
        PrintValue("Target address:    ", explicitAddress);
        if (slotCount > 1) {
            std::cout << "Slot count:         " << slotCount << " (8 bytes each)\n";
        }
    } else {
        std::cout << "Target symbol: " << kTargetSymbol << "\n";
    }
    PrintValue("Requested new value:", requestedValue);

    PrintKernelSafetyWarning();

    IDebugClient* client = nullptr;
    IDebugControl* control = nullptr;
    IDebugSymbols3* symbols = nullptr;
    IDebugDataSpaces* dataSpaces = nullptr;

    HRESULT hr = DebugCreate(__uuidof(IDebugClient), reinterpret_cast<void**>(&client));
    if (FAILED(hr)) {
        PrintHr("DebugCreate", hr);
        return 1;
    }

    hr = client->QueryInterface(__uuidof(IDebugControl), reinterpret_cast<void**>(&control));
    if (FAILED(hr)) {
        PrintHr("QueryInterface(IDebugControl)", hr);
        SafeRelease(client);
        return 1;
    }

    hr = client->QueryInterface(__uuidof(IDebugSymbols3), reinterpret_cast<void**>(&symbols));
    if (FAILED(hr)) {
        PrintHr("QueryInterface(IDebugSymbols3)", hr);
        SafeRelease(control);
        SafeRelease(client);
        return 1;
    }

    hr = client->QueryInterface(__uuidof(IDebugDataSpaces), reinterpret_cast<void**>(&dataSpaces));
    if (FAILED(hr)) {
        PrintHr("QueryInterface(IDebugDataSpaces)", hr);
        SafeRelease(symbols);
        SafeRelease(control);
        SafeRelease(client);
        return 1;
    }

    hr = symbols->SetSymbolPath(kDefaultSymbolPath);
    if (FAILED(hr)) {
        PrintHr("SetSymbolPath", hr);
        std::cerr << "[!] Continuing with the debugger engine's existing symbol configuration.\n";
    }

    std::cout << "[*] Attaching to the local kernel debugger...\n";
    hr = client->AttachKernel(DEBUG_ATTACH_LOCAL_KERNEL, nullptr);
    if (FAILED(hr)) {
        PrintHr("AttachKernel(DEBUG_ATTACH_LOCAL_KERNEL)", hr);
        std::cerr << "    Run elevated, enable local kernel debugging, and reboot first.\n";
        goto cleanup;
    }

    std::cout << "[*] Waiting for the local kernel debugging session to initialize...\n";
    hr = control->WaitForEvent(DEBUG_WAIT_DEFAULT, INFINITE);
    if (FAILED(hr)) {
        PrintHr("WaitForEvent", hr);
        goto cleanup;
    }

    std::cout << "[*] Kernel session attached. Reloading symbols...\n";
    hr = symbols->Reload("/f nt");
    if (FAILED(hr)) {
        std::cerr << "[!] nt symbol reload returned HRESULT=0x"
                  << std::hex << std::uppercase << static_cast<unsigned long>(hr)
                  << std::dec << std::nouppercase << "; continuing.\n";
    }

    if (!hasExplicitAddress) {
        hr = symbols->Reload("/f MyLabDriver.sys");
        if (FAILED(hr)) {
            std::cerr << "[!] MyLabDriver.sys symbol reload returned HRESULT=0x"
                      << std::hex << std::uppercase << static_cast<unsigned long>(hr)
                      << std::dec << std::nouppercase << "; continuing.\n";
        }
    }

    // Reload warnings above are non-fatal; clear hr so a warning-only failure
    // does not leak into the final exit code below.
    hr = S_OK;

    if (hasExplicitAddress) {
        targetAddress = explicitAddress;
        std::cout << "[*] Using explicit address 0x"
                  << std::hex << targetAddress << std::dec << "\n";
    } else {
        hr = symbols->GetOffsetByName(kTargetSymbol, &targetAddress);
        if (FAILED(hr)) {
            PrintHr("GetOffsetByName(MyLabDriver!g_LabValue)", hr);
            std::cerr << "    Ensure the driver is loaded and its PDB is reachable via the symbol path.\n";
            goto cleanup;
        }

        std::cout << "[*] Resolved " << kTargetSymbol << " at 0x"
                  << std::hex << targetAddress << std::dec << "\n";
    }

    // slotCount is bounded by kMaxSlotCount (currently 64), so rangeBytes itself
    // can't overflow; the concern is targetAddress + (rangeBytes - 1) wrapping
    // the 64-bit address space near the top.
    {
        const ULONG64 rangeBytes = static_cast<ULONG64>(slotCount) * sizeof(ULONG64);
        const ULONG64 addressMax = ~static_cast<ULONG64>(0);
        if (targetAddress > addressMax - (rangeBytes - 1)) {
            std::cerr << "[-] Target address 0x" << std::hex << targetAddress
                      << " with slot count " << std::dec << slotCount
                      << " would wrap the 64-bit address space.\n";
            hr = E_INVALIDARG;
            goto cleanup;
        }
    }

    {
        std::vector<WrittenSlot> modified;
        modified.reserve(static_cast<std::size_t>(slotCount));
        bool aborted = false;
        int processed = 0;

        for (int slot = 0; slot < slotCount; ++slot) {
            ULONG64 slotAddress = targetAddress +
                static_cast<ULONG64>(slot) * sizeof(ULONG64);

            if (slotCount > 1) {
                std::cout << "\n[*] Slot " << slot << " at 0x"
                          << std::hex << slotAddress << std::dec << "\n";
            }

            ULONG64 before = 0;
            if (!ReadU64Uncached(dataSpaces, slotAddress, before)) {
                aborted = true;
                break;
            }
            PrintValue("[+] Current value: ", before);

            WriteOutcome outcome = WriteU64Uncached(dataSpaces, slotAddress, requestedValue);
            if (outcome != WriteOutcome::Success) {
                if (outcome == WriteOutcome::TornWrite) {
                    // Record the torn slot too so rollback tries to restore it.
                    modified.push_back({slotAddress, before});
                }
                aborted = true;
                break;
            }
            modified.push_back({slotAddress, before});

            ULONG64 after = 0;
            if (!ReadU64Uncached(dataSpaces, slotAddress, after)) {
                aborted = true;
                break;
            }
            PrintValue("[+] New value:     ", after);

            if (after != requestedValue) {
                std::cerr << "[!] Verification mismatch at slot " << slot
                          << ": uncached read-back does not match the requested value.\n";
                aborted = true;
                break;
            }
            ++processed;
        }

        if (aborted) {
            RollbackWrittenSlots(dataSpaces, modified);
            hr = E_FAIL;
        } else if (slotCount == 1) {
            std::cout << "[+] Verification successful.\n";
        } else {
            std::cout << "\n[*] Summary: " << processed << "/" << slotCount
                      << " slots written and verified.\n";
        }
    }

cleanup:
    if (client) {
        client->EndSession(DEBUG_END_ACTIVE_DETACH);
    }

    SafeRelease(dataSpaces);
    SafeRelease(symbols);
    SafeRelease(control);
    SafeRelease(client);

    return FAILED(hr) ? 1 : 0;
}
