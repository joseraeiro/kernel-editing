#include <windows.h>
#include <dbgeng.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

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

bool ParseHexU64(const char* text, ULONG64& value) {
    if (!text || !*text) {
        return false;
    }

    char* end = nullptr;
    value = _strtoui64(text, &end, 0);
    return end && *end == '\0';
}

bool ReadU64(IDebugDataSpaces* dataSpaces, ULONG64 address, ULONG64& value) {
    value = 0;
    ULONG bytesRead = 0;
    HRESULT hr = dataSpaces->ReadVirtual(
        address,
        &value,
        static_cast<ULONG>(sizeof(value)),
        &bytesRead);

    if (FAILED(hr)) {
        PrintHr("ReadVirtual", hr);
        return false;
    }

    if (bytesRead != sizeof(value)) {
        std::cerr << "[-] ReadVirtual returned a short read: " << bytesRead << " bytes\n";
        return false;
    }

    return true;
}

bool WriteU64(IDebugDataSpaces* dataSpaces, ULONG64 address, ULONG64 value) {
    ULONG bytesWritten = 0;
    HRESULT hr = dataSpaces->WriteVirtual(
        address,
        &value,
        static_cast<ULONG>(sizeof(value)),
        &bytesWritten);

    if (FAILED(hr)) {
        PrintHr("WriteVirtual", hr);
        return false;
    }

    if (bytesWritten != sizeof(value)) {
        std::cerr << "[-] WriteVirtual returned a short write: " << bytesWritten << " bytes\n";
        return false;
    }

    return true;
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

} // namespace

int main(int argc, char** argv) {
    ULONG64 requestedValue = kDefaultWriteValue;
    ULONG64 explicitAddress = 0;
    ULONG64 targetAddress = 0;
    bool hasExplicitAddress = false;
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
            char* end = nullptr;
            long parsed = strtol(argv[argIndex + 1], &end, 10);
            if (!end || *end != '\0' || parsed < 1 || parsed > kMaxSlotCount) {
                std::cerr << "[-] --count must be between 1 and " << kMaxSlotCount << ".\n";
                return 1;
            }
            slotCount = static_cast<int>(parsed);
            argIndex += 2;
            continue;
        }

        if (!ParseHexU64(argv[argIndex], requestedValue)) {
            std::cerr << "[-] Could not parse the requested value as a 64-bit integer.\n";
            PrintUsage(argv[0]);
            return 1;
        }
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
    std::cout << "\n";

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

    {
        int succeeded = 0;
        int failed = 0;

        for (int slot = 0; slot < slotCount; ++slot) {
            ULONG64 slotAddress = targetAddress + slot * sizeof(ULONG64);

            if (slotCount > 1) {
                std::cout << "\n[*] Slot " << slot << " at 0x"
                          << std::hex << slotAddress << std::dec << "\n";
            }

            ULONG64 before = 0;
            if (!ReadU64(dataSpaces, slotAddress, before)) {
                ++failed;
                continue;
            }
            PrintValue("[+] Current value: ", before);

            if (!WriteU64(dataSpaces, slotAddress, requestedValue)) {
                ++failed;
                continue;
            }

            ULONG64 after = 0;
            if (!ReadU64(dataSpaces, slotAddress, after)) {
                ++failed;
                continue;
            }
            PrintValue("[+] New value:     ", after);

            if (after == requestedValue) {
                ++succeeded;
            } else {
                std::cout << "[!] Verification mismatch at slot " << slot << ".\n";
                ++failed;
            }
        }

        if (slotCount == 1) {
            std::cout << (failed == 0
                ? "[+] Verification successful.\n"
                : "[!] Verification mismatch. Investigate symbol correctness and paging state.\n");
        } else {
            std::cout << "\n[*] Summary: " << succeeded << "/" << slotCount
                      << " slots written and verified";
            if (failed > 0) {
                std::cout << ", " << failed << " failed";
            }
            std::cout << ".\n";
        }

        if (failed > 0) {
            hr = E_FAIL;
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
