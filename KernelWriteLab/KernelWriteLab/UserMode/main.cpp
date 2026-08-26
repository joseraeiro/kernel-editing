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
    std::cout << "Usage: " << exeName << " [hex-value]\n\n"
              << "This lab tool attaches to the local kernel debugger, resolves "
              << kTargetSymbol << ",\n"
              << "reads the current 64-bit value, writes a replacement value, and reads it again.\n\n"
              << "Examples:\n"
              << "  " << exeName << "\n"
              << "  " << exeName << " 0x1234567890ABCDEF\n\n"
              << "Notes:\n"
              << "  * Copy MyLabDriver.pdb to C:\\LabSymbols, or update kDefaultSymbolPath.\n"
              << "  * Run as Administrator after enabling local kernel debugging and rebooting.\n";
}

} // namespace

int main(int argc, char** argv) {
    ULONG64 requestedValue = kDefaultWriteValue;

    if (argc >= 2) {
        if (std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help") {
            PrintUsage(argv[0]);
            return 0;
        }

        if (!ParseHexU64(argv[1], requestedValue)) {
            std::cerr << "[-] Could not parse the requested value as a 64-bit integer.\n";
            PrintUsage(argv[0]);
            return 1;
        }
    }

    std::cout << "KernelWriteLab - constrained WriteVirtual demonstration\n";
    std::cout << "Target symbol: " << kTargetSymbol << "\n";
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
    hr = symbols->Reload("/f nt; .reload /f MyLabDriver.sys");
    if (FAILED(hr)) {
        std::cerr << "[!] Symbol reload returned HRESULT=0x"
                  << std::hex << std::uppercase << static_cast<unsigned long>(hr)
                  << std::dec << std::nouppercase << "; continuing.\n";
    }

    ULONG64 targetAddress = 0;
    hr = symbols->GetOffsetByName(kTargetSymbol, &targetAddress);
    if (FAILED(hr)) {
        PrintHr("GetOffsetByName(MyLabDriver!g_LabValue)", hr);
        std::cerr << "    Ensure the driver is loaded and its PDB is reachable via the symbol path.\n";
        goto cleanup;
    }

    std::cout << "[*] Resolved " << kTargetSymbol << " at 0x"
              << std::hex << targetAddress << std::dec << "\n";

    ULONG64 before = 0;
    if (!ReadU64(dataSpaces, targetAddress, before)) {
        goto cleanup;
    }
    PrintValue("[+] Current value: ", before);

    if (!WriteU64(dataSpaces, targetAddress, requestedValue)) {
        goto cleanup;
    }
    std::cout << "[+] WriteVirtual completed successfully.\n";

    ULONG64 after = 0;
    if (!ReadU64(dataSpaces, targetAddress, after)) {
        goto cleanup;
    }
    PrintValue("[+] New value:     ", after);

    if (after == requestedValue) {
        std::cout << "[+] Verification successful.\n";
    } else {
        std::cout << "[!] Verification mismatch. Investigate symbol correctness and paging state.\n";
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
