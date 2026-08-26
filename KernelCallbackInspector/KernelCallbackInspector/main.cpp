#include <windows.h>
#include <dbgeng.h>

#include <array>
#include <cstdint>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>

#pragma comment(lib, "dbgeng.lib")

namespace {

constexpr std::size_t kCallbackSlots = 64;
constexpr ULONG64 kFastRefMask = ~0xFULL;
constexpr ULONG64 kCallbackFunctionOffset = 0x08;

struct CallbackArraySpec {
    const char* label;
    const char* symbol;
};

constexpr CallbackArraySpec kArrays[] = {
    {"Process", "nt!PspCreateProcessNotifyRoutine"},
    {"Thread",  "nt!PspCreateThreadNotifyRoutine"},
    {"Image",   "nt!PspLoadImageNotifyRoutine"},
};

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

std::string ModuleNameFromAddress(IDebugSymbols3* symbols, ULONG64 address) {
    ULONG index = DEBUG_ANY_ID;
    ULONG64 moduleBase = 0;

    HRESULT hr = symbols->GetModuleByOffset(address, 0, &index, &moduleBase);
    if (FAILED(hr)) {
        return "<unresolved module>";
    }

    char imageName[MAX_PATH] = {};
    ULONG required = 0;
    hr = symbols->GetModuleNameString(
        DEBUG_MODNAME_IMAGE,
        index,
        moduleBase,
        imageName,
        static_cast<ULONG>(sizeof(imageName)),
        &required);

    if (FAILED(hr)) {
        return "<module name unavailable>";
    }

    return imageName;
}

std::string SymbolNameFromAddress(IDebugSymbols3* symbols, ULONG64 address) {
    char name[1024] = {};
    ULONG nameSize = 0;
    ULONG64 displacement = 0;

    HRESULT hr = symbols->GetNameByOffset(
        address,
        name,
        static_cast<ULONG>(sizeof(name)),
        &nameSize,
        &displacement);

    if (FAILED(hr)) {
        return "<symbol unavailable>";
    }

    std::string result = name;
    if (displacement != 0) {
        result += "+0x";
        char buf[32] = {};
        sprintf_s(buf, "%llx", static_cast<unsigned long long>(displacement));
        result += buf;
    }
    return result;
}

bool ReadU64(IDebugDataSpaces* dataSpaces, ULONG64 address, ULONG64& value) {
    value = 0;
    ULONG bytesRead = 0;
    HRESULT hr = dataSpaces->ReadVirtual(
        address,
        &value,
        static_cast<ULONG>(sizeof(value)),
        &bytesRead);

    return SUCCEEDED(hr) && bytesRead == static_cast<ULONG>(sizeof(value));
}

void EnumerateCallbackArray(
    IDebugSymbols3* symbols,
    IDebugDataSpaces* dataSpaces,
    const CallbackArraySpec& spec) {

    ULONG64 arrayBase = 0;
    HRESULT hr = symbols->GetOffsetByName(spec.symbol, &arrayBase);
    if (FAILED(hr)) {
        std::cout << "\n[-] " << spec.label << " callbacks: could not resolve "
                  << spec.symbol << " (HRESULT=0x"
                  << std::hex << std::uppercase << static_cast<unsigned long>(hr)
                  << std::dec << std::nouppercase << ")\n";
        std::cout << "    This symbol may not be present in the public symbols for this build.\n";
        return;
    }

    std::array<ULONG64, kCallbackSlots> entries{};
    ULONG bytesRead = 0;
    hr = dataSpaces->ReadVirtual(
        arrayBase,
        entries.data(),
        static_cast<ULONG>(sizeof(entries)),
        &bytesRead);

    if (FAILED(hr)) {
        PrintHr("ReadVirtual(callback array)", hr);
        return;
    }

    const std::size_t readableSlots = bytesRead / sizeof(ULONG64);

    std::cout << "\n=== " << spec.label << " callbacks ===\n";
    std::cout << "Symbol : " << spec.symbol << "\n";
    std::cout << "Address: 0x" << std::hex << arrayBase << std::dec << "\n";
    std::cout << "Slots read: " << readableSlots << " / " << kCallbackSlots << "\n\n";

    std::cout << std::left
              << std::setw(6)  << "Slot"
              << std::setw(19) << "Encoded entry"
              << std::setw(19) << "Block"
              << std::setw(19) << "Callback"
              << std::setw(28) << "Owner"
              << "Symbol\n";
    std::cout << std::string(120, '-') << "\n";

    std::size_t active = 0;

    for (std::size_t i = 0; i < readableSlots; ++i) {
        const ULONG64 encoded = entries[i];
        if (encoded == 0) {
            continue;
        }

        ++active;
        const ULONG64 block = encoded & kFastRefMask;
        ULONG64 callback = 0;

        const bool callbackReadable =
            ReadU64(dataSpaces, block + kCallbackFunctionOffset, callback);

        std::string owner = callbackReadable && callback
            ? ModuleNameFromAddress(symbols, callback)
            : "<unreadable>";

        std::string callbackSymbol = callbackReadable && callback
            ? SymbolNameFromAddress(symbols, callback)
            : "<unreadable>";

        std::cout << std::left << std::setw(6) << i;

        auto printHexColumn = [](ULONG64 value, int width) {
            std::ostringstream oss;
            oss << "0x" << std::hex << value;
            std::cout << std::left << std::setw(width) << oss.str();
        };

        printHexColumn(encoded, 19);
        printHexColumn(block, 19);
        printHexColumn(callback, 19);
        std::cout << std::left << std::setw(28) << owner
                  << callbackSymbol << "\n";
    }

    if (active == 0) {
        std::cout << "<no populated entries found>\n";
    }

    std::cout << "\nActive entries: " << active << "\n";
}

} // namespace

int main() {
    std::cout << "KernelCallbackInspector - read-only local kernel callback enumerator\n";
    std::cout << "No kernel memory writes are performed by this program.\n\n";

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

    // Microsoft public symbol server. The cache directory is local to the VM.
    hr = symbols->SetSymbolPath("srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols");
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

    std::cout << "[*] Kernel session attached. Resolving symbols...\n";

    // Force/reload nt symbols. Failure is not fatal; GetOffsetByName below will
    // still attempt normal on-demand symbol loading.
    hr = symbols->Reload("/f nt");
    if (FAILED(hr)) {
        std::cerr << "[!] nt symbol reload returned HRESULT=0x"
                  << std::hex << std::uppercase << static_cast<unsigned long>(hr)
                  << std::dec << std::nouppercase << "; continuing.\n";
    }

    for (const auto& spec : kArrays) {
        EnumerateCallbackArray(symbols, dataSpaces, spec);
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
