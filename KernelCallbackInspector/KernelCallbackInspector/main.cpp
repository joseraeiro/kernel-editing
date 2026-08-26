#define PSAPI_VERSION 1

#include <windows.h>
#include <psapi.h>
#include <dbgeng.h>

#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "dbgeng.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "advapi32.lib")

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

    struct DriverInfo {
        ULONG64 base = 0;
        ULONG size = 0;
        std::string name;
        std::string path;
    };

    template <typename T>
    void SafeRelease(T*& ptr)
    {
        if (ptr) {
            ptr->Release();
            ptr = nullptr;
        }
    }

    void PrintHr(const char* what, HRESULT hr)
    {
        std::cerr
            << "[-] " << what
            << " failed: HRESULT=0x"
            << std::hex
            << std::uppercase
            << static_cast<unsigned long>(hr)
            << std::dec
            << std::nouppercase
            << "\n";
    }

    /*
     * ------------------------------------------------------------
     * Privilege handling
     * ------------------------------------------------------------
     */

    bool EnableDebugPrivilege()
    {
        HANDLE token = nullptr;

        if (!OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &token))
        {
            std::cerr
                << "[-] OpenProcessToken failed: "
                << GetLastError()
                << "\n";

            return false;
        }

        LUID luid{};

        if (!LookupPrivilegeValueW(
            nullptr,
            SE_DEBUG_NAME,
            &luid))
        {
            std::cerr
                << "[-] LookupPrivilegeValue(SE_DEBUG_NAME) failed: "
                << GetLastError()
                << "\n";

            CloseHandle(token);
            return false;
        }

        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        SetLastError(ERROR_SUCCESS);

        if (!AdjustTokenPrivileges(
            token,
            FALSE,
            &tp,
            sizeof(tp),
            nullptr,
            nullptr))
        {
            std::cerr
                << "[-] AdjustTokenPrivileges failed: "
                << GetLastError()
                << "\n";

            CloseHandle(token);
            return false;
        }

        DWORD error = GetLastError();

        CloseHandle(token);

        if (error == ERROR_NOT_ALL_ASSIGNED) {
            std::cerr
                << "[-] SeDebugPrivilege is not present in this token.\n";
            return false;
        }

        if (error != ERROR_SUCCESS) {
            std::cerr
                << "[-] Enabling SeDebugPrivilege returned error "
                << error
                << "\n";

            return false;
        }

        return true;
    }

    /*
     * ------------------------------------------------------------
     * Basic DbgEng helpers
     * ------------------------------------------------------------
     */

    void PrintLoadedDbgEngPath()
    {
        HMODULE dbgeng = GetModuleHandleA("dbgeng.dll");

        if (!dbgeng) {
            std::cout
                << "[!] dbgeng.dll not loaded.\n";
            return;
        }

        char path[MAX_PATH] = {};

        DWORD length = GetModuleFileNameA(
            dbgeng,
            path,
            static_cast<DWORD>(sizeof(path)));

        if (length == 0) {
            std::cout
                << "[!] Could not determine dbgeng.dll path.\n";
            return;
        }

        std::cout
            << "[*] Loaded dbgeng.dll: "
            << path
            << "\n";
    }

    bool ReadVirtualExact(
        IDebugDataSpaces* dataSpaces,
        ULONG64 address,
        void* buffer,
        ULONG size)
    {
        ULONG bytesRead = 0;

        HRESULT hr = dataSpaces->ReadVirtual(
            address,
            buffer,
            size,
            &bytesRead);

        return
            SUCCEEDED(hr) &&
            bytesRead == size;
    }

    bool ReadU64(
        IDebugDataSpaces* dataSpaces,
        ULONG64 address,
        ULONG64& value)
    {
        value = 0;

        return ReadVirtualExact(
            dataSpaces,
            address,
            &value,
            static_cast<ULONG>(sizeof(value)));
    }

    /*
     * ------------------------------------------------------------
     * Determine SizeOfImage from the loaded driver's PE header.
     *
     * EnumDeviceDrivers gives us the load address, but not the size.
     * Since we already have read-only kernel memory access through
     * DbgEng, read the PE header and obtain SizeOfImage.
     * ------------------------------------------------------------
     */

    ULONG GetKernelImageSize(
        IDebugDataSpaces* dataSpaces,
        ULONG64 imageBase)
    {
        IMAGE_DOS_HEADER dos{};

        if (!ReadVirtualExact(
            dataSpaces,
            imageBase,
            &dos,
            sizeof(dos)))
        {
            return 0;
        }

        if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
            return 0;
        }

        /*
         * Protect against obviously broken/corrupt e_lfanew values.
         */
        if (dos.e_lfanew <= 0 ||
            dos.e_lfanew > 0x100000)
        {
            return 0;
        }

        IMAGE_NT_HEADERS64 nt{};

        if (!ReadVirtualExact(
            dataSpaces,
            imageBase +
            static_cast<ULONG64>(dos.e_lfanew),
            &nt,
            sizeof(nt)))
        {
            return 0;
        }

        if (nt.Signature != IMAGE_NT_SIGNATURE) {
            return 0;
        }

        if (nt.OptionalHeader.Magic !=
            IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            return 0;
        }

        return nt.OptionalHeader.SizeOfImage;
    }

    /*
     * ------------------------------------------------------------
     * Enumerate loaded kernel drivers independently of DbgEng.
     * ------------------------------------------------------------
     */

    std::vector<DriverInfo> EnumerateKernelDrivers(
        IDebugDataSpaces* dataSpaces)
    {
        std::vector<DriverInfo> result;

        DWORD needed = 0;

        /*
         * Start with room for 512 drivers.
         */
        std::vector<LPVOID> bases(512);

        while (true) {

            DWORD bufferBytes =
                static_cast<DWORD>(
                    bases.size() * sizeof(LPVOID));

            needed = 0;

            if (!EnumDeviceDrivers(
                bases.data(),
                bufferBytes,
                &needed))
            {
                std::cerr
                    << "[-] EnumDeviceDrivers failed: "
                    << GetLastError()
                    << "\n";

                return result;
            }

            if (needed <= bufferBytes) {
                break;
            }

            bases.resize(
                (needed / sizeof(LPVOID)) + 64);
        }

        const std::size_t count =
            needed / sizeof(LPVOID);

        result.reserve(count);

        for (std::size_t i = 0; i < count; ++i) {

            if (!bases[i]) {
                continue;
            }

            const ULONG64 base =
                reinterpret_cast<ULONG64>(bases[i]);

            char name[MAX_PATH] = {};
            char path[1024] = {};

            if (!GetDeviceDriverBaseNameA(
                bases[i],
                name,
                static_cast<DWORD>(sizeof(name))))
            {
                strcpy_s(
                    name,
                    "<unknown>");
            }

            if (!GetDeviceDriverFileNameA(
                bases[i],
                path,
                static_cast<DWORD>(sizeof(path))))
            {
                strcpy_s(
                    path,
                    name);
            }

            ULONG size =
                GetKernelImageSize(
                    dataSpaces,
                    base);

            DriverInfo driver;

            driver.base = base;
            driver.size = size;
            driver.name = name;
            driver.path = path;

            result.push_back(
                std::move(driver));
        }

        return result;
    }

    /*
     * ------------------------------------------------------------
     * Find which loaded driver owns an address.
     * ------------------------------------------------------------
     */

    const DriverInfo* FindDriverByAddress(
        const std::vector<DriverInfo>& drivers,
        ULONG64 address)
    {
        for (const auto& driver : drivers) {

            if (!driver.base ||
                !driver.size)
            {
                continue;
            }

            const ULONG64 end =
                driver.base +
                static_cast<ULONG64>(driver.size);

            if (address >= driver.base &&
                address < end)
            {
                return &driver;
            }
        }

        return nullptr;
    }

    std::string OwnerFromAddress(
        const std::vector<DriverInfo>& drivers,
        ULONG64 address)
    {
        const DriverInfo* driver =
            FindDriverByAddress(
                drivers,
                address);

        if (!driver) {
            return "<unresolved module>";
        }

        return driver->name;
    }

    /*
     * ------------------------------------------------------------
     * Symbol resolution.
     *
     * First ask DbgEng for a real symbol.
     *
     * For modules that DbgEng doesn't know about, fall back to
     *
     *     driver.sys+0xRVA
     *
     * using our independently enumerated kernel module list.
     * ------------------------------------------------------------
     */

    std::string SymbolFromAddress(
        IDebugSymbols3* symbols,
        const std::vector<DriverInfo>& drivers,
        ULONG64 address)
    {
        char name[1024] = {};
        ULONG nameSize = 0;
        ULONG64 displacement = 0;

        HRESULT hr = symbols->GetNameByOffset(
            address,
            name,
            static_cast<ULONG>(sizeof(name)),
            &nameSize,
            &displacement);

        if (SUCCEEDED(hr)) {

            std::ostringstream oss;

            oss << name;

            if (displacement != 0) {
                oss
                    << "+0x"
                    << std::hex
                    << displacement;
            }

            return oss.str();
        }

        /*
         * DbgEng could not resolve it.
         *
         * Use our own driver list.
         */
        const DriverInfo* driver =
            FindDriverByAddress(
                drivers,
                address);

        if (!driver) {
            return "<symbol unavailable>";
        }

        const ULONG64 rva =
            address - driver->base;

        std::ostringstream oss;

        oss
            << driver->name
            << "+0x"
            << std::hex
            << rva;

        return oss.str();
    }

    /*
     * ------------------------------------------------------------
     * Resolve nt!_EX_CALLBACK_ROUTINE_BLOCK::Function offset from
     * type information rather than hard-coding it.
     *
     * The struct layout is undocumented; if a future Windows build
     * changes it, hard-coding 0x08 would silently misinterpret the
     * callback array. Ask DbgEng for the offset and fall back to
     * 0x08 only if type info is unavailable.
     * ------------------------------------------------------------
     */

    ULONG ResolveCallbackFunctionOffset(
        IDebugSymbols3* symbols)
    {
        ULONG typeId = 0;
        ULONG64 moduleBase = 0;

        HRESULT hr = symbols->GetSymbolTypeId(
            "nt!_EX_CALLBACK_ROUTINE_BLOCK",
            &typeId,
            &moduleBase);

        if (FAILED(hr)) {
            std::cout
                << "[!] nt!_EX_CALLBACK_ROUTINE_BLOCK type not available; "
                "falling back to assumed callback offset 0x"
                << std::hex
                << kCallbackFunctionOffset
                << std::dec
                << ".\n";

            return static_cast<ULONG>(
                kCallbackFunctionOffset);
        }

        ULONG offset = 0;

        hr = symbols->GetFieldOffset(
            moduleBase,
            typeId,
            "Function",
            &offset);

        if (FAILED(hr)) {
            std::cout
                << "[!] _EX_CALLBACK_ROUTINE_BLOCK::Function offset unavailable; "
                "falling back to 0x"
                << std::hex
                << kCallbackFunctionOffset
                << std::dec
                << ".\n";

            return static_cast<ULONG>(
                kCallbackFunctionOffset);
        }

        std::cout
            << "[+] _EX_CALLBACK_ROUTINE_BLOCK::Function resolved at offset 0x"
            << std::hex
            << offset
            << std::dec
            << ".\n";

        return offset;
    }

    /*
     * ------------------------------------------------------------
     * Print driver enumeration diagnostics.
     * ------------------------------------------------------------
     */

    void PrintDriverStatistics(
        const std::vector<DriverInfo>& drivers)
    {
        std::size_t validRanges = 0;

        for (const auto& driver : drivers) {
            if (driver.base &&
                driver.size)
            {
                ++validRanges;
            }
        }

        std::cout
            << "[+] PSAPI driver list: "
            << drivers.size()
            << " loaded drivers\n";

        std::cout
            << "[+] Driver ranges resolved: "
            << validRanges
            << " / "
            << drivers.size()
            << "\n";
    }

    /*
     * ------------------------------------------------------------
     * Callback array enumeration.
     * ------------------------------------------------------------
     */

    bool EnumerateCallbackArray(
        IDebugSymbols3* symbols,
        IDebugDataSpaces* dataSpaces,
        const std::vector<DriverInfo>& drivers,
        const CallbackArraySpec& spec,
        ULONG callbackFunctionOffset)
    {
        ULONG64 arrayBase = 0;

        HRESULT hr = symbols->GetOffsetByName(
            spec.symbol,
            &arrayBase);

        if (FAILED(hr)) {

            std::cout
                << "\n[-] "
                << spec.label
                << " callbacks: could not resolve "
                << spec.symbol
                << " (HRESULT=0x"
                << std::hex
                << std::uppercase
                << static_cast<unsigned long>(hr)
                << std::dec
                << std::nouppercase
                << ")\n";

            return false;
        }

        std::array<ULONG64, kCallbackSlots> entries{};

        ULONG bytesRead = 0;

        hr = dataSpaces->ReadVirtual(
            arrayBase,
            entries.data(),
            static_cast<ULONG>(sizeof(entries)),
            &bytesRead);

        if (FAILED(hr)) {
            PrintHr(
                "ReadVirtual(callback array)",
                hr);

            return false;
        }

        const std::size_t readableSlots =
            bytesRead / sizeof(ULONG64);

        std::cout
            << "\n=== "
            << spec.label
            << " callbacks ===\n";

        std::cout
            << "Symbol : "
            << spec.symbol
            << "\n";

        std::cout
            << "Address: 0x"
            << std::hex
            << arrayBase
            << std::dec
            << "\n";

        std::cout
            << "Slots read: "
            << readableSlots
            << " / "
            << kCallbackSlots
            << "\n\n";

        std::cout
            << std::left
            << std::setw(6)
            << "Slot"
            << std::setw(19)
            << "Encoded entry"
            << std::setw(19)
            << "Block"
            << std::setw(19)
            << "Callback"
            << std::setw(32)
            << "Owner"
            << "Symbol\n";

        std::cout
            << std::string(135, '-')
            << "\n";

        std::size_t active = 0;

        for (std::size_t i = 0;
            i < readableSlots;
            ++i)
        {
            const ULONG64 encoded =
                entries[i];

            if (encoded == 0) {
                continue;
            }

            ++active;

            /*
             * EX_FAST_REF:
             * clear the low reference/tag bits.
             */
            const ULONG64 block =
                encoded & kFastRefMask;

            ULONG64 callback = 0;

            const bool callbackReadable =
                ReadU64(
                    dataSpaces,
                    block +
                    callbackFunctionOffset,
                    callback);

            std::string owner;
            std::string symbol;

            if (callbackReadable &&
                callback)
            {
                owner =
                    OwnerFromAddress(
                        drivers,
                        callback);

                symbol =
                    SymbolFromAddress(
                        symbols,
                        drivers,
                        callback);
            }
            else {
                owner =
                    "<unreadable>";

                symbol =
                    "<unreadable>";
            }

            auto PrintHexColumn =
                [](ULONG64 value,
                    int width)
                {
                    std::ostringstream oss;

                    oss
                        << "0x"
                        << std::hex
                        << value;

                    std::cout
                        << std::left
                        << std::setw(width)
                        << oss.str();
                };

            std::cout
                << std::left
                << std::setw(6)
                << i;

            PrintHexColumn(
                encoded,
                19);

            PrintHexColumn(
                block,
                19);

            PrintHexColumn(
                callback,
                19);

            std::cout
                << std::left
                << std::setw(32)
                << owner
                << symbol
                << "\n";
        }

        std::cout
            << "\nActive entries: "
            << active
            << "\n";

        return true;
    }

} // namespace

int main()
{
    std::cout
        << "KernelCallbackInspector - "
        "read-only local kernel callback enumerator\n";

    std::cout
        << "No kernel memory writes are performed "
        "by this program.\n\n";

    /*
     * Windows 11 24H2 and later require SeDebugPrivilege
     * for EnumDeviceDrivers() to provide real kernel
     * ImageBase values.
     */
    if (EnableDebugPrivilege()) {
        std::cout
            << "[+] SeDebugPrivilege enabled.\n";
    }
    else {
        std::cout
            << "[!] Could not enable SeDebugPrivilege.\n"
            "    Driver base addresses may be unavailable.\n";
    }

    IDebugClient* client = nullptr;
    IDebugControl* control = nullptr;
    IDebugSymbols3* symbols = nullptr;
    IDebugDataSpaces* dataSpaces = nullptr;

    HRESULT hr = DebugCreate(
        __uuidof(IDebugClient),
        reinterpret_cast<void**>(
            &client));

    if (FAILED(hr)) {
        PrintHr(
            "DebugCreate",
            hr);

        return 1;
    }

    PrintLoadedDbgEngPath();

    hr = client->QueryInterface(
        __uuidof(IDebugControl),
        reinterpret_cast<void**>(
            &control));

    if (FAILED(hr)) {
        PrintHr(
            "QueryInterface(IDebugControl)",
            hr);

        goto cleanup;
    }

    hr = client->QueryInterface(
        __uuidof(IDebugSymbols3),
        reinterpret_cast<void**>(
            &symbols));

    if (FAILED(hr)) {
        PrintHr(
            "QueryInterface(IDebugSymbols3)",
            hr);

        goto cleanup;
    }

    hr = client->QueryInterface(
        __uuidof(IDebugDataSpaces),
        reinterpret_cast<void**>(
            &dataSpaces));

    if (FAILED(hr)) {
        PrintHr(
            "QueryInterface(IDebugDataSpaces)",
            hr);

        goto cleanup;
    }

    /*
     * Microsoft public symbol server.
     */
    hr = symbols->SetSymbolPath(
        "srv*C:\\Symbols*"
        "https://msdl.microsoft.com/download/symbols");

    if (FAILED(hr)) {
        PrintHr(
            "SetSymbolPath",
            hr);
    }
    else {
        std::cout
            << "[*] Symbol path: "
            "srv*C:\\Symbols*"
            "https://msdl.microsoft.com/download/symbols\n";
    }

    /*
     * Attach local KD.
     */
    std::cout
        << "[*] Attaching to the local kernel debugger...\n";

    hr = client->AttachKernel(
        DEBUG_ATTACH_LOCAL_KERNEL,
        nullptr);

    if (FAILED(hr)) {
        PrintHr(
            "AttachKernel(DEBUG_ATTACH_LOCAL_KERNEL)",
            hr);

        goto cleanup;
    }

    std::cout
        << "[*] Waiting for local kernel session...\n";

    hr = control->WaitForEvent(
        DEBUG_WAIT_DEFAULT,
        INFINITE);

    if (FAILED(hr)) {
        PrintHr(
            "WaitForEvent",
            hr);

        goto cleanup;
    }

    std::cout
        << "[+] Kernel session attached.\n";

    /*
     * We still need nt symbols because the callback arrays
     * themselves are internal nt symbols.
     */
    std::cout
        << "[*] Loading nt symbols...\n";

    hr = symbols->Reload(
        "/f nt");

    if (FAILED(hr)) {
        PrintHr(
            "Reload(/f nt)",
            hr);
    }

    /*
     * The reload warning above is non-fatal; clear hr so it does
     * not leak into the final exit code, and track enumeration
     * outcomes explicitly below.
     */
    hr = S_OK;

    /*
     * Do NOT rely on DbgEng's module list here.
     *
     * Enumerate loaded drivers independently through PSAPI.
     */
    std::cout
        << "[*] Enumerating loaded kernel drivers...\n";

    {
        std::vector<DriverInfo> drivers =
            EnumerateKernelDrivers(
                dataSpaces);

        PrintDriverStatistics(
            drivers);

        const ULONG callbackFunctionOffset =
            ResolveCallbackFunctionOffset(
                symbols);

        std::cout
            << "[!] Assuming Windows uses "
            << kCallbackSlots
            << " slots per process/thread/image callback array; "
            "this layout is undocumented and may change between builds.\n";

        std::size_t enumerationsFailed = 0;

        for (const auto& spec : kArrays) {
            if (!EnumerateCallbackArray(
                    symbols,
                    dataSpaces,
                    drivers,
                    spec,
                    callbackFunctionOffset))
            {
                ++enumerationsFailed;
            }
        }

        if (enumerationsFailed > 0) {
            std::cerr
                << "\n[-] "
                << enumerationsFailed
                << " callback array(s) failed to enumerate.\n";
            hr = E_FAIL;
        }
    }

cleanup:

    if (client) {
        client->EndSession(
            DEBUG_END_ACTIVE_DETACH);
    }

    SafeRelease(dataSpaces);
    SafeRelease(symbols);
    SafeRelease(control);
    SafeRelease(client);

    return FAILED(hr) ? 1 : 0;
}
