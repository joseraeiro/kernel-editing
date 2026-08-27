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
     * Generic type-info helpers.
     *
     * All fltmgr / nt struct offsets are looked up dynamically so
     * a layout change between Windows builds surfaces as a clear
     * error instead of silent misinterpretation.
     * ------------------------------------------------------------
     */

    bool ResolveTypeAndField(
        IDebugSymbols3* symbols,
        const char* qualifiedType,
        const char* field,
        ULONG& offset)
    {
        ULONG typeId = 0;
        ULONG64 moduleBase = 0;

        HRESULT hr = symbols->GetSymbolTypeId(
            qualifiedType,
            &typeId,
            &moduleBase);

        if (FAILED(hr)) {
            return false;
        }

        return SUCCEEDED(
            symbols->GetFieldOffset(
                moduleBase,
                typeId,
                field,
                &offset));
    }

    bool ResolveTypeSize(
        IDebugSymbols3* symbols,
        const char* qualifiedType,
        ULONG& size)
    {
        ULONG typeId = 0;
        ULONG64 moduleBase = 0;

        HRESULT hr = symbols->GetSymbolTypeId(
            qualifiedType,
            &typeId,
            &moduleBase);

        if (FAILED(hr)) {
            return false;
        }

        return SUCCEEDED(
            symbols->GetTypeSize(
                moduleBase,
                typeId,
                &size));
    }

    /*
     * ------------------------------------------------------------
     * Kernel LIST_ENTRY walker.
     *
     * Given the head LIST_ENTRY address and the container's field
     * offset for its embedded LIST_ENTRY, iterate up to maxCount
     * containers. Stops on:
     *   * Flink returning to the head       (end of list)
     *   * Flink == current                  (self-loop)
     *   * Flink == 0                        (garbage)
     *   * Flink < listEntryOffsetContainer  (would underflow)
     *   * ReadVirtual failure               (unmapped memory)
     *   * maxCount reached                  (runaway)
     * ------------------------------------------------------------
     */

    std::vector<ULONG64> WalkListEntries(
        IDebugDataSpaces* dataSpaces,
        ULONG64 headAddress,
        ULONG listEntryOffsetInContainer,
        std::size_t maxCount)
    {
        std::vector<ULONG64> containers;

        ULONG64 firstFlink = 0;

        if (!ReadU64(
                dataSpaces,
                headAddress,
                firstFlink))
        {
            return containers;
        }

        ULONG64 current = firstFlink;

        while (current != headAddress &&
               containers.size() < maxCount)
        {
            if (current < listEntryOffsetInContainer) {
                break;
            }

            containers.push_back(
                current -
                listEntryOffsetInContainer);

            ULONG64 nextFlink = 0;

            if (!ReadU64(
                    dataSpaces,
                    current,
                    nextFlink))
            {
                break;
            }

            if (nextFlink == 0 ||
                nextFlink == current)
            {
                break;
            }

            current = nextFlink;
        }

        return containers;
    }

    /*
     * ------------------------------------------------------------
     * Read a kernel UNICODE_STRING at the given address.
     *
     * The buffer is capped at kUnicodeStringByteCap to protect
     * against a garbage Length field pointing at a huge allocation.
     * Non-ASCII code points are rendered as '?' since this is a
     * console tool and driver names are effectively ASCII in
     * practice.
     * ------------------------------------------------------------
     */

    constexpr USHORT kUnicodeStringByteCap = 512;

    #pragma pack(push, 1)
    struct KernelUnicodeString {
        USHORT  Length;
        USHORT  MaximumLength;
        ULONG   _pad;
        ULONG64 Buffer;
    };
    #pragma pack(pop)

    static_assert(
        sizeof(KernelUnicodeString) == 16,
        "UNICODE_STRING x64 layout mismatch");

    std::string ReadUnicodeString(
        IDebugDataSpaces* dataSpaces,
        ULONG64 unicodeStringAddress)
    {
        KernelUnicodeString us{};

        if (!ReadVirtualExact(
                dataSpaces,
                unicodeStringAddress,
                &us,
                sizeof(us)))
        {
            return "<unreadable>";
        }

        if (us.Length == 0 ||
            us.Buffer == 0)
        {
            return {};
        }

        USHORT byteCount = us.Length;

        if (byteCount > kUnicodeStringByteCap) {
            byteCount = kUnicodeStringByteCap;
        }

        std::vector<wchar_t> buf(
            byteCount / sizeof(wchar_t));

        if (!ReadVirtualExact(
                dataSpaces,
                us.Buffer,
                buf.data(),
                byteCount))
        {
            return "<unreadable>";
        }

        std::string out;
        out.reserve(buf.size());

        for (wchar_t wc : buf) {
            if (wc == 0) {
                break;
            }
            if (wc < 128) {
                out.push_back(
                    static_cast<char>(wc));
            }
            else {
                out.push_back('?');
            }
        }

        return out;
    }

    /*
     * ------------------------------------------------------------
     * IRP major function label.
     *
     * Filter Manager pseudo-major functions occupy 0xEC..0xFF
     * (defined as (UCHAR)-1 through (UCHAR)-20 in fltKernel.h).
     * ------------------------------------------------------------
     */

    constexpr UCHAR kIrpMjOperationEnd = 0x80;

    const char* IrpMajorName(UCHAR mj)
    {
        switch (mj) {
        case 0x00: return "IRP_MJ_CREATE";
        case 0x01: return "IRP_MJ_CREATE_NAMED_PIPE";
        case 0x02: return "IRP_MJ_CLOSE";
        case 0x03: return "IRP_MJ_READ";
        case 0x04: return "IRP_MJ_WRITE";
        case 0x05: return "IRP_MJ_QUERY_INFORMATION";
        case 0x06: return "IRP_MJ_SET_INFORMATION";
        case 0x07: return "IRP_MJ_QUERY_EA";
        case 0x08: return "IRP_MJ_SET_EA";
        case 0x09: return "IRP_MJ_FLUSH_BUFFERS";
        case 0x0a: return "IRP_MJ_QUERY_VOLUME_INFORMATION";
        case 0x0b: return "IRP_MJ_SET_VOLUME_INFORMATION";
        case 0x0c: return "IRP_MJ_DIRECTORY_CONTROL";
        case 0x0d: return "IRP_MJ_FILE_SYSTEM_CONTROL";
        case 0x0e: return "IRP_MJ_DEVICE_CONTROL";
        case 0x0f: return "IRP_MJ_INTERNAL_DEVICE_CONTROL";
        case 0x10: return "IRP_MJ_SHUTDOWN";
        case 0x11: return "IRP_MJ_LOCK_CONTROL";
        case 0x12: return "IRP_MJ_CLEANUP";
        case 0x13: return "IRP_MJ_CREATE_MAILSLOT";
        case 0x14: return "IRP_MJ_QUERY_SECURITY";
        case 0x15: return "IRP_MJ_SET_SECURITY";
        case 0x16: return "IRP_MJ_POWER";
        case 0x17: return "IRP_MJ_SYSTEM_CONTROL";
        case 0x18: return "IRP_MJ_DEVICE_CHANGE";
        case 0x19: return "IRP_MJ_QUERY_QUOTA";
        case 0x1a: return "IRP_MJ_SET_QUOTA";
        case 0x1b: return "IRP_MJ_PNP";
        case 0xff: return "IRP_MJ_ACQUIRE_FOR_SECTION_SYNC";
        case 0xfe: return "IRP_MJ_RELEASE_FOR_SECTION_SYNC";
        case 0xfd: return "IRP_MJ_ACQUIRE_FOR_MOD_WRITE";
        case 0xfc: return "IRP_MJ_RELEASE_FOR_MOD_WRITE";
        case 0xfb: return "IRP_MJ_ACQUIRE_FOR_CC_FLUSH";
        case 0xfa: return "IRP_MJ_RELEASE_FOR_CC_FLUSH";
        case 0xf9: return "IRP_MJ_QUERY_OPEN";
        case 0xf3: return "IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE";
        case 0xf2: return "IRP_MJ_NETWORK_QUERY_OPEN";
        case 0xf1: return "IRP_MJ_MDL_READ";
        case 0xf0: return "IRP_MJ_MDL_READ_COMPLETE";
        case 0xef: return "IRP_MJ_PREPARE_MDL_WRITE";
        case 0xee: return "IRP_MJ_MDL_WRITE_COMPLETE";
        case 0xed: return "IRP_MJ_VOLUME_MOUNT";
        case 0xec: return "IRP_MJ_VOLUME_DISMOUNT";
        default:   return nullptr;
        }
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

    /*
     * ------------------------------------------------------------
     * Minifilter enumeration.
     *
     * Filter Manager registrations are not a flat array like the
     * process/thread/image callback tables. Instead, walk from
     *
     *   fltmgr!FltGlobals
     *     .FrameList (LIST_ENTRY head, inside _FLT_RESOURCE_LIST_HEAD)
     *       -> _FLTP_FRAME
     *          .RegisteredFilters (LIST_ENTRY head)
     *              -> _FLT_FILTER
     *                 .Name (UNICODE_STRING)
     *                 .DriverObject (_DRIVER_OBJECT*)
     *                 .Operations   (_FLT_OPERATION_REGISTRATION*)
     *
     * The operations array is terminated by MajorFunction == 0x80
     * (IRP_MJ_OPERATION_END). Every offset is looked up dynamically
     * because the layouts are undocumented and shift between builds.
     * ------------------------------------------------------------
     */

    constexpr std::size_t kMaxFrames = 16;
    constexpr std::size_t kMaxFiltersPerFrame = 256;
    constexpr std::size_t kMaxOperationsPerFilter = 64;

    bool EnumerateMinifilters(
        IDebugSymbols3* symbols,
        IDebugDataSpaces* dataSpaces,
        const std::vector<DriverInfo>& drivers)
    {
        ULONG64 fltGlobals = 0;

        HRESULT hr = symbols->GetOffsetByName(
            "fltmgr!FltGlobals",
            &fltGlobals);

        if (FAILED(hr)) {
            std::cout
                << "\n[-] Minifilters: could not resolve fltmgr!FltGlobals "
                "(HRESULT=0x"
                << std::hex
                << std::uppercase
                << static_cast<unsigned long>(hr)
                << std::dec
                << std::nouppercase
                << "). Ensure fltmgr.sys public symbols are on the symbol path.\n";
            return false;
        }

        struct FieldRef {
            const char* type;
            const char* field;
            ULONG*      out;
        };

        ULONG globalsFrameListOff = 0;
        ULONG resourceListRListOff = 0;
        ULONG frameLinksOff = 0;
        ULONG frameRegisteredFiltersOff = 0;
        ULONG filterPrimaryLinkOff = 0;
        ULONG filterNameOff = 0;
        ULONG filterOperationsOff = 0;
        ULONG filterDriverObjectOff = 0;
        ULONG opMajorFunctionOff = 0;
        ULONG opPreOff = 0;
        ULONG opPostOff = 0;
        ULONG driverObjectDriverStartOff = 0;

        const FieldRef fields[] = {
            {"fltmgr!_GLOBALS",                     "FrameList",         &globalsFrameListOff},
            {"fltmgr!_FLT_RESOURCE_LIST_HEAD",      "rList",             &resourceListRListOff},
            {"fltmgr!_FLTP_FRAME",                  "Links",             &frameLinksOff},
            {"fltmgr!_FLTP_FRAME",                  "RegisteredFilters", &frameRegisteredFiltersOff},
            {"fltmgr!_FLT_FILTER",                  "PrimaryLink",       &filterPrimaryLinkOff},
            {"fltmgr!_FLT_FILTER",                  "Name",              &filterNameOff},
            {"fltmgr!_FLT_FILTER",                  "Operations",        &filterOperationsOff},
            {"fltmgr!_FLT_FILTER",                  "DriverObject",      &filterDriverObjectOff},
            {"fltmgr!_FLT_OPERATION_REGISTRATION",  "MajorFunction",     &opMajorFunctionOff},
            {"fltmgr!_FLT_OPERATION_REGISTRATION",  "PreOperation",      &opPreOff},
            {"fltmgr!_FLT_OPERATION_REGISTRATION",  "PostOperation",     &opPostOff},
            {"nt!_DRIVER_OBJECT",                   "DriverStart",       &driverObjectDriverStartOff},
        };

        for (const auto& f : fields) {
            if (!ResolveTypeAndField(
                    symbols,
                    f.type,
                    f.field,
                    *f.out))
            {
                std::cerr
                    << "\n[-] Minifilters: could not resolve "
                    << f.type
                    << "::"
                    << f.field
                    << ". Filter Manager symbols may be missing or the "
                    "layout may have changed in this build.\n";
                return false;
            }
        }

        ULONG opRegSize = 0;

        if (!ResolveTypeSize(
                symbols,
                "fltmgr!_FLT_OPERATION_REGISTRATION",
                opRegSize))
        {
            std::cerr
                << "\n[-] Minifilters: could not size "
                "fltmgr!_FLT_OPERATION_REGISTRATION.\n";
            return false;
        }

        const ULONG64 frameListHead =
            fltGlobals +
            globalsFrameListOff +
            resourceListRListOff;

        std::vector<ULONG64> frames =
            WalkListEntries(
                dataSpaces,
                frameListHead,
                frameLinksOff,
                kMaxFrames);

        std::cout
            << "\n=== Minifilters ===\n"
            << "Symbol : fltmgr!FltGlobals\n"
            << "Address: 0x"
            << std::hex << fltGlobals << std::dec << "\n"
            << "Frames : " << frames.size() << "\n";

        std::size_t frameIndex = 0;

        for (ULONG64 frame : frames) {
            const ULONG64 filterListHead =
                frame +
                frameRegisteredFiltersOff +
                resourceListRListOff;

            std::vector<ULONG64> filters =
                WalkListEntries(
                    dataSpaces,
                    filterListHead,
                    filterPrimaryLinkOff,
                    kMaxFiltersPerFrame);

            std::cout
                << "\n-- Frame " << frameIndex
                << " at 0x" << std::hex << frame << std::dec
                << " (" << filters.size() << " filter(s)) --\n";

            for (ULONG64 filter : filters) {
                std::string name =
                    ReadUnicodeString(
                        dataSpaces,
                        filter + filterNameOff);

                ULONG64 operations = 0;
                ReadU64(
                    dataSpaces,
                    filter + filterOperationsOff,
                    operations);

                ULONG64 driverObject = 0;
                ReadU64(
                    dataSpaces,
                    filter + filterDriverObjectOff,
                    driverObject);

                ULONG64 driverStart = 0;

                if (driverObject) {
                    ReadU64(
                        dataSpaces,
                        driverObject + driverObjectDriverStartOff,
                        driverStart);
                }

                std::string filterOwner =
                    driverStart
                        ? OwnerFromAddress(drivers, driverStart)
                        : std::string("<unknown>");

                std::cout
                    << "\nFilter : "
                    << (name.empty() ? std::string("<unnamed>") : name)
                    << "\n"
                    << "Address    : 0x" << std::hex << filter << std::dec << "\n"
                    << "Owner      : " << filterOwner << "\n"
                    << "Operations : 0x" << std::hex << operations << std::dec << "\n";

                if (!operations) {
                    std::cout
                        << "  (no operation registration array)\n";
                    continue;
                }

                std::cout
                    << std::left
                    << std::setw(38) << "IRP major"
                    << std::setw(19) << "PRE"
                    << std::setw(19) << "POST"
                    << std::setw(32) << "Owner"
                    << "Symbol\n";

                std::cout
                    << std::string(140, '-')
                    << "\n";

                std::size_t rowsPrinted = 0;

                for (std::size_t i = 0;
                     i < kMaxOperationsPerFilter;
                     ++i)
                {
                    const ULONG64 entryAddr =
                        operations +
                        static_cast<ULONG64>(i) * opRegSize;

                    UCHAR major = 0;

                    if (!ReadVirtualExact(
                            dataSpaces,
                            entryAddr + opMajorFunctionOff,
                            &major,
                            sizeof(major)))
                    {
                        break;
                    }

                    if (major == kIrpMjOperationEnd) {
                        break;
                    }

                    ULONG64 preCb = 0;
                    ULONG64 postCb = 0;

                    ReadU64(
                        dataSpaces,
                        entryAddr + opPreOff,
                        preCb);

                    ReadU64(
                        dataSpaces,
                        entryAddr + opPostOff,
                        postCb);

                    if (!preCb && !postCb) {
                        continue;
                    }

                    const char* mjName = IrpMajorName(major);
                    std::ostringstream mjLabel;

                    if (mjName) {
                        mjLabel << mjName;
                    }
                    else {
                        mjLabel
                            << "IRP_MJ_0x"
                            << std::hex
                            << static_cast<unsigned>(major);
                    }

                    std::ostringstream preText;
                    std::ostringstream postText;

                    if (preCb) {
                        preText << "0x" << std::hex << preCb;
                    }
                    else {
                        preText << "-";
                    }

                    if (postCb) {
                        postText << "0x" << std::hex << postCb;
                    }
                    else {
                        postText << "-";
                    }

                    const ULONG64 primaryCb =
                        preCb ? preCb : postCb;

                    std::string owner =
                        OwnerFromAddress(
                            drivers,
                            primaryCb);

                    std::string symbol =
                        SymbolFromAddress(
                            symbols,
                            drivers,
                            primaryCb);

                    std::cout
                        << std::left
                        << std::setw(38) << mjLabel.str()
                        << std::setw(19) << preText.str()
                        << std::setw(19) << postText.str()
                        << std::setw(32) << owner
                        << symbol
                        << "\n";

                    ++rowsPrinted;
                }

                if (rowsPrinted == 0) {
                    std::cout
                        << "  (operation array present but no non-null callbacks)\n";
                }
            }

            ++frameIndex;
        }

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
     * fltmgr symbols are required to enumerate minifilter
     * registrations; the reload is non-fatal because everything
     * else (process/thread/image callbacks) still works without
     * them.
     */
    hr = symbols->Reload(
        "/f fltmgr.sys");

    if (FAILED(hr)) {
        std::cerr
            << "[!] fltmgr symbol reload returned HRESULT=0x"
            << std::hex
            << std::uppercase
            << static_cast<unsigned long>(hr)
            << std::dec
            << std::nouppercase
            << "; minifilter enumeration may not resolve types.\n";
    }

    /*
     * The reload warnings above are non-fatal; clear hr so they
     * do not leak into the final exit code, and track enumeration
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

        if (!EnumerateMinifilters(
                symbols,
                dataSpaces,
                drivers))
        {
            ++enumerationsFailed;
        }

        if (enumerationsFailed > 0) {
            std::cerr
                << "\n[-] "
                << enumerationsFailed
                << " enumeration(s) failed.\n";
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
