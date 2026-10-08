#include <Windows.h>
#include <iostream>
#include <string>
#include <iomanip>

// IOCTL Codes (Must match driver)
constexpr ULONG init_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9A1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG read_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9A2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG write_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9A3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG get_pid_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9A4, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG get_module_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9A5, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

struct info_t {
    HANDLE target_pid = 0;
    void* target_address = 0x0;
    void* buffer_address = 0x0;
    SIZE_T size = 0;
    SIZE_T return_size = 0;
    wchar_t process_name[256] = { 0 };
    wchar_t module_name[256] = { 0 };
    void* module_base = 0x0;
};

int main() {
    std::cout << "[*] Opening handle to \\\\.\\x9f2a3b...\n";

    HANDLE hDriver = CreateFileA(
        "\\\\.\\x9f2a3b",
        GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );

    if (hDriver == INVALID_HANDLE_VALUE) {
        std::cout << "[-] Failed to open handle. Error: " << GetLastError() << "\n";
        std::cin.get(); return -1;
    }
    std::cout << "[+] Successfully connected to the driver!\n";

    // --- TEST 1: GET_PID ---
    std::wstring procName;
    std::cout << "[*] Enter the process name to find (e.g., explorer.exe): ";
    std::wcin >> procName;

    info_t request = { 0 };
    wcsncpy_s(request.process_name, procName.c_str(), 255);

    DWORD bytesReturned = 0;
    BOOL result = DeviceIoControl(hDriver, get_pid_code, &request, sizeof(request), &request, sizeof(request), &bytesReturned, NULL);

    if (!result || request.target_pid == 0) {
        std::cout << "[-] GET_PID failed.\n";
        CloseHandle(hDriver); std::cin.get(); return -1;
    }
    std::cout << "[+] Found PID: " << (DWORD)(ULONG_PTR)request.target_pid << "\n";

    // --- TEST 2: INIT (Attach to process) ---
    // (Note: The driver needs to store the PEPROCESS globally for read/write to work)
    info_t initReq = { 0 };
    initReq.target_pid = request.target_pid;
    initReq.size = 1; // Dummy size to pass the sanity check
    DeviceIoControl(hDriver, init_code, &initReq, sizeof(initReq), &initReq, sizeof(initReq), &bytesReturned, NULL);
    std::cout << "[+] Attached to process.\n";

    // --- TEST 3: GET_MODULE ---
    std::wstring modName;
    std::cout << "[*] Enter the module name to find (e.g., ntdll.dll): ";
    std::wcin >> modName;

    info_t modRequest = { 0 };
    modRequest.target_pid = request.target_pid;
    wcsncpy_s(modRequest.module_name, modName.c_str(), 255);

    result = DeviceIoControl(hDriver, get_module_code, &modRequest, sizeof(modRequest), &modRequest, sizeof(modRequest), &bytesReturned, NULL);

    if (!result || modRequest.module_base == 0) {
        std::cout << "[-] GET_MODULE failed.\n";
        CloseHandle(hDriver); std::cin.get(); return -1;
    }
    std::cout << "[+] Found module base: 0x" << std::hex << (ULONG_PTR)modRequest.module_base << std::dec << "\n";

    // --- TEST 4: READ MEMORY (Read the first 2 bytes of the module, should be 'MZ') ---
    unsigned char readBuffer[2] = { 0 };
    info_t readReq = { 0 };
    readReq.target_address = modRequest.module_base; // Address to read from
    readReq.buffer_address = readBuffer;             // Address to write to (our local buffer)
    readReq.size = 2;                                // Read 2 bytes

    result = DeviceIoControl(hDriver, read_code, &readReq, sizeof(readReq), &readReq, sizeof(readReq), &bytesReturned, NULL);

    if (result && readReq.return_size == 2) {
        std::cout << "[+] READ successful! Bytes read: "
            << std::hex << (int)readBuffer[0] << " " << (int)readBuffer[1] << std::dec
            << " (ASCII: " << readBuffer[0] << readBuffer[1] << ")\n";
        if (readBuffer[0] == 'M' && readBuffer[1] == 'Z') {
            std::cout << "[***] SUCCESS: Valid MZ header found! Memory reading is fully functional!\n";
        }
    }
    else {
        std::cout << "[-] READ failed. Error: " << GetLastError() << "\n";
    }

    CloseHandle(hDriver);
    std::cout << "[*] Press Enter to exit.\n";
    std::cin.ignore(); std::cin.get();
    return 0;
}