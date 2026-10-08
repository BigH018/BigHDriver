# BigHDriver - Kernel Memory Manipulation Driver

A manually mapped Windows kernel driver designed for stealthy external memory reading/writing and process enumeration. Built as a foundation for an external CS2 cheat to bypass user-mode anti-cheat hooks (e.g., VAC).

WARNING: This driver is mapped using KDMapper. It has no unload routine. Once mapped, it stays in memory until the VM/PC is rebooted. Always revert to a clean VM snapshot before testing a new build.

---

## 🏗️ Architecture Overview

The system is split into two components:
1. KMDriver.sys (Kernel Driver): Manually mapped via KDMapper. Handles IOCTL requests, walks the kernel process list, attaches to process PEBs for module enumeration, and performs cross-process memory copies.
2. UserModeApp.exe (Test Client): Communicates with the driver via DeviceIoControl. Demonstrates connecting, finding a PID by name, finding a module base by name, and reading memory.

### Obfuscated Identifiers (Phase 1)
* Driver Object Name: \Driver\KMDriver
* Device Object Name: \Device\x9f2a3b
* Symbolic Link (User-Mode Path): \\.\x9f2a3b

---

## 🔌 IOCTL Reference Table

| Command | Hex Code | Purpose |
| :--- | :--- | :--- |
| init_code | 0x9A1 | Attaches the driver to a target process by PID. Stores the PEPROCESS globally. |
| read_code | 0x9A2 | Reads memory from the target process into the user-mode buffer. |
| write_code | 0x9A3 | Writes memory from the user-mode buffer into the target process. |
| get_pid_code | 0x9A4 | Finds a process PID by its name (e.g., explorer.exe or cs2.exe). |
| get_module_code | 0x9A5 | Finds a module's base address by name (e.g., client.dll) inside the attached process. |

*All IOCTLs use METHOD_BUFFERED and FILE_SPECIAL_ACCESS.*

---

## 📦 The info_t Communication Structure

This struct is passed back and forth between the user-mode app and the driver. It must remain byte-aligned and identical in both projects.

struct info_t {
    HANDLE target_pid = 0;          // PID of the target process
    void*  target_address = 0x0;    // Address in the target process
    void*  buffer_address = 0x0;    // Address in the user-mode app's memory
    SIZE_T size = 0;                // Number of bytes to read/write
    SIZE_T return_size = 0;         // Bytes successfully processed
    wchar_t process_name[256] = { 0 }; // Used for GET_PID
    wchar_t module_name[256] = { 0 };  // Used for GET_MODULE
    void*  module_base = 0x0;       // Return value for GET_MODULE
};

---

## 🛠️ Troubleshooting Guide (When Windows Updates Break Everything)

Windows updates frequently re-enable security features or change undocumented structure offsets. If KDMapper fails or the VM BSODs, check these first:

### 1. KDMapper fails silently or returns 0xC0000603 (STATUS_IMAGE_CERT_REVOKED)
* Cause: The Vulnerable Driver Blocklist was re-enabled by Windows Update.
* Fix: Open regedit. Navigate to HKLM\SYSTEM\CurrentControlSet\Control\CI\Config. Set VulnerableDriverBlocklistEnable to 0. Reboot the VM.

### 2. KDMapper BSODs the VM instantly (e.g., nt!kdhvdrivermask crash)
* Cause: Memory Integrity (HVCI) was re-enabled by Windows Update.
* Fix: Open Windows Security -> Device Security -> Core Isolation details. Turn Memory Integrity OFF. Reboot the VM.

### 3. Defender deletes KDMapper or the .sys file
* Cause: Tamper Protection re-enabled itself, or Defender updated its signatures.
* Fix: Re-run the Defender Control tool. Verify in Windows Security that Tamper Protection is OFF and Real-Time Protection is OFF. Add your working folder as an Exclusion.

### 4. Driver fails to map but KDMapper prints success
* Cause: The IoCreateDriver call failed, or the obfuscated device name is already in use by a leaked previous mapping.
* Fix: Reboot the VM (never try to unload the driver). Check WinDbg for [KMDriver] debug prints to see where it failed.

### 5. BSOD when calling GET_MODULE (Invalid memory access)
* Cause: Windows updated its internal PEB, PEB_LDR_DATA, or LDR_DATA_TABLE_ENTRY structure layouts.
* Fix: You will need to update the offsets in the _PEB, _PEB_LDR_DATA, and _LDR_DATA_TABLE_ENTRY structs in main.cpp using a tool like WinDbg (dt _PEB) or a public symbol reference for the new Windows build.

### 6. KDMapper fails to map on a new Windows build
* Cause: KDMapper's embedded offsets for the Intel driver iqvw64e.sys may be outdated for newer Windows kernels.
* Fix: Update KDMapper to the latest version from the official repository. As a last resort, you may need to find a new vulnerable driver (BYOVD) to use instead of the Intel one.

---

## 🚀 Testing Workflow (Golden Rules)

1. Never test on your host PC. Always use the isolated VM.
2. Take a snapshot called Golden_Base_No_Driver before mapping anything.
3. When testing a new driver build:
   * Restore Golden_Base_No_Driver.
   * Boot VM.
   * Run kdmapper.exe KMDriver.sys from an Admin CMD.
   * Run UserModeApp.exe to verify functionality.
   * Power off the VM.
   * Restore Golden_Base_No_Driver.
4. Do not attempt to unload the driver. It has no DriverUnload routine when mapped via KDMapper. If you need to update the driver, reboot the VM.

---

## 🛡️ VAC / Anti-Cheat Notes
* VAC is user-mode only and cannot directly scan this kernel driver.
* However, KDMapper's public footprint (the vulnerable Intel driver) is a known detection vector. The driver itself is safe, but the method of mapping it carries a ban risk.
* This driver bypasses CreateToolhelp32Snapshot and Module32First in user-mode, removing common detection points.