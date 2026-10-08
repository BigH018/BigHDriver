# BigHDriver - Kernel Memory Manipulation Driver

A manually mapped Windows kernel driver designed for external memory reading/writing and process enumeration.

WARNING: This driver is mapped using KDMapper. It has no unload routine. Once mapped, it stays in memory until the VM/PC is rebooted. Always revert to a clean VM snapshot before testing a new build.

---

## Architecture Overview

The driver:
- Handles IOCTL requests from a user-mode client.
- Walks the kernel process list to find a target PID by name.
- Attaches to the target process's PEB to find module base addresses.
- Performs cross-process memory reads and writes via MmCopyVirtualMemory.

### Obfuscated Identifiers
* Driver Object Name: \Driver\BigHDriver
* Device Object Name: \Device\x9f2a3b
* Symbolic Link (User-Mode Path): \\.\x9f2a3b

---

## IOCTL Reference Table

| Command | Hex Code | Purpose |
| :--- | :--- | :--- |
| init_code | 0x9A1 | Attaches the driver to a target process by PID. Stores the PEPROCESS globally. |
| read_code | 0x9A2 | Reads memory from the target process into the user-mode buffer. |
| write_code | 0x9A3 | Writes memory from the user-mode buffer into the target process. |
| get_pid_code | 0x9A4 | Finds a process PID by its name (e.g., explorer.exe, cs2.exe). |
| get_module_code | 0x9A5 | Finds a module's base address and size by name (e.g., client.dll) inside the attached process. |

All IOCTLs use METHOD_BUFFERED and FILE_SPECIAL_ACCESS.

---

## The info_t Communication Structure

This struct is passed back and forth between the user-mode client and the driver. It must remain byte-aligned and identical in both projects.

    struct info_t {
        HANDLE target_pid = 0;             // PID of the target process
        void*  target_address = 0x0;       // Address in the target process
        void*  buffer_address = 0x0;       // Address in the user-mode app's memory
        SIZE_T size = 0;                   // Number of bytes to read/write
        SIZE_T return_size = 0;            // Bytes successfully processed
        wchar_t process_name[256] = { 0 }; // Used for GET_PID
        wchar_t module_name[256] = { 0 };  // Used for GET_MODULE
        void*  module_base = 0x0;          // Return value for GET_MODULE
        SIZE_T module_size = 0;            // Return value for GET_MODULE (SizeOfImage)
    };

---

## Troubleshooting Guide (When Windows Updates Break Everything)

Windows updates frequently re-enable security features or change undocumented structure offsets. If KDMapper fails or the VM BSODs, check these first:

### 1. KDMapper fails silently or returns 0xC0000603 (STATUS_IMAGE_CERT_REVOKED)
* Cause: The Vulnerable Driver Blocklist was re-enabled by Windows Update.
* Fix: Open regedit. Navigate to HKLM\SYSTEM\CurrentControlSet\Control\CI\Config. Set VulnerableDriverBlocklistEnable to 0. Reboot the VM.

### 2. KDMapper BSODs the VM instantly (e.g., nt!kdhvdrivermask crash)
* Cause: Memory Integrity (HVCI) was re-enabled by Windows Update.
* Fix: Windows Security -> Device Security -> Core Isolation details -> Memory Integrity OFF. Reboot the VM.

### 3. Defender deletes KDMapper or the .sys file
* Cause: Tamper Protection re-enabled itself, or Defender updated its signatures.
* Fix: Re-verify that Tamper Protection and Real-Time Protection are OFF. Add the working folder as a Defender Exclusion.

### 4. Driver fails to map but KDMapper prints success
* Cause: The IoCreateDriver call failed, or the device name is already in use from a leaked previous mapping.
* Fix: Reboot the VM (never try to unload the driver). Check WinDbg for [KMDriver] debug prints to see where it failed.

### 5. BSOD when calling GET_MODULE
* Cause: Windows changed internal PEB, PEB_LDR_DATA, or LDR_DATA_TABLE_ENTRY structure layouts.
* Fix: Update the offsets in the _PEB, _PEB_LDR_DATA, and _LDR_DATA_TABLE_ENTRY structs in main.cpp using WinDbg (dt _PEB) or a public symbol reference for the new Windows build.

### 6. SizeOfImage returned by the driver is wrong (module size looks like a few MB when it should be tens of MB)
* Cause: The LDR_DATA_TABLE_ENTRY layout changed and the driver is reading the wrong field.
* Fix: On the client side, read the PE headers directly from the target process instead of trusting the driver's module_size. Parse IMAGE_DOS_HEADER -> IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage to get the true size.

### 7. KDMapper fails to map on a new Windows build
* Cause: KDMapper's embedded offsets for the vulnerable Intel driver (iqvw64e.sys) may be outdated.
* Fix: Update KDMapper to the latest version from the official repository.

---

## Testing Workflow (Golden Rules)

1. Never test on the host PC. Always use the isolated VM.
2. Take a snapshot called Golden_Base_No_Driver before mapping anything.
3. When testing a new driver build:
   * Restore Golden_Base_No_Driver.
   * Boot the VM.
   * Run kdmapper.exe BigHDriver.sys from an Admin CMD.
   * Verify functionality from the client.
   * Power off the VM.
   * Restore Golden_Base_No_Driver.
4. Do not attempt to unload the driver. It has no DriverUnload routine when mapped via KDMapper. To update the driver, reboot the VM.

---

## Notes

* The driver is mapped via KDMapper and therefore is not registered as a Windows service. Standard tools (sc query, driverquery) will not show it. Use "dir \\.\x9f2a3b" from a CMD to confirm the device is present.
* SizeOfImage from the driver's GET_MODULE may be unreliable on newer Windows builds. Clients should validate by reading PE headers if exact module bounds are required.