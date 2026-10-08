#include <ntifs.h>
#include <ntstrsafe.h>

// ============================================================================
// FIX FOR UNDEFINED 'BYTE' IN KERNEL MODE
// ============================================================================
#ifndef BYTE
typedef unsigned char BYTE;
#endif

// ============================================================================
// UNDOCUMENTED NATIVE API DECLARATIONS
// ============================================================================
extern "C" {
    NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
    NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
        PEPROCESS SourceProcess, PVOID SourceAddress,
        PEPROCESS TargetProcess, PVOID TargetAddress,
        SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode,
        PSIZE_T ReturnSize
    );
    // NOTE: PsLookupProcessByProcessId is ALREADY declared in ntifs.h. Do NOT redeclare it here.
    NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);

    NTKERNELAPI NTSTATUS ZwQuerySystemInformation(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
    );
}

// ============================================================================
// UNDOCUMENTED STRUCTURES
// ============================================================================
typedef struct _PEB {
    BYTE InheritedAddressSpace;
    BYTE ReadImageFileExecOptions;
    BYTE BeingDebugged;
    BYTE BitField;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PVOID Ldr;
    PVOID ProcessParameters;
} PEB, * PPEB;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE ParentProcessId;
    ULONG HandleCount;
    ULONG SessionId;
    ULONG_PTR UniqueProcessKey;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG PageFaultCount;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    SIZE_T QuotaPeakPagedPoolUsage;
    SIZE_T QuotaPagedPoolUsage;
    SIZE_T QuotaPeakNonPagedPoolUsage;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER ReadOperationCount;
    LARGE_INTEGER WriteOperationCount;
    LARGE_INTEGER OtherOperationCount;
    LARGE_INTEGER ReadTransferCount;
    LARGE_INTEGER WriteTransferCount;
    LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

// ============================================================================
// PHASE 1: OBFUSCATION
// ============================================================================
constexpr ULONG init_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9A1, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG read_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9A2, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG write_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9A3, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG get_pid_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9A4, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);
constexpr ULONG get_module_code = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x9A5, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

// ============================================================================
// COMMUNICATION STRUCTURE
// ============================================================================
struct info_t {
    HANDLE target_pid = 0;
    void* target_address = 0x0;
    void* buffer_address = 0x0;
    SIZE_T size = 0;
    SIZE_T return_size = 0;
    wchar_t process_name[256] = { 0 };
    wchar_t module_name[256] = { 0 };
    void* module_base = 0x0;
    SIZE_T module_size = 0; // NEW: Size of the module in bytes
};

PEPROCESS g_TargetProcess = NULL;

// ============================================================================
// PHASE 2: KERNEL-MODE PROCESS & MODULE ENUMERATION
// ============================================================================
NTSTATUS GetProcessIdByName(const wchar_t* process_name, HANDLE* pid) {
    ULONG buffer_size = 1024 * 1024;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_size, 'tmpD');
    if (!buffer) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS status = ZwQuerySystemInformation(5, buffer, buffer_size, &buffer_size);
    if (!NT_SUCCESS(status)) {
        ExFreePool(buffer);
        return status;
    }

    PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;
    while (TRUE) {
        if (spi->ImageName.Buffer && spi->ImageName.Length > 0) {
            if (wcsstr(spi->ImageName.Buffer, process_name) != NULL) {
                *pid = (HANDLE)(ULONG_PTR)spi->UniqueProcessId;
                ExFreePool(buffer);
                return STATUS_SUCCESS;
            }
        }
        if (spi->NextEntryOffset == 0) break;
        spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryOffset);
    }

    ExFreePool(buffer);
    return STATUS_NOT_FOUND;
}

NTSTATUS GetModuleBaseByName(HANDLE pid, const wchar_t* module_name, PVOID* base, SIZE_T* size) {
    PEPROCESS process = NULL;
    NTSTATUS status = PsLookupProcessByProcessId(pid, &process);
    if (!NT_SUCCESS(status)) return status;

    KAPC_STATE apc_state;
    KeStackAttachProcess(process, &apc_state);

    PPEB peb = PsGetProcessPeb(process);
    if (peb && peb->Ldr) {
        PPEB_LDR_DATA ldr = (PPEB_LDR_DATA)peb->Ldr;
        LIST_ENTRY* list_head = &ldr->InLoadOrderModuleList;
        LIST_ENTRY* current = list_head->Flink;

        while (current != list_head) {
            PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            if (entry->BaseDllName.Buffer) {
                if (_wcsicmp(entry->BaseDllName.Buffer, module_name) == 0) {
                    *base = entry->DllBase;
                    *size = entry->SizeOfImage; // Fill in the module size
                    KeUnstackDetachProcess(&apc_state);
                    ObDereferenceObject(process);
                    return STATUS_SUCCESS;
                }
            }
            current = current->Flink;
        }
    }

    KeUnstackDetachProcess(&apc_state);
    ObDereferenceObject(process);
    return STATUS_NOT_FOUND;
}

// ============================================================================
// CLEANUP & IRP HANDLERS
// ============================================================================
void CleanupTargetProcess() {
    if (g_TargetProcess) {
        DbgPrint("[KMDriver] Dereferencing old target process.\n");
        ObDereferenceObject(g_TargetProcess);
        g_TargetProcess = NULL;
    }
}

NTSTATUS ctl_io(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);

    irp->IoStatus.Information = sizeof(info_t);
    auto stack = IoGetCurrentIrpStackLocation(irp);
    auto buffer = (info_t*)irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_INVALID_PARAMETER;

    if (stack && buffer && stack->Parameters.DeviceIoControl.InputBufferLength >= sizeof(info_t)) {
        const auto ctl_code = stack->Parameters.DeviceIoControl.IoControlCode;

        if (ctl_code == init_code) {
            DbgPrint("[KMDriver] Received INIT request for PID: %lu\n", (ULONG)(ULONG_PTR)buffer->target_pid);
            CleanupTargetProcess();
            status = PsLookupProcessByProcessId(buffer->target_pid, &g_TargetProcess);
        }
        else if (ctl_code == get_pid_code) {
            DbgPrint("[KMDriver] Received GET_PID request for: %ws\n", (PWCHAR)buffer->process_name);
            status = GetProcessIdByName(buffer->process_name, &buffer->target_pid);
        }
        else if (ctl_code == get_module_code) {
            DbgPrint("[KMDriver] Received GET_MODULE request for: %ws\n", (PWCHAR)buffer->module_name);
            status = GetModuleBaseByName(buffer->target_pid, buffer->module_name, &buffer->module_base, &buffer->module_size);
            if (NT_SUCCESS(status)) DbgPrint("[KMDriver] Found module base: 0x%p size: 0x%X\n", buffer->module_base, (ULONG)buffer->module_size);
        }
        else if (ctl_code == read_code || ctl_code == write_code) {
            if (buffer->size == 0 || buffer->size > 0x10000000) { status = STATUS_INVALID_BUFFER_SIZE; goto complete; }
            if (!g_TargetProcess) { status = STATUS_PROCESS_IS_TERMINATING; goto complete; }

            if (ctl_code == read_code) {
                status = MmCopyVirtualMemory(g_TargetProcess, buffer->target_address, PsGetCurrentProcess(), buffer->buffer_address, buffer->size, KernelMode, &buffer->return_size);
            }
            else {
                status = MmCopyVirtualMemory(PsGetCurrentProcess(), buffer->buffer_address, g_TargetProcess, buffer->target_address, buffer->size, KernelMode, &buffer->return_size);
            }
        }
    }

complete:
    irp->IoStatus.Status = status;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS unsupported_io(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);
    irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return irp->IoStatus.Status;
}

NTSTATUS create_io(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);
    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS close_io(PDEVICE_OBJECT device_obj, PIRP irp) {
    UNREFERENCED_PARAMETER(device_obj);
    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

void driver_unload(PDRIVER_OBJECT driver_obj) {
    CleanupTargetProcess();
    UNICODE_STRING sym_link;
    RtlInitUnicodeString(&sym_link, L"\\DosDevices\\x9f2a3b");
    IoDeleteSymbolicLink(&sym_link);
    IoDeleteDevice(driver_obj->DeviceObject);
}

NTSTATUS real_main(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {
    UNREFERENCED_PARAMETER(registery_path);

    UNICODE_STRING dev_name, sym_link;
    PDEVICE_OBJECT dev_obj;

    RtlInitUnicodeString(&dev_name, L"\\Device\\x9f2a3b");
    auto status = IoCreateDevice(driver_obj, 0, &dev_name, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &dev_obj);
    if (!NT_SUCCESS(status)) return status;

    RtlInitUnicodeString(&sym_link, L"\\DosDevices\\x9f2a3b");
    status = IoCreateSymbolicLink(&sym_link, &dev_name);
    if (!NT_SUCCESS(status)) { IoDeleteDevice(dev_obj); return status; }

    SetFlag(dev_obj->Flags, DO_BUFFERED_IO);

    for (int t = 0; t <= IRP_MJ_MAXIMUM_FUNCTION; t++)
        driver_obj->MajorFunction[t] = unsupported_io;

    driver_obj->MajorFunction[IRP_MJ_CREATE] = create_io;
    driver_obj->MajorFunction[IRP_MJ_CLOSE] = close_io;
    driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ctl_io;
    driver_obj->DriverUnload = driver_unload;

    ClearFlag(dev_obj->Flags, DO_DEVICE_INITIALIZING);
    return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registery_path) {
    UNREFERENCED_PARAMETER(driver_obj);
    UNREFERENCED_PARAMETER(registery_path);

    DbgPrint("[KMDriver] DriverEntry called by KDMapper!\n");
    UNICODE_STRING drv_name;
    RtlInitUnicodeString(&drv_name, L"\\Driver\\KMDriver");
    IoCreateDriver(&drv_name, &real_main);
    return STATUS_SUCCESS;
}