#include <ntifs.h>
#include <wdm.h>

#define DEVICE_NAME L"\\Device\\Watchdog"
#define SYMBOLIC_NAME L"\\DosDevices\\Watchdog"

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

VOID WatchdogThread(IN PVOID Context);

PDEVICE_OBJECT g_DeviceObject = NULL;

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicName;

    RtlInitUnicodeString(&deviceName, DEVICE_NAME);
    status = IoCreateDevice(pDriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    RtlInitUnicodeString(&symbolicName, SYMBOLIC_NAME);
    status = IoCreateSymbolicLink(&symbolicName, &deviceName);
    if (!NT_SUCCESS(status))
    {
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    pDriverObject->DriverUnload = DriverUnload;

    HANDLE hThread;
    status = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, WatchdogThread, NULL);
    if (!NT_SUCCESS(status))
    {
        IoDeleteSymbolicLink(&symbolicName);
        IoDeleteDevice(g_DeviceObject);
        return status;
    }

    ZwClose(hThread);

    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    UNICODE_STRING symbolicName;
    RtlInitUnicodeString(&symbolicName, SYMBOLIC_NAME);
    IoDeleteSymbolicLink(&symbolicName);

    IoDeleteDevice(g_DeviceObject);
}

VOID WatchdogThread(IN PVOID Context)
{
    UNREFERENCED_PARAMETER(Context);

    // Set the thread name (for debugging purposes)
    PAGED_CODE();
    PETHREAD pThread = PsGetCurrentThread();
    KeSetObjectName(pThread, L"WatchdogThread");

    LONG priority = -1;
    KeSetPriorityThread(pThread, priority);

    for (;;)
    {
        BOOLEAN bTamperingDetected = FALSE;

        PVOID pDriverEntry = &DriverEntry;
        if (!MmIsAddressValid(pDriverEntry))
        {
            bTamperingDetected = TRUE;
        }

        if (!MmIsAddressValid(g_DeviceObject))
        {
            bTamperingDetected = TRUE;
        }

        PVOID pWatchdogThread = &WatchdogThread;
        if (!MmIsAddressValid(pWatchdogThread))
        {
            bTamperingDetected = TRUE;
        }

        if (bTamperingDetected)
        {
            UNICODE_STRING desktopPath;
            RtlInitUnicodeString(&desktopPath, L"C:\\Users\\%USERNAME%\\Desktop");
            ExpandEnvironmentStringsW(desktopPath.Buffer, desktopPath.Buffer, desktopPath.Length / sizeof(WCHAR));

            UNICODE_STRING filename;
            RtlInitUnicodeString(&filename, L"\\tampering_detected.txt");
            desktopPath.Length += filename.Length;

            OBJECT_ATTRIBUTES objAttrs;
            InitializeObjectAttributes(&objAttrs, &desktopPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            HANDLE hFile;
            NTSTATUS status = ZwCreateFile(&hFile, FILE_APPEND_DATA, &objAttrs, &ioStatus, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
            if (!NT_SUCCESS(status))
            {
                DbgPrint("Error creating file: %x\n", status);
                return;
            }

            UNICODE_STRING message;
            RtlInitUnicodeString(&message, L"detected\r\n");
            status = ZwWriteFile(hFile, NULL, NULL, NULL, &ioStatus, message.Buffer, message.Length, NULL, NULL);
            if (!NT_SUCCESS(status))
            {
                DbgPrint("Error writing to file: %x\n", status);
                ZwClose(hFile);
                return;
            }

            ZwClose(hFile);
        }

        LARGE_INTEGER timeout;
        timeout.QuadPart = -10000; // 100 microseconds
        KeDelayExecutionThread(KernelMode, FALSE, &timeout);
    }
