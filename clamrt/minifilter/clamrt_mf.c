/*
 * clamrt_mf.c -- clamrt v3 NEW: OPTIONAL Windows minifilter driver giving clamrt real BLOCKING on execution.
 *
 *   *** NOT BUILT, NOT SIGNED, NOT RUN ***  This source was written without a Windows Driver Kit available in the
 *   build environment.  Treat it as a reviewed starting point: build it with the WDK (Visual Studio "Filter Driver:
 *   Filesystem Mini-Filter" template, link fltmgr.lib), test it on a VM with test-signing enabled, and run it
 *   through Driver Verifier before it goes anywhere near production.  A bug in a kernel driver is a blue screen.
 *
 * What it does
 *   Hooks IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, which the memory manager issues when a user-mode process creates
 *   an image / executable section of a file (CreateProcess, LoadLibrary, mapping with PAGE_EXECUTE*).  For such a
 *   request it sends {pid, NT path} to the user-mode client (clamrt.exe --block-exec) over a filter communication
 *   port and waits at most TimeoutMs for allow/deny.  Deny -> the section is refused with STATUS_ACCESS_DENIED, i.e.
 *   the infected program cannot start.  No client connected, timeout, or any error -> ALLOW (fail-open) unless the
 *   client asked for fail-closed at connect time.
 *
 * Design rules that keep it safe
 *   - Only user-mode requestors with executable page protection are considered; kernel requests, the client's own
 *     process (pid sent at connect), paging I/O and non-file objects are skipped.
 *   - The client reads the file with ordinary read access (never as an executable mapping), so verdict requests
 *     cannot recurse into this callback.
 *   - Everything is bounded: one message per image-section creation, copied path <= CLAMRT_MF_MAX_CHARS.
 *   - Verdict timeouts are enforced by FltSendMessage, so a hung client cannot hang processes indefinitely.
 */
#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "clamrt_mf_proto.h"

#pragma prefast(disable : __WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "not applicable in kernel mode")

static PFLT_FILTER g_Filter;
static PFLT_PORT g_Server;
static PFLT_PORT g_Client;     /* NULL while no clamrt.exe is connected */
static ULONG g_ClientPid;
static LONG g_TimeoutMs = 4000;
static BOOLEAN g_FailClosed;

DRIVER_INITIALIZE DriverEntry;
NTSTATUS ClamrtUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS PortConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerCookie, _In_reads_bytes_opt_(Size) PVOID Ctx,
                     _In_ ULONG Size, _Outptr_result_maybenull_ PVOID *ConnectionCookie);
VOID PortDisconnect(_In_opt_ PVOID ConnectionCookie);
FLT_PREOP_CALLBACK_STATUS PreSection(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                     _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

static const FLT_OPERATION_REGISTRATION Callbacks[] = {
    {IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0, PreSection, NULL},
    {IRP_MJ_OPERATION_END}};

static const FLT_REGISTRATION Registration = {
    sizeof(FLT_REGISTRATION), FLT_REGISTRATION_VERSION, 0, NULL, Callbacks, ClamrtUnload,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS st;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING port = RTL_CONSTANT_STRING(CLAMRT_MF_PORT_NAME);

    UNREFERENCED_PARAMETER(RegistryPath);
    st = FltRegisterFilter(DriverObject, &Registration, &g_Filter);
    if (!NT_SUCCESS(st)) return st;
    st = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS); /* administrators / SYSTEM only */
    if (NT_SUCCESS(st)) {
        InitializeObjectAttributes(&oa, &port, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);
        st = FltCreateCommunicationPort(g_Filter, &g_Server, &oa, NULL, PortConnect, PortDisconnect, NULL, 1);
        FltFreeSecurityDescriptor(sd);
    }
    if (NT_SUCCESS(st)) st = FltStartFiltering(g_Filter);
    if (!NT_SUCCESS(st)) {
        if (g_Server) FltCloseCommunicationPort(g_Server);
        FltUnregisterFilter(g_Filter);
    }
    return st;
}

NTSTATUS ClamrtUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    FltCloseCommunicationPort(g_Server);
    FltUnregisterFilter(g_Filter);
    return STATUS_SUCCESS;
}

NTSTATUS PortConnect(_In_ PFLT_PORT ClientPort, _In_opt_ PVOID ServerCookie, _In_reads_bytes_opt_(Size) PVOID Ctx,
                     _In_ ULONG Size, _Outptr_result_maybenull_ PVOID *ConnectionCookie)
{
    const CLAMRT_MF_CONNECT *c = (const CLAMRT_MF_CONNECT *)Ctx;
    UNREFERENCED_PARAMETER(ServerCookie);
    *ConnectionCookie = NULL;
    if (!c || Size < sizeof *c || c->Version != CLAMRT_MF_PROTO_VERSION) return STATUS_INVALID_PARAMETER;
    if (g_Client) return STATUS_ALREADY_REGISTERED; /* one scanner at a time */
    g_ClientPid = c->ClientPid;
    g_TimeoutMs = (LONG)(c->TimeoutMs < 100 ? 100 : c->TimeoutMs > 30000 ? 30000 : c->TimeoutMs);
    g_FailClosed = c->FailClosed ? TRUE : FALSE;
    g_Client = ClientPort;
    return STATUS_SUCCESS;
}

VOID PortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(g_Filter, &g_Client); /* sets g_Client to NULL -> fail-open for everybody from now on */
    g_ClientPid = 0;
}

FLT_PREOP_CALLBACK_STATUS PreSection(_Inout_ PFLT_CALLBACK_DATA Data, _In_ PCFLT_RELATED_OBJECTS FltObjects,
                                     _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PFLT_FILE_NAME_INFORMATION ni = NULL;
    CLAMRT_MF_REQUEST *req = NULL;
    CLAMRT_MF_REPLY reply;
    ULONG replyLen = sizeof reply;
    LARGE_INTEGER to;
    NTSTATUS st;
    FLT_PREOP_CALLBACK_STATUS ret = FLT_PREOP_SUCCESS_NO_CALLBACK;
    ULONG prot, pid;

    UNREFERENCED_PARAMETER(FltObjects);
    *CompletionContext = NULL;
    if (!g_Client) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->RequestorMode == KernelMode) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType != SyncTypeCreateSection)
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    prot = Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection;
    if (!(prot & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    pid = FltGetRequestorProcessId(Data);
    if (pid == g_ClientPid) return FLT_PREOP_SUCCESS_NO_CALLBACK;

    st = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &ni);
    if (!NT_SUCCESS(st)) return FLT_PREOP_SUCCESS_NO_CALLBACK;
    if (ni->Name.Length == 0 || ni->Name.Length / sizeof(WCHAR) >= CLAMRT_MF_MAX_CHARS) {
        FltReleaseFileNameInformation(ni);
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    req = (CLAMRT_MF_REQUEST *)ExAllocatePool2(POOL_FLAG_PAGED, sizeof *req, 'tRmC');
    if (!req) { FltReleaseFileNameInformation(ni); return FLT_PREOP_SUCCESS_NO_CALLBACK; }
    RtlZeroMemory(req, sizeof *req);
    req->Pid = pid;
    req->PathChars = ni->Name.Length / sizeof(WCHAR);
    RtlCopyMemory(req->Path, ni->Name.Buffer, ni->Name.Length);
    FltReleaseFileNameInformation(ni);

    RtlZeroMemory(&reply, sizeof reply);
    to.QuadPart = -(LONGLONG)g_TimeoutMs * 10000; /* relative, 100 ns units */
    st = FltSendMessage(g_Filter, &g_Client, req, sizeof *req, &reply, &replyLen, &to);
    if (st == STATUS_SUCCESS) {
        if (reply.Verdict == 1) {
            Data->IoStatus.Status = STATUS_ACCESS_DENIED;
            Data->IoStatus.Information = 0;
            ret = FLT_PREOP_COMPLETE;
        }
    } else if (g_FailClosed) { /* STATUS_TIMEOUT or any send failure */
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        ret = FLT_PREOP_COMPLETE;
    }
    ExFreePoolWithTag(req, 'tRmC');
    return ret;
}
