/*
 * clamrt_mf_proto.h -- clamrt v3 NEW: wire protocol between the (optional) kernel minifilter driver clamrt_mf.sys and
 * the user-mode client inside clamrt.exe (clamrt_win_ext.c).  Shared by both sides.
 */
#ifndef CLAMRT_MF_PROTO_H
#define CLAMRT_MF_PROTO_H
#define CLAMRT_MF_PORT_NAME L"\\ClamrtPort" /* wide string literal: L"..." */
#define CLAMRT_MF_PROTO_VERSION 3
#define CLAMRT_MF_MAX_CHARS 1024

/* sent once by the client when it connects (FilterConnectCommunicationPort context) */
typedef struct _CLAMRT_MF_CONNECT {
    unsigned long Version;     /* CLAMRT_MF_PROTO_VERSION                                         */
    unsigned long ClientPid;   /* the driver never asks the client to scan its own process's loads */
    unsigned long TimeoutMs;   /* how long the driver holds an execution waiting for a verdict    */
    unsigned long FailClosed;  /* 1 = deny when the verdict does not arrive, 0 = allow            */
} CLAMRT_MF_CONNECT;

/* driver -> client: "process Pid is about to map this file as an executable image" */
typedef struct _CLAMRT_MF_REQUEST {
    unsigned long Pid;
    unsigned long PathChars;                    /* length in WCHARs, without NUL                  */
    unsigned short Path[CLAMRT_MF_MAX_CHARS];   /* normalised NT path, e.g. \Device\HarddiskVolume3\Users\x\a.exe */
} CLAMRT_MF_REQUEST;

/* client -> driver */
typedef struct _CLAMRT_MF_REPLY {
    unsigned long Verdict;                      /* 0 = allow, 1 = deny                            */
} CLAMRT_MF_REPLY;
#endif
