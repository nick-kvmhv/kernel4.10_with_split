typedef void* PVOID;
typedef unsigned short WORD;
typedef ulong ULONG;
typedef ulong UINT64;
typedef void VOID;
typedef unsigned char UCHAR;
typedef char CHAR;
typedef long INT64;
typedef long LONG;
typedef unsigned short WCHAR;

typedef enum _EXCEPTION_DISPOSITION
{
         ExceptionContinueExecution = 0,
         ExceptionContinueSearch = 1,
         ExceptionNestedException = 2,
         ExceptionCollidedUnwind = 3
} EXCEPTION_DISPOSITION, *PEXCEPTION_DISPOSITION;

typedef struct EXCEPTION_REGISTRATION_RECORD EXCEPTION_REGISTRATION_RECORD;
typedef EXCEPTION_REGISTRATION_RECORD *PEXCEPTION_REGISTRATION_RECORD;
struct EXCEPTION_REGISTRATION_RECORD
{
     PEXCEPTION_REGISTRATION_RECORD Next;
     PEXCEPTION_DISPOSITION Handler;
} ;

typedef struct NT_TIB NT_TIB;
typedef NT_TIB *PNT_TIB;

struct NT_TIB
{
     PEXCEPTION_REGISTRATION_RECORD ExceptionList;
     PVOID StackBase;
     PVOID StackLimit;
     PVOID SubSystemTib;
     union
     {
          PVOID FiberData;
          ULONG Version;
     };
     PVOID ArbitraryUserPointer;
     PNT_TIB Self;
};

typedef struct _CLIENT_ID
{
     PVOID UniqueProcess;
     PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct LIST_ENTRY LIST_ENTRY;
typedef LIST_ENTRY * PLIST_ENTRY;
struct LIST_ENTRY
{
     PLIST_ENTRY Flink;
     PLIST_ENTRY Blink;
};

typedef struct _UNICODE_STRING
{
     WORD Length;
     WORD MaximumLength;
     WORD * Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CURDIR
{
     UNICODE_STRING DosPath;
     PVOID Handle;
} CURDIR, *PCURDIR;

typedef struct _STRING
{
     WORD Length;
     WORD MaximumLength;
     CHAR * Buffer;
} STRING, *PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
     WORD Flags;
     WORD Length;
     ULONG TimeStamp;
     STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct RTL_CRITICAL_SECTION RTL_CRITICAL_SECTION;
typedef RTL_CRITICAL_SECTION * PRTL_CRITICAL_SECTION;

typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
     WORD Type;
     WORD CreatorBackTraceIndex;
     PRTL_CRITICAL_SECTION CriticalSection;
     LIST_ENTRY ProcessLocksList;
     ULONG EntryCount;
     ULONG ContentionCount;
     ULONG Flags;
     WORD CreatorBackTraceIndexHigh;
     WORD SpareUSHORT;
} RTL_CRITICAL_SECTION_DEBUG, *PRTL_CRITICAL_SECTION_DEBUG;

struct RTL_CRITICAL_SECTION
{
     PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
     LONG LockCount;
     LONG RecursionCount;
     PVOID OwningThread;
     PVOID LockSemaphore;
     ULONG SpinCount;
};

typedef struct PEB_FREE_BLOCK PEB_FREE_BLOCK;
typedef PEB_FREE_BLOCK * PPEB_FREE_BLOCK;

struct PEB_FREE_BLOCK
{
     PPEB_FREE_BLOCK Next;
     ULONG Size;
};

typedef struct _LARGE_INTEGER
{
     union
     {
          struct
          {
               ULONG LowPart;
               LONG HighPart;
          };
          INT64 QuadPart;
     };
} LARGE_INTEGER, *PLARGE_INTEGER;

typedef struct _ULARGE_INTEGER
{
     union
     {
          struct
          {
               ULONG LowPart;
               ULONG HighPart;
          };
          UINT64 QuadPart;
     };
} ULARGE_INTEGER, *PULARGE_INTEGER;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
     ULONG MaximumLength;
     ULONG Length;
     ULONG Flags;
     ULONG DebugFlags;
     PVOID ConsoleHandle;
     ULONG ConsoleFlags;
     PVOID StandardInput;
     PVOID StandardOutput;
     PVOID StandardError;
     CURDIR CurrentDirectory;
     UNICODE_STRING DllPath;
     UNICODE_STRING ImagePathName;
     UNICODE_STRING CommandLine;
     /*
     PVOID Environment;
     ULONG StartingX;
     ULONG StartingY;
     ULONG CountX;
     ULONG CountY;
     ULONG CountCharsX;
     ULONG CountCharsY;
     ULONG FillAttribute;
     ULONG WindowFlags;
     ULONG ShowWindowFlags;
     UNICODE_STRING WindowTitle;
     UNICODE_STRING DesktopInfo;
     UNICODE_STRING ShellInfo;
     UNICODE_STRING RuntimeData;
     RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
     ULONG EnvironmentSize;
     */
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef void _ACTIVATION_CONTEXT_DATA;
typedef void _ASSEMBLY_STORAGE_MAP;
typedef void _FLS_CALLBACK_INFO;
typedef void * PRTL_ACTIVATION_CONTEXT_STACK_FRAME;

typedef struct _PEB_LDR_DATA
{
     ULONG Length;
     UCHAR Initialized;
     PVOID SsHandle;
     LIST_ENTRY InLoadOrderModuleList;
     LIST_ENTRY InMemoryOrderModuleList;
     LIST_ENTRY InInitializationOrderModuleList;
     PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
     UCHAR InheritedAddressSpace;
     UCHAR ReadImageFileExecOptions;
     UCHAR BeingDebugged;
     UCHAR BitField;
     ULONG ImageUsesLargePages: 1;
     ULONG IsProtectedProcess: 1;
     ULONG IsLegacyProcess: 1;
     ULONG IsImageDynamicallyRelocated: 1;
     ULONG SpareBits: 4;
     PVOID Mutant;
     PVOID ImageBaseAddress;
     PPEB_LDR_DATA Ldr;
     PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
     /*
     PVOID SubSystemData;
     PVOID ProcessHeap;
     PRTL_CRITICAL_SECTION FastPebLock;
     PVOID AtlThunkSListPtr;
     PVOID IFEOKey;
     ULONG CrossProcessFlags;
     ULONG ProcessInJob: 1;
     ULONG ProcessInitializing: 1;
     ULONG ReservedBits0: 30;
     union
     {
          PVOID KernelCallbackTable;
          PVOID UserSharedInfoPtr;
     };
     ULONG SystemReserved[1];
     ULONG SpareUlong;
     PPEB_FREE_BLOCK FreeList;
     ULONG TlsExpansionCounter;
     PVOID TlsBitmap;
     ULONG TlsBitmapBits[2];
     PVOID ReadOnlySharedMemoryBase;
     PVOID HotpatchInformation;
     VOID * * ReadOnlyStaticServerData;
     PVOID AnsiCodePageData;
     PVOID OemCodePageData;
     PVOID UnicodeCaseTableData;
     ULONG NumberOfProcessors;
     ULONG NtGlobalFlag;
     LARGE_INTEGER CriticalSectionTimeout;
     ULONG HeapSegmentReserve;
     ULONG HeapSegmentCommit;
     ULONG HeapDeCommitTotalFreeThreshold;
     ULONG HeapDeCommitFreeBlockThreshold;
     ULONG NumberOfHeaps;
     ULONG MaximumNumberOfHeaps;
     VOID * * ProcessHeaps;
     PVOID GdiSharedHandleTable;
     PVOID ProcessStarterHelper;
     ULONG GdiDCAttributeList;
     PRTL_CRITICAL_SECTION LoaderLock;
     ULONG OSMajorVersion;
     ULONG OSMinorVersion;
     WORD OSBuildNumber;
     WORD OSCSDVersion;
     ULONG OSPlatformId;
     ULONG ImageSubsystem;
     ULONG ImageSubsystemMajorVersion;
     ULONG ImageSubsystemMinorVersion;
     ULONG ImageProcessAffinityMask;
     ULONG GdiHandleBuffer[34];
     PVOID PostProcessInitRoutine;
     PVOID TlsExpansionBitmap;
     ULONG TlsExpansionBitmapBits[32];
     ULONG SessionId;
     ULARGE_INTEGER AppCompatFlags;
     ULARGE_INTEGER AppCompatFlagsUser;
     PVOID pShimData;
     PVOID AppCompatInfo;
     UNICODE_STRING CSDVersion;
     _ACTIVATION_CONTEXT_DATA * ActivationContextData;
     _ASSEMBLY_STORAGE_MAP * ProcessAssemblyStorageMap;
     _ACTIVATION_CONTEXT_DATA * SystemDefaultActivationContextData;
     _ASSEMBLY_STORAGE_MAP * SystemAssemblyStorageMap;
     ULONG MinimumStackCommit;
     _FLS_CALLBACK_INFO * FlsCallback;
     LIST_ENTRY FlsListHead;
     PVOID FlsBitmap;
     ULONG FlsBitmapBits[4];
     ULONG FlsHighIndex;
     PVOID WerRegistrationData;
     PVOID WerShipAssertPtr;
     */
} PEB, *PPEB;

typedef struct _ACTIVATION_CONTEXT_STACK
{
     PRTL_ACTIVATION_CONTEXT_STACK_FRAME ActiveFrame;
     LIST_ENTRY FrameListCache;
     ULONG Flags;
     ULONG NextCookieSequenceNumber;
     ULONG StackId;
} ACTIVATION_CONTEXT_STACK, *PACTIVATION_CONTEXT_STACK;

typedef struct _GDI_TEB_BATCH
{
     ULONG Offset;
     ULONG HDC;
     ULONG Buffer[310];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _GUID
{
     ULONG Data1;
     WORD Data2;
     WORD Data3;
     UCHAR Data4[8];
} GUID, *PGUID;

typedef struct TEB_ACTIVE_FRAME TEB_ACTIVE_FRAME;
typedef TEB_ACTIVE_FRAME * PTEB_ACTIVE_FRAME;

typedef struct _TEB_ACTIVE_FRAME_CONTEXT
{
     ULONG Flags;
     CHAR * FrameName;
} TEB_ACTIVE_FRAME_CONTEXT, *PTEB_ACTIVE_FRAME_CONTEXT;

struct TEB_ACTIVE_FRAME
{
     ULONG Flags;
     PTEB_ACTIVE_FRAME Previous;
     PTEB_ACTIVE_FRAME_CONTEXT Context;
};

typedef struct _TEB
{
     NT_TIB NtTib;
     PVOID EnvironmentPointer;
     CLIENT_ID ClientId;
     PVOID ActiveRpcHandle;
     PVOID ThreadLocalStoragePointer;
     PPEB ProcessEnvironmentBlock;
     /*
     ULONG LastErrorValue;
     ULONG CountOfOwnedCriticalSections;
     PVOID CsrClientThread;
     PVOID Win32ThreadInfo;
     ULONG User32Reserved[26];
     ULONG UserReserved[5];
     PVOID WOW32Reserved;
     ULONG CurrentLocale;
     ULONG FpSoftwareStatusRegister;
     VOID * SystemReserved1[54];
     LONG ExceptionCode;
     PACTIVATION_CONTEXT_STACK ActivationContextStackPointer;
     UCHAR SpareBytes1[36];
     ULONG TxFsContext;
     GDI_TEB_BATCH GdiTebBatch;
     CLIENT_ID RealClientId;
     PVOID GdiCachedProcessHandle;
     ULONG GdiClientPID;
     ULONG GdiClientTID;
     PVOID GdiThreadLocalInfo;
     ULONG Win32ClientInfo[62];
     VOID * glDispatchTable[233];
     ULONG glReserved1[29];
     PVOID glReserved2;
     PVOID glSectionInfo;
     PVOID glSection;
     PVOID glTable;
     PVOID glCurrentRC;
     PVOID glContext;
     ULONG LastStatusValue;
     UNICODE_STRING StaticUnicodeString;
     WCHAR StaticUnicodeBuffer[261];
     PVOID DeallocationStack;
     VOID * TlsSlots[64];
     LIST_ENTRY TlsLinks;
     PVOID Vdm;
     PVOID ReservedForNtRpc;
     VOID * DbgSsReserved[2];
     ULONG HardErrorMode;
     VOID * Instrumentation[9];
     GUID ActivityId;
     PVOID SubProcessTag;
     PVOID EtwLocalData;
     PVOID EtwTraceData;
     PVOID WinSockData;
     ULONG GdiBatchCount;
     UCHAR SpareBool0;
     UCHAR SpareBool1;
     UCHAR SpareBool2;
     UCHAR IdealProcessor;
     ULONG GuaranteedStackBytes;
     PVOID ReservedForPerf;
     PVOID ReservedForOle;
     ULONG WaitingOnLoaderLock;
     PVOID SavedPriorityState;
     ULONG SoftPatchPtr1;
     PVOID ThreadPoolData;
     VOID * * TlsExpansionSlots;
     ULONG ImpersonationLocale;
     ULONG IsImpersonating;
     PVOID NlsCache;
     PVOID pShimData;
     ULONG HeapVirtualAffinity;
     PVOID CurrentTransactionHandle;
     PTEB_ACTIVE_FRAME ActiveFrame;
     PVOID FlsData;
     PVOID PreferredLanguages;
     PVOID UserPrefLanguages;
     PVOID MergedPrefLanguages;
     ULONG MuiImpersonation;
     WORD CrossTebFlags;
     ULONG SpareCrossTebBits: 16;
     WORD SameTebFlags;
     ULONG DbgSafeThunkCall: 1;
     ULONG DbgInDebugPrint: 1;
     ULONG DbgHasFiberData: 1;
     ULONG DbgSkipThreadAttach: 1;
     ULONG DbgWerInShipAssertCode: 1;
     ULONG DbgRanProcessInit: 1;
     ULONG DbgClonedThread: 1;
     ULONG DbgSuppressDebugMsg: 1;
     ULONG SpareSameTebBits: 8;
     PVOID TxnScopeEnterCallback;
     PVOID TxnScopeExitCallback;
     PVOID TxnScopeContext;
     ULONG LockCount;
     ULONG ProcessRundown;
     UINT64 LastSwitchTime;
     UINT64 TotalSwitchOutTime;
     LARGE_INTEGER WaitReasonBitMap;
     */
} TEB, *PTEB;
