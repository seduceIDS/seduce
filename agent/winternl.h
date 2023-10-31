#ifndef WINTERNL_H
#define WINTERNL_H 1

#include <stdint.h>
#include <stdbool.h>

typedef struct _LIST_ENTRY {
  uint32_t Flink;
  uint32_t Blink;
} LIST_ENTRY, *PLIST_ENTRY;

typedef struct _UNICODE_STRING {
  uint16_t Length;
  uint16_t MaximumLength;
  uint32_t  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _LDR_MODULE {
   LIST_ENTRY InLoadOrderModuleList;
   LIST_ENTRY InMemoryOrderModuleList;
   LIST_ENTRY InInitializationOrderModuleList;
   uint32_t BaseAddress;
   uint32_t EntryPoint;
   uint32_t SizeOfImage;
   UNICODE_STRING FullDllName;
   UNICODE_STRING BaseDllName;
   uint32_t Flags;
   int16_t LoadCount;
   int16_t TlsIndex;
   LIST_ENTRY HashTableEntry;
   uint32_t TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _PEB_LDR_DATA {
   uint32_t Length;
   _Bool Initialized;
   uint32_t SsHandle;
   LIST_ENTRY InLoadOrderModuleList;
   LIST_ENTRY InMemoryOrderModuleList;
   LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
  uint8_t Reserved1[16];
  uint32_t Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

/* typedef struct _PEB {
  uint8_t                       Reserved1[2];
  uint8_t                       BeingDebugged;
  uint8_t                       Reserved2[1];
  void*                         Reserved3[2];
  PEB_LDR_DATA                  Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  void*                         Reserved4[3];
  void*                         AtlThunkSListPtr;
  void*                         Reserved5;
  uint32_t                      Reserved6;
  void*                         Reserved7;
  uint32_t                      Reserved8;
  uint32_t                      AtlThunkSListPtr32;
  void*                         Reserved9[45];
  uint8_t                       Reserved10[96];
  void*                         PostProcessInitRoutine;
  uint8_t                       Reserved11[128];
  void*                         Reserved12[1];
  uint32_t                      SessionId;
} PEB, *PPEB; */

typedef struct _NT_TIB {
    uint32_t ExceptionList;
    uint32_t StackBase;
    uint32_t StackLimit;
    uint32_t Reserved1;
    uint32_t Reserved2;
    uint32_t Reserved3;
    uint32_t Self;
} NT_TIB, *PNT_TIB;

typedef struct _CLIENT_ID {
    uint32_t UniqueProcess;
    uint32_t UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

/* typedef struct _TEB {
    NT_TIB NtTib;
    uint32_t EnvironmentPointer;
    CLIENT_ID ClientId;
    uint32_t ActiveRpcHandle;
    uint32_t ThreadLocalStoragePointer;
    uint32_t ProcessEnvironmentBlock;
    uint32_t LastErrorValue;
    uint32_t CountOfOwnedCriticalSections;
    uint32_t CsrClientThread;
    uint32_t Win32ThreadInfo;
    uint32_t User32Reserved[26];
    uint32_t UserReserved[5];
    uint32_t WOW32Reserved;
    uint32_t CurrentLocale;
} TEB, *TEB; */

typedef struct _GDI_TEB_BATCH {
    uint32_t Offset;
    uint32_t HDC;
    uint32_t Buffer[310];
} GDI_TEB_BATCH, *PGDI_TEB_BATCH;

typedef struct _PROCESSOR_NUMBER {
    uint16_t Group;
    uint8_t Number;
    uint8_t Reserved;
}PROCESSOR_NUMBER, *PPROCESSOR_NUMBER;

typedef struct _GUID {
    uint32_t Data1;
    uint16_t Data2;
    uint16_t Data3;
    uint8_t Data4[8];
} GUID, *PGUID;

#pragma pack(push, 8)  // Set packing to 8 bytes
typedef struct __TEB {
    NT_TIB NtTib;
    uint32_t EnvironmentPointer;
    CLIENT_ID ClientId;
    uint32_t ActiveRpcuint32_t;
    uint32_t ThreadLocalStoragePointer;
    uint32_t ProcessEnvironmentBlock;  // PPEB
    uint32_t LastErrorValue;
    uint32_t CountOfOwnedCriticalSections;
    uint32_t CsrClientThread;
    uint32_t Win32ThreadInfo;
    uint32_t User32Reserved[26];
    uint32_t UserReserved[5];
    uint32_t WOW32Reserved;  // ptr to wow64cpu!X86SwitchTo64BitMode
    uint32_t CurrentLocale;
    uint32_t FpSoftwareStatusRegister;
    uint32_t SystemReserved1[54];
    uint32_t ExceptionCode;
    uint32_t ActivationContextStackPointer;  // PACTIVATION_CONTEXT_STACK
    uint8_t SpareBytes[36];
    uint32_t TxFsContext;
    GDI_TEB_BATCH GdiTebBatch;
    CLIENT_ID RealClientId;
    uint32_t GdiCachedProcessuint32_t;
    uint32_t GdiClientPID;
    uint32_t GdiClientTID;
    uint32_t GdiThreadLocalInfo;
    uint32_t Win32ClientInfo[62];
    uint32_t glDispatchTable[233];
    uint32_t glReserved1[29];
    uint32_t glReserved2;
    uint32_t glSectionInfo;
    uint32_t glSection;
    uint32_t glTable;
    uint32_t glCurrentRC;
    uint32_t glContext;
    uint32_t LastStatusValue;
    UNICODE_STRING StaticUnicodeString;
    uint16_t StaticUnicodeBuffer[261];
    uint32_t DeallocationStack;
    uint32_t TlsSlots[64];
    LIST_ENTRY TlsLinks;
    uint32_t Vdm;
    uint32_t ReservedForNtRpc;
    uint32_t DbgSsReserved[2];
    uint32_t HardErrorMode;
    uint32_t Instrumentation[9];
    GUID ActivityId;
    uint32_t SubProcessTag;
    uint32_t EtwLocalData;
    uint32_t EtwTraceData;
    uint32_t WinSockData;
    uint32_t GdiBatchCount;
    PROCESSOR_NUMBER CurrentIdealProcessor;
    uint32_t IdealProcessorValue;
    uint8_t ReservedPad0;
    uint8_t ReservedPad1;
    uint8_t ReservedPad2;
    uint8_t IdealProcessor;
    uint32_t GuaranteedStackBytes;
    uint32_t ReservedForPerf;
    uint32_t ReservedForOle;
    uint32_t WaitingOnLoaderLock;
    uint32_t SavedPriorityState;
    uint32_t SoftPatchPtr1;
    uint32_t ThreadPoolData;
    uint32_t TlsExpansionSlots;  // Ptr32 Ptr32 Void
    uint32_t MuiGeneration;
    _Bool IsImpersonating;
    uint32_t NlsCache;
    uint32_t pShimData;
    uint32_t HeapVirtualAffinity;
    uint32_t CurrentTransactionuint32_t;
    uint32_t ActiveFrame;  // PTEB_ACTIVE_FRAME
    uint32_t FlsData;
    uint32_t PreferredLanguages;
    uint32_t UserPrefLanguages;
    uint32_t MergedPrefLanguages;
    _Bool MuiImpersonation;
    uint16_t CrossTebFlags;
    uint16_t SameTebFlags;
    uint32_t TxnScopeEnterCallback;
    uint32_t TxnScopeExitCallback;
    uint32_t TxnScopeContext;
    uint32_t LockCount;
    uint32_t SpareUlong0;
    uint32_t ResourceRetValue;
} TEB, *PTEB;



typedef struct __PEB {
    uint8_t InheritedAddressSpace;
    uint8_t ReadImageFileExecOptions;
    uint8_t BeingDebugged;
    uint8_t BitField;
    uint32_t Mutant;
    uint32_t ImageBaseAddress;
    uint32_t Ldr;  //PEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    uint32_t SubSystemData;
    uint32_t ProcessHeap;
    uint32_t FastPebLock;
    uint32_t AtlThunkSListPtr;
    uint32_t IFEOKey;
    uint32_t CrossProcessFlags;
    uint32_t UserSharedInfoPtr;
    uint32_t SystemReserved;
    uint32_t AtlThunkSListPtr32;
    uint32_t ApiSetMap;
    uint32_t TlsExpansionCounter;
    uint32_t TlsBitmap;
    uint32_t TlsBitmapBits[2];
    uint32_t ReadOnlySharedMemoryBase;
    uint32_t SharedData;
    uint32_t ReadOnlyStaticServerData;
    uint32_t AnsiCodePageData;
    uint32_t OemCodePageData;
    uint32_t UnicodeCaseTableData;
    uint32_t NumberOfProcessors;
    uint32_t NtGlobalFlag;
    int64_t CriticalSectionTimeout;
    uint32_t HeapSegmentReserve;
    uint32_t HeapSegmentCommit;
    uint32_t HeapDeCommitTotalFreeThreshold;
    uint32_t HeapDeCommitFreeBlockThreshold;
    uint32_t NumberOfHeaps;
    uint32_t MaximumNumberOfHeaps;
    uint32_t ProcessHeaps;
    uint32_t GdiSharedHandleTable;
    uint32_t ProcessStarterHelper;
    uint32_t GdiDCAttributeList;
    uint32_t LoaderLock;
    uint32_t OSMajorVersion;
    uint32_t OSMinorVersion;
    uint16_t OSBuildNumber;
    uint16_t OSCSDVersion;
    uint32_t OSPlatformId;
    uint32_t ImageSubsystem;
    uint32_t ImageSubsystemMajorVersion;
    uint32_t ImageSubsystemMinorVersion;
    uint32_t ActiveProcessAffinityMask;
    uint32_t GdiHandleBuffer[34]; // or [60] depending on the ptr_size
    uint32_t PostProcessInitRoutine;
    uint32_t TlsExpansionBitmap;
    uint32_t TlsExpansionBitmapBits[32];
    uint32_t SessionId;
    uint64_t AppCompatFlags;
    uint64_t AppCompatFlagsUser;
    uint32_t pShimData;
    uint32_t AppCompatInfo;
    UNICODE_STRING CSDVersion;
    uint32_t ActivationContextData;
    uint32_t ProcessAssemblyStorageMap;
    uint32_t SystemDefaultActivationContextData;
    uint32_t SystemAssemblyStorageMap;
    uint32_t MinimumStackCommit;
    uint32_t FlsCallback;
    LIST_ENTRY FlsListHead;
    uint32_t FlsBitmap;
    uint32_t FlsBitmapBits[4];
    uint32_t FlsHighIndex;
    uint32_t WerRegistrationData;
    uint32_t WerShipAssertPtr;
    uint32_t pUnused; // pContextData
    uint32_t pImageHeaderHash;
    uint64_t TracingFlags;
    uint64_t CsrServerReadOnlySharedMemoryBase;
    uint32_t TppWorkerpListLock;
    LIST_ENTRY TppWorkerpList;
    uint32_t WaitOnAddressHashTable[128];
} PEB, * PPEB;

#endif // WINTERNL_H
