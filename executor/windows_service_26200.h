// Generated Windows 11 25H2 build 26200 syscall service mappings.
// Service names are mapped to windows/amd64 target IDs in syscalls_windows_nyx_demo.h.
// Source: https://raw.githubusercontent.com/hfiref0x/SyscallTables/master/data/Composition/X86_64/W11/ntos/26200.txt
// Source: https://hfiref0x.github.io/sctables/X86_64/W11_w32ksyscalls.html

#define WINDOWS_NYX_SERVICE_TABLE_26200(X) \
	X(ntos, W32_NTDELAYEXEC, "NtDelayExecution", "NtDelayExecution", 52) \
	X(ntos, W32_NTDEVICEIOCTLFILE, "NtDeviceIoControlFile", "NtDeviceIoControlFile", 7) \
	X(ntos, W32_NTFLUSHICACHE, "NtFlushInstructionCache", "NtFlushInstructionCache", 241) \
	X(ntos, W32_NTFLUSHWBUF, "NtFlushWriteBuffer", "NtFlushWriteBuffer", 245) \
	X(ntos, W32_NTFSCONTROLFILE, "NtFsControlFile", "NtFsControlFile", 57) \
	X(ntos, W32_NTFSCONTROLFILE_NTFS_GET_COMP, "NtFsControlFile$ntfs_get_compression", "NtFsControlFile", 57) \
	X(ntos, W32_NTFSCONTROLFILE_NTFS_SET_COMP, "NtFsControlFile$ntfs_set_compression", "NtFsControlFile", 57) \
	X(ntos, W32_NTFSCONTROLFILE_NTFS_SET_SPARSE, "NtFsControlFile$ntfs_set_sparse", "NtFsControlFile", 57) \
	X(ntos, W32_NTFSCONTROLFILE_NTFS_SET_ZERO_DATA, "NtFsControlFile$ntfs_set_zero_data", "NtFsControlFile", 57) \
	X(ntos, W32_NTFSCONTROLFILE_NTFS_QUERY_ALLOC_RANGES, "NtFsControlFile$ntfs_query_allocated_ranges", "NtFsControlFile", 57) \
	X(ntos, W32_NTPOWERINFO, "NtPowerInformation", "NtPowerInformation", 95) \
	X(ntos, W32_NTQINFO_PROC, "NtQueryInformationProcess", "NtQueryInformationProcess", 25) \
	X(ntos, W32_NTQINFO_SYS, "NtQuerySystemInformation", "NtQuerySystemInformation", 54) \
	X(ntos, W32_NTQINFOFILE_BASIC, "NtQueryInformationFile$basic", "NtQueryInformationFile", 17) \
	X(ntos, W32_NTQINFOFILE_NETOPEN, "NtQueryInformationFile$network_open", "NtQueryInformationFile", 17) \
	X(ntos, W32_NTQINFOFILE_STANDARD, "NtQueryInformationFile$standard", "NtQueryInformationFile", 17) \
	X(ntos, W32_NTQUERYDEFLOCALE, "NtQueryDefaultLocale", "NtQueryDefaultLocale", 21) \
	X(ntos, W32_NTQUERYDEFUILANG, "NtQueryDefaultUILanguage", "NtQueryDefaultUILanguage", 68) \
	X(ntos, W32_NTQUERYPERFCTR, "NtQueryPerformanceCounter", "NtQueryPerformanceCounter", 49) \
	X(ntos, W32_NTQUERYTIMERRES, "NtQueryTimerResolution", "NtQueryTimerResolution", 367) \
	X(ntos, W32_NTQUERYSYSTIME, "NtQuerySystemTime", "NtQuerySystemTime", 91) \
	X(ntos, W32_NTREADFILE, "NtReadFile", "NtReadFile", 6) \
	X(ntos, W32_NTSETINFO_PROC, "NtSetInformationProcess", "NtSetInformationProcess", 28) \
	X(ntos, W32_NTSETINFOFILE_BASIC, "NtSetInformationFile$basic", "NtSetInformationFile", 39) \
	X(ntos, W32_NTSETTIMERRES, "NtSetTimerResolution", "NtSetTimerResolution", 450) \
	X(ntos, W32_NTWRITEFILE, "NtWriteFile", "NtWriteFile", 8) \
	X(ntos, W32_NTYIELDEXEC, "NtYieldExecution", "NtYieldExecution", 70)
