#pragma once

#include "Includes.h"
#include "DynData.h"
#include "CPUZ.h"

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

struct ProcessContext
{
	uint32_t pid;
	uint64_t dir_base;
	uint64_t kernel_entry;

};
class Process
{
private:
	stack<ProcessContext> contextStack;
	ProcessContext* currentContext;
	CPUZ* cpuz;

	LPVOID GetKernelBase(PSIZE_T kernelSize);
	uint8_t* FindKernelProc(const char* name);
	ProcessContext FindProcessInfo(uint32_t pid);

public:
	Process(CPUZ* cpuz);

	bool Attach(uint32_t pid);
	void Detach();
	bool GrantHandleAccess(HANDLE handle, ACCESS_MASK accessRights);
	bool StripPPL();

	bool Read(PVOID base, PVOID buf, size_t len);
	bool Write(PVOID base, PVOID buf, size_t len);

	template<typename T, typename U>
	T Read(U base)
	{
		T value;
		Read((PVOID)base, &value, sizeof(T));
		return value;
	}

	template<typename T, typename U>
	bool Write(U base, T value)
	{
		return Write((PVOID)base, &value, sizeof(T));
	}

	PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntryWin7(PHANDLE_TABLE HandleTable, ULONGLONG Handle);
	PHANDLE_TABLE_ENTRY ExpLookupHandleTableEntry(PHANDLE_TABLE HandleTable, ULONGLONG Handle);
};