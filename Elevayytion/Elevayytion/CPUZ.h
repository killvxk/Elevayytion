#pragma once

#include "Includes.h"

class CPUZ
{
private:
	wstring driverDisplayName = L"cpuz141";
	wstring driverFileName = L"C:\\Windows\\System32\\drivers\\cpuz141.sys";
	wstring driverDeviceName = L"\\Device\\cpuz141";

	DWORD IOCTL_READ_CR = 0x9C402428;
	DWORD IOCTL_READ_MEM = 0x9C402420;
	DWORD IOCTL_WRITE_MEM = 0x9C402430;

	SC_HANDLE serviceHandle;
	HANDLE deviceHandle;

	SERVICE_NOTIFY notification;

public:
	CPUZ();

	bool UnloadDriver();
	bool LoadDriver();
	bool LoadDevice();

	uint64_t ReadCR0();
	uint64_t ReadCR2();
	uint64_t ReadCR3();

	uint64_t TranslateLinearAddress(uint64_t directoryTableBase, LPVOID virtualAddress);

	bool ReadPhysicalAddress(uint64_t address, LPVOID buffer, size_t len);
	bool WritePhysicalAddress(uint64_t address, LPVOID buffer, size_t len);
	bool ReadSystemAddress(LPVOID address, LPVOID buf, size_t len);
	bool WriteSystemAddress(LPVOID address, LPVOID buffer, size_t len);

	template<typename T, typename U>
	T ReadPhysicalAddress(U address)
	{
		T buf;
		ReadPhysicalAddress((uint64_t)address, (uint8_t*)&buf, sizeof(T));
		return buf;
	}

	template<typename T, typename U>
	T ReadSystemAddress(U address)
	{
		T buf;
		ReadSystemAddress((LPVOID)address, (uint8_t*)&buf, sizeof(T));
		return buf;
	}

	template<typename T, typename U>
	bool WritePhysicalAddress(T address, U value)
	{
		return WritePhysicalAddress((LPVOID)address, (uint8_t*)&value, sizeof(U));
	}

	template<typename T, typename U>
	bool WriteSystemAddress(T address, U value)
	{
		return WriteSystemAddress((LPVOID)address, (uint8_t*)&value, sizeof(U));
	}
};