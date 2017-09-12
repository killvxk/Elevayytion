#include "CPUZ.h"
#include "Process.h"

int main()
{
	CPUZ* cpuz = new CPUZ();
	bool success = cpuz->LoadDriver();
	cout << "loaded driver successfully: " << success << endl;

	success = cpuz->LoadDevice();
	cout << "loaded device successfully: " << success << endl;

	Process process(cpuz);
	
	//HANDLE weakHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, 8360);
	//if (process.Attach(GetCurrentProcessId()))
	if (process.Attach(GetCurrentProcessId()))
	{
		/*
		if (!process.GrantHandleAccess(weakHandle, PROCESS_ALL_ACCESS))
			cout << "failed to grant access" << endl;
			*/

		// PPL value is 97
		//if (!process.GivePPL())
			
		process.GivePPL();
		
		process.Detach();
	}
	else 
	{
		cout << "failed to attach to process" << endl;
	}

	success = cpuz->UnloadDriver();

	HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, 4272);
	cout << handle << endl;

	while (1) Sleep(1);

	cout << "unloaded device successfully: " << success << endl;
}