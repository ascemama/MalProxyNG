#include "RpcLib/MalproxySession.h"
#include "Framework/Utils.h"
#include "Framework/NtHelper.h"
#include <Windows.h>
#include "MalproxyClientRunner.h"

HANDLE WINAPI Malproxy_CreateFileW (
    MalproxySession* client
    ,wchar_t* lpFileName
    ,DWORD dwDesiredAccess
    ,DWORD dwShareMode
    ,LPVOID lpSecurityAttributes
    ,DWORD dwCreationDisposition
    ,DWORD dwFlagsAndAttributes
    ,HANDLE hTemplateFile
) {
if (lpSecurityAttributes != nullptr) THROW("lpSecurityAttributes must be nullptr");
malproxy::CallFuncRequest request;
request.set_dll_name("kernel32.dll");
request.set_function_name("CreateFileW");

malproxy::Argument* arg_lpFileName = request.add_in_arguments();
arg_lpFileName->set_wstring_val(StringUtils::Utf16ToUtf8(lpFileName));

malproxy::Argument* arg_dwDesiredAccess = request.add_in_arguments();
arg_dwDesiredAccess->set_uint32_val((DWORD)dwDesiredAccess);
malproxy::Argument* arg_dwShareMode = request.add_in_arguments();
arg_dwShareMode->set_uint32_val((DWORD)dwShareMode);
malproxy::Argument* arg_lpSecurityAttributes = request.add_in_arguments();
arg_lpSecurityAttributes->set_empty_val((LPVOID)true);
malproxy::Argument* arg_dwCreationDisposition = request.add_in_arguments();
arg_dwCreationDisposition->set_uint32_val((DWORD)dwCreationDisposition);
malproxy::Argument* arg_dwFlagsAndAttributes = request.add_in_arguments();
arg_dwFlagsAndAttributes->set_uint32_val((DWORD)dwFlagsAndAttributes);
malproxy::Argument* arg_hTemplateFile = request.add_in_arguments();
std::unique_ptr<malproxy::HandleType> handle_hTemplateFile = std::make_unique<malproxy::HandleType>();
handle_hTemplateFile->set_handle((uint64_t)hTemplateFile);
arg_hTemplateFile->set_allocated_handle_val(handle_hTemplateFile.release());


auto response = client->CallFunc(request);
return (HANDLE)response.return_value().handle_val().handle();
}

HANDLE WINAPI CreateFileW_stub (
wchar_t* lpFileName,DWORD dwDesiredAccess,DWORD dwShareMode,LPVOID lpSecurityAttributes,DWORD dwCreationDisposition,DWORD dwFlagsAndAttributes,HANDLE hTemplateFile
) {
return Malproxy_CreateFileW(MalproxyClientRunner::Instance().Session().get()
    ,lpFileName
    ,dwDesiredAccess
    ,dwShareMode
    ,lpSecurityAttributes
    ,dwCreationDisposition
    ,dwFlagsAndAttributes
    ,hTemplateFile
);
}

void WINAPI Malproxy_OutputDebugStringW (
    MalproxySession* client
    ,wchar_t* lpOutputString
) {
malproxy::CallFuncRequest request;
request.set_dll_name("kernel32.dll");
request.set_function_name("OutputDebugStringW");

malproxy::Argument* arg_lpOutputString = request.add_in_arguments();
arg_lpOutputString->set_wstring_val(StringUtils::Utf16ToUtf8(lpOutputString));


auto response = client->CallFunc(request);
}

void WINAPI OutputDebugStringW_stub (
wchar_t* lpOutputString
) {
return Malproxy_OutputDebugStringW(MalproxyClientRunner::Instance().Session().get()
    ,lpOutputString
);
}

void WINAPI Malproxy_OutputDebugStringA (
    MalproxySession* client
    ,char* lpOutputString
) {
malproxy::CallFuncRequest request;
request.set_dll_name("kernel32.dll");
request.set_function_name("OutputDebugStringA");

malproxy::Argument* arg_lpOutputString = request.add_in_arguments();
arg_lpOutputString->set_string_val((char*)lpOutputString);

auto response = client->CallFunc(request);
}

void WINAPI OutputDebugStringA_stub (
char* lpOutputString
) {
return Malproxy_OutputDebugStringA(MalproxyClientRunner::Instance().Session().get()
    ,lpOutputString
);
}

DWORD WINAPI Malproxy_GetLastError (
    MalproxySession* client
) {
malproxy::CallFuncRequest request;
request.set_dll_name("kernel32.dll");
request.set_function_name("GetLastError");


auto response = client->CallFunc(request);
return (DWORD)response.return_value().uint32_val();
}

DWORD WINAPI GetLastError_stub (

) {
return Malproxy_GetLastError(MalproxyClientRunner::Instance().Session().get()
);
}

DWORD WINAPI Malproxy_NtQuerySystemInformation (
    MalproxySession* client
    ,DWORD SystemInformationClass
    ,LPVOID SystemInformation, DWORD SystemInformationLength
    ,DWORD* ReturnLength
) {
malproxy::CallFuncRequest request;
request.set_dll_name("ntdll.dll");
request.set_function_name("NtQuerySystemInformation");

malproxy::Argument* arg_SystemInformationClass = request.add_in_arguments();
arg_SystemInformationClass->set_uint32_val((DWORD)SystemInformationClass);
malproxy::Argument* arg_SystemInformation = request.add_in_arguments();
std::unique_ptr<malproxy::BufferArgument> arg_SystemInformation_value_buffer = std::make_unique<malproxy::BufferArgument>();
arg_SystemInformation_value_buffer->set_size(SystemInformationLength);
arg_SystemInformation_value_buffer->set_type(malproxy::BufferType::BufferType_UserAllocated);
arg_SystemInformation->set_allocated_buffer_val(arg_SystemInformation_value_buffer.release());


malproxy::Argument* arg_ReturnLength = request.add_in_arguments();

auto response = client->CallFunc(request);
auto out_buffer_SystemInformation = response.out_arguments(0).buffer_val();
auto out_buffer_SystemInformation_data = out_buffer_SystemInformation.data();
if (out_buffer_SystemInformation.type() == malproxy::BufferType::BufferType_UserAllocated && !out_buffer_SystemInformation_data.empty()) {
 memcpy(SystemInformation, out_buffer_SystemInformation_data.data(), std::min((DWORD)out_buffer_SystemInformation_data.size(), SystemInformationLength));
 unsigned long long diff = (unsigned long long)(ULONG_PTR)SystemInformation - out_buffer_SystemInformation.relocations().base_address();
 for (auto offset : out_buffer_SystemInformation.relocations().offsets()) {
  unsigned long long* current = (unsigned long long*)(((char*)SystemInformation) + offset);
  if (*current != 0) *current += diff;
 }
}

if (ReturnLength != nullptr) *ReturnLength = (DWORD)response.out_arguments(1).uint32_val();
return (DWORD)response.return_value().uint32_val();
}

DWORD WINAPI NtQuerySystemInformation_stub (
DWORD SystemInformationClass,LPVOID SystemInformation, DWORD SystemInformationLength,DWORD* ReturnLength
) {
return Malproxy_NtQuerySystemInformation(MalproxyClientRunner::Instance().Session().get()
    ,SystemInformationClass
    ,SystemInformation,SystemInformationLength
    ,ReturnLength
);
}

HANDLE WINAPI Malproxy_OpenProcess (
    MalproxySession* client
    ,DWORD dwDesiredAccess
    ,BOOL bInheritHandle
    ,DWORD dwProcessId
) {
malproxy::CallFuncRequest request;
request.set_dll_name("kernel32.dll");
request.set_function_name("OpenProcess");

malproxy::Argument* arg_dwDesiredAccess = request.add_in_arguments();
arg_dwDesiredAccess->set_uint32_val((DWORD)dwDesiredAccess);
malproxy::Argument* arg_bInheritHandle = request.add_in_arguments();
arg_bInheritHandle->set_bool_val((BOOL)bInheritHandle);
malproxy::Argument* arg_dwProcessId = request.add_in_arguments();
arg_dwProcessId->set_uint32_val((DWORD)dwProcessId);

auto response = client->CallFunc(request);
return (HANDLE)response.return_value().handle_val().handle();
}

HANDLE WINAPI OpenProcess_stub (
DWORD dwDesiredAccess,BOOL bInheritHandle,DWORD dwProcessId
) {
return Malproxy_OpenProcess(MalproxyClientRunner::Instance().Session().get()
    ,dwDesiredAccess
    ,bInheritHandle
    ,dwProcessId
);
}

DWORD WINAPI Malproxy_GetProcessId (
    MalproxySession* client
    ,HANDLE Process
) {
malproxy::CallFuncRequest request;
request.set_dll_name("kernel32.dll");
request.set_function_name("GetProcessId");

malproxy::Argument* arg_Process = request.add_in_arguments();
std::unique_ptr<malproxy::HandleType> handle_Process = std::make_unique<malproxy::HandleType>();
handle_Process->set_handle((uint64_t)Process);
arg_Process->set_allocated_handle_val(handle_Process.release());


auto response = client->CallFunc(request);
return (DWORD)response.return_value().uint32_val();
}

DWORD WINAPI GetProcessId_stub (
HANDLE Process
) {
return Malproxy_GetProcessId(MalproxyClientRunner::Instance().Session().get()
    ,Process
);
}

BOOL WINAPI Malproxy_OpenProcessToken (
    MalproxySession* client
    ,HANDLE ProcessHandle
    ,DWORD DesiredAccess
    ,HANDLE* TokenHandle
) {
malproxy::CallFuncRequest request;
request.set_dll_name("advapi32.dll");
request.set_function_name("OpenProcessToken");

malproxy::Argument* arg_ProcessHandle = request.add_in_arguments();
std::unique_ptr<malproxy::HandleType> handle_ProcessHandle = std::make_unique<malproxy::HandleType>();
handle_ProcessHandle->set_handle((uint64_t)ProcessHandle);
arg_ProcessHandle->set_allocated_handle_val(handle_ProcessHandle.release());

malproxy::Argument* arg_DesiredAccess = request.add_in_arguments();
arg_DesiredAccess->set_uint32_val((DWORD)DesiredAccess);
malproxy::Argument* arg_TokenHandle = request.add_in_arguments();

auto response = client->CallFunc(request);
*TokenHandle = (HANDLE)response.out_arguments(0).handle_val().handle();
return (BOOL)response.return_value().bool_val();
}

BOOL WINAPI OpenProcessToken_stub (
HANDLE ProcessHandle,DWORD DesiredAccess,HANDLE* TokenHandle
) {
return Malproxy_OpenProcessToken(MalproxyClientRunner::Instance().Session().get()
    ,ProcessHandle
    ,DesiredAccess
    ,TokenHandle
);
}

DWORD WINAPI Malproxy_NtQueryInformationProcess (
    MalproxySession* client
    ,HANDLE ProcessHandle
    ,DWORD PROCESSINFOCLASS
    ,LPVOID ProcessInformation, DWORD ProcessInformationLength
    ,DWORD* ReturnLength
) {
malproxy::CallFuncRequest request;
request.set_dll_name("ntdll.dll");
request.set_function_name("NtQueryInformationProcess");

malproxy::Argument* arg_ProcessHandle = request.add_in_arguments();
std::unique_ptr<malproxy::HandleType> handle_ProcessHandle = std::make_unique<malproxy::HandleType>();
handle_ProcessHandle->set_handle((uint64_t)ProcessHandle);
arg_ProcessHandle->set_allocated_handle_val(handle_ProcessHandle.release());

malproxy::Argument* arg_PROCESSINFOCLASS = request.add_in_arguments();
arg_PROCESSINFOCLASS->set_uint32_val((DWORD)PROCESSINFOCLASS);
malproxy::Argument* arg_ProcessInformation = request.add_in_arguments();
std::unique_ptr<malproxy::BufferArgument> arg_ProcessInformation_value_buffer = std::make_unique<malproxy::BufferArgument>();
arg_ProcessInformation_value_buffer->set_size(ProcessInformationLength);
arg_ProcessInformation_value_buffer->set_type(malproxy::BufferType::BufferType_UserAllocated);
arg_ProcessInformation->set_allocated_buffer_val(arg_ProcessInformation_value_buffer.release());


malproxy::Argument* arg_ReturnLength = request.add_in_arguments();

auto response = client->CallFunc(request);
auto out_buffer_ProcessInformation = response.out_arguments(0).buffer_val();
auto out_buffer_ProcessInformation_data = out_buffer_ProcessInformation.data();
if (out_buffer_ProcessInformation.type() == malproxy::BufferType::BufferType_UserAllocated && !out_buffer_ProcessInformation_data.empty()) {
 memcpy(ProcessInformation, out_buffer_ProcessInformation_data.data(), std::min((DWORD)out_buffer_ProcessInformation_data.size(), ProcessInformationLength));
 unsigned long long diff = (unsigned long long)(ULONG_PTR)ProcessInformation - out_buffer_ProcessInformation.relocations().base_address();
 for (auto offset : out_buffer_ProcessInformation.relocations().offsets()) {
  unsigned long long* current = (unsigned long long*)(((char*)ProcessInformation) + offset);
  if (*current != 0) *current += diff;
 }
}

if (ReturnLength != nullptr) *ReturnLength = (DWORD)response.out_arguments(1).uint32_val();
return (DWORD)response.return_value().uint32_val();
}

DWORD WINAPI NtQueryInformationProcess_stub (
HANDLE ProcessHandle,DWORD PROCESSINFOCLASS,LPVOID ProcessInformation, DWORD ProcessInformationLength,DWORD* ReturnLength
) {
return Malproxy_NtQueryInformationProcess(MalproxyClientRunner::Instance().Session().get()
    ,ProcessHandle
    ,PROCESSINFOCLASS
    ,ProcessInformation,ProcessInformationLength
    ,ReturnLength
);
}

DWORD WINAPI Malproxy_ReadProcessMemory (
    MalproxySession* client
    ,HANDLE hProcess
    ,LPVOID lpBaseAddress
    ,LPVOID lpBuffer, DWORD nSize
    ,SIZE_T* lpNumberOfBytesRead
) {
malproxy::CallFuncRequest request;
request.set_dll_name("kernel32.dll");
request.set_function_name("ReadProcessMemory");

malproxy::Argument* arg_hProcess = request.add_in_arguments();
std::unique_ptr<malproxy::HandleType> handle_hProcess = std::make_unique<malproxy::HandleType>();
handle_hProcess->set_handle((uint64_t)hProcess);
arg_hProcess->set_allocated_handle_val(handle_hProcess.release());

malproxy::Argument* arg_lpBaseAddress = request.add_in_arguments();
arg_lpBaseAddress->set_uint64_val((uint64_t)lpBaseAddress);
malproxy::Argument* arg_lpBuffer = request.add_in_arguments();
std::unique_ptr<malproxy::BufferArgument> arg_lpBuffer_value_buffer = std::make_unique<malproxy::BufferArgument>();
arg_lpBuffer_value_buffer->set_size(nSize);
arg_lpBuffer_value_buffer->set_type(malproxy::BufferType::BufferType_UserAllocated);
arg_lpBuffer->set_allocated_buffer_val(arg_lpBuffer_value_buffer.release());


malproxy::Argument* arg_lpNumberOfBytesRead = request.add_in_arguments();

auto response = client->CallFunc(request);
auto out_buffer_lpBuffer = response.out_arguments(0).buffer_val();
auto out_buffer_lpBuffer_data = out_buffer_lpBuffer.data();
if (out_buffer_lpBuffer.type() == malproxy::BufferType::BufferType_UserAllocated && !out_buffer_lpBuffer_data.empty()) {
 memcpy(lpBuffer, out_buffer_lpBuffer_data.data(), std::min((DWORD)out_buffer_lpBuffer_data.size(), nSize));
 unsigned long long diff = (unsigned long long)(ULONG_PTR)lpBuffer - out_buffer_lpBuffer.relocations().base_address();
 for (auto offset : out_buffer_lpBuffer.relocations().offsets()) {
  unsigned long long* current = (unsigned long long*)(((char*)lpBuffer) + offset);
  if (*current != 0) *current += diff;
 }
}

if (lpNumberOfBytesRead != nullptr) *lpNumberOfBytesRead = (SIZE_T)response.out_arguments(1).uint64_val();
return (DWORD)response.return_value().uint32_val();
}

DWORD WINAPI ReadProcessMemory_stub (
HANDLE hProcess,LPVOID lpBaseAddress,LPVOID lpBuffer, DWORD nSize,SIZE_T* lpNumberOfBytesRead
) {
return Malproxy_ReadProcessMemory(MalproxyClientRunner::Instance().Session().get()
    ,hProcess
    ,lpBaseAddress
    ,lpBuffer,nSize
    ,lpNumberOfBytesRead
);
}

DWORD WINAPI Malproxy_RtlAdjustPrivilege (
    MalproxySession* client
    ,DWORD Privilege
    ,BOOL Enable
    ,BOOL CurrentThread
    ,BOOL* Enabled
) {
malproxy::CallFuncRequest request;
request.set_dll_name("ntdll.dll");
request.set_function_name("RtlAdjustPrivilege");

malproxy::Argument* arg_Privilege = request.add_in_arguments();
arg_Privilege->set_uint32_val((DWORD)Privilege);
malproxy::Argument* arg_Enable = request.add_in_arguments();
arg_Enable->set_bool_val((BOOL)Enable);
malproxy::Argument* arg_CurrentThread = request.add_in_arguments();
arg_CurrentThread->set_bool_val((BOOL)CurrentThread);
malproxy::Argument* arg_Enabled = request.add_in_arguments();

auto response = client->CallFunc(request);
if (Enabled != nullptr) *Enabled = (BOOL)response.out_arguments(0).bool_val();
return (DWORD)response.return_value().uint32_val();
}

DWORD WINAPI RtlAdjustPrivilege_stub (
DWORD Privilege,BOOL Enable,BOOL CurrentThread,BOOL* Enabled
) {
return Malproxy_RtlAdjustPrivilege(MalproxyClientRunner::Instance().Session().get()
    ,Privilege
    ,Enable
    ,CurrentThread
    ,Enabled
);
}

std::map<std::string, std::map<std::string, FARPROC>> autogenerated_stubs = {
{
"kernel32.dll",
{
{ "CreateFileW", (FARPROC)CreateFileW_stub },
{ "OutputDebugStringW", (FARPROC)OutputDebugStringW_stub },
{ "OutputDebugStringA", (FARPROC)OutputDebugStringA_stub },
{ "GetLastError", (FARPROC)GetLastError_stub },
{ "OpenProcess", (FARPROC)OpenProcess_stub },
{ "GetProcessId", (FARPROC)GetProcessId_stub },
{ "ReadProcessMemory", (FARPROC)ReadProcessMemory_stub },
}
},
{
"ntdll.dll",
{
{ "NtQuerySystemInformation", (FARPROC)NtQuerySystemInformation_stub },
{ "NtQueryInformationProcess", (FARPROC)NtQueryInformationProcess_stub },
{ "RtlAdjustPrivilege", (FARPROC)RtlAdjustPrivilege_stub },
}
},
{
"advapi32.dll",
{
{ "OpenProcessToken", (FARPROC)OpenProcessToken_stub },
}
},
};
