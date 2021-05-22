#include "RpcLib/MalproxyServer.h"
#include "Framework/Utils.h"
#include "Framework/NtHelper.h"
malproxy::CallFuncResponse CreateFileW_stub(const malproxy::CallFuncRequest& request, FARPROC real_func)
{
printf("Running function %s ! %s\n", request.dll_name().c_str(), request.function_name().c_str());
auto lpFileName_data = request.in_arguments(0).wstring_val();
auto lpFileName_wstring = StringUtils::Utf8ToUtf16(lpFileName_data);
wchar_t* lpFileName = (wchar_t*)lpFileName_wstring.c_str();

DWORD dwDesiredAccess = (DWORD)request.in_arguments(1).uint32_val();
DWORD dwShareMode = (DWORD)request.in_arguments(2).uint32_val();
LPVOID lpSecurityAttributes = (LPVOID)nullptr;
DWORD dwCreationDisposition = (DWORD)request.in_arguments(4).uint32_val();
DWORD dwFlagsAndAttributes = (DWORD)request.in_arguments(5).uint32_val();
HANDLE hTemplateFile = (HANDLE)request.in_arguments(6).handle_val().handle();
HANDLE raw_retval =  ((HANDLE(*)(wchar_t*,DWORD,DWORD,LPVOID,DWORD,DWORD,HANDLE))real_func)(lpFileName,dwDesiredAccess,dwShareMode,lpSecurityAttributes,dwCreationDisposition,dwFlagsAndAttributes,hTemplateFile);
malproxy::CallFuncResponse result;
malproxy::Argument retval_value; malproxy::Argument* retval = &retval_value;
std::unique_ptr<malproxy::HandleType> handle_retval_ = std::make_unique<malproxy::HandleType>();
handle_retval_->set_handle((uint64_t)raw_retval);
retval->set_allocated_handle_val(handle_retval_.release());

std::unique_ptr<malproxy::Argument> retval_allocated_ptr = std::make_unique<malproxy::Argument>(retval_value);
result.set_allocated_return_value(retval_allocated_ptr.release());
return result;
}

malproxy::CallFuncResponse OutputDebugStringW_stub(const malproxy::CallFuncRequest& request, FARPROC real_func)
{
printf("Running function %s ! %s\n", request.dll_name().c_str(), request.function_name().c_str());
auto lpOutputString_data = request.in_arguments(0).wstring_val();
auto lpOutputString_wstring = StringUtils::Utf8ToUtf16(lpOutputString_data);
wchar_t* lpOutputString = (wchar_t*)lpOutputString_wstring.c_str();

 ((void(*)(wchar_t*))real_func)(lpOutputString);
malproxy::CallFuncResponse result;
return result;
}

malproxy::CallFuncResponse OutputDebugStringA_stub(const malproxy::CallFuncRequest& request, FARPROC real_func)
{
printf("Running function %s ! %s\n", request.dll_name().c_str(), request.function_name().c_str());
auto lpOutputString_string = request.in_arguments(0).string_val();
char* lpOutputString = (char*)lpOutputString_string.c_str();

 ((void(*)(char*))real_func)(lpOutputString);
malproxy::CallFuncResponse result;
return result;
}

malproxy::CallFuncResponse GetLastError_stub(const malproxy::CallFuncRequest& request, FARPROC real_func)
{
printf("Running function %s ! %s\n", request.dll_name().c_str(), request.function_name().c_str());
DWORD raw_retval =  ((DWORD(*)())real_func)();
malproxy::CallFuncResponse result;
malproxy::Argument retval_value; malproxy::Argument* retval = &retval_value;
retval->set_uint32_val((DWORD)raw_retval);
std::unique_ptr<malproxy::Argument> retval_allocated_ptr = std::make_unique<malproxy::Argument>(retval_value);
result.set_allocated_return_value(retval_allocated_ptr.release());
return result;
}

malproxy::CallFuncResponse NtQuerySystemInformation_stub(const malproxy::CallFuncRequest& request, FARPROC real_func)
{
printf("Running function %s ! %s\n", request.dll_name().c_str(), request.function_name().c_str());
DWORD SystemInformationClass = (DWORD)request.in_arguments(0).uint32_val();
auto SystemInformation_buffer = request.in_arguments(1).buffer_val();
auto SystemInformation_buffer_data = SystemInformation_buffer.data();
DWORD SystemInformationLength = (DWORD)SystemInformation_buffer.size();
LPVOID SystemInformation = nullptr;
std::vector<char> SystemInformation_temp_data(SystemInformationLength);
if (SystemInformationLength > 0) SystemInformation = SystemInformation_temp_data.data();

DWORD ReturnLength_val = { 0 }; DWORD* ReturnLength = &ReturnLength_val;
DWORD raw_retval =  ((DWORD(*)(DWORD,LPVOID,DWORD,DWORD*))real_func)(SystemInformationClass,SystemInformation,SystemInformationLength,ReturnLength);
malproxy::CallFuncResponse result;
malproxy::Argument retval_value; malproxy::Argument* retval = &retval_value;
retval->set_uint32_val((DWORD)raw_retval);
std::unique_ptr<malproxy::Argument> retval_allocated_ptr = std::make_unique<malproxy::Argument>(retval_value);
result.set_allocated_return_value(retval_allocated_ptr.release());
malproxy::Argument* out_SystemInformation = result.add_out_arguments();
std::unique_ptr<malproxy::BufferArgument> SystemInformation_buffer_ptr = std::make_unique<malproxy::BufferArgument>();
std::string out_SystemInformation_data; out_SystemInformation_data.assign((char*)SystemInformation, SystemInformationLength);
SystemInformation_buffer_ptr->set_data(out_SystemInformation_data);
SystemInformation_buffer_ptr->set_size(SystemInformationLength);
SystemInformation_buffer_ptr->set_type(malproxy::BufferType::BufferType_UserAllocated);
std::unique_ptr<malproxy::DataRelocations> SystemInformation_relocations = std::make_unique<malproxy::DataRelocations>();
SystemInformation_relocations->set_base_address((unsigned long long)(ULONG_PTR)SystemInformation);
if (NT_SUCCESS(raw_retval)) {
 for (SYSTEM_PROCESS_INFORMATION* ptr = (SYSTEM_PROCESS_INFORMATION*)SystemInformation; (char*)ptr < (char*)SystemInformation + SystemInformationLength && ptr->NextEntryOffset > 0; ptr = (SYSTEM_PROCESS_INFORMATION*)((char*)ptr + ptr->NextEntryOffset)) {
  SystemInformation_relocations->add_offsets(((unsigned long long)(ULONG_PTR)&ptr->ImageName.Buffer) - (ULONG_PTR)SystemInformation);
 }
}

SystemInformation_buffer_ptr->set_allocated_relocations(SystemInformation_relocations.release());
out_SystemInformation->set_allocated_buffer_val(SystemInformation_buffer_ptr.release());

malproxy::Argument* out_ReturnLength = result.add_out_arguments();
out_ReturnLength->set_uint32_val(*ReturnLength);

return result;
}

malproxy::CallFuncResponse OpenProcess_stub(const malproxy::CallFuncRequest& request, FARPROC real_func)
{
printf("Running function %s ! %s\n", request.dll_name().c_str(), request.function_name().c_str());
DWORD dwDesiredAccess = (DWORD)request.in_arguments(0).uint32_val();
BOOL bInheritHandle = (BOOL)request.in_arguments(1).bool_val();
DWORD dwProcessId = (DWORD)request.in_arguments(2).uint32_val();
HANDLE raw_retval =  ((HANDLE(*)(DWORD,BOOL,DWORD))real_func)(dwDesiredAccess,bInheritHandle,dwProcessId);
malproxy::CallFuncResponse result;
malproxy::Argument retval_value; malproxy::Argument* retval = &retval_value;
std::unique_ptr<malproxy::HandleType> handle_retval_ = std::make_unique<malproxy::HandleType>();
handle_retval_->set_handle((uint64_t)raw_retval);
retval->set_allocated_handle_val(handle_retval_.release());

std::unique_ptr<malproxy::Argument> retval_allocated_ptr = std::make_unique<malproxy::Argument>(retval_value);
result.set_allocated_return_value(retval_allocated_ptr.release());
return result;
}

malproxy::CallFuncResponse GetProcessId_stub(const malproxy::CallFuncRequest& request, FARPROC real_func)
{
printf("Running function %s ! %s\n", request.dll_name().c_str(), request.function_name().c_str());
HANDLE Process = (HANDLE)request.in_arguments(0).handle_val().handle();
DWORD raw_retval =  ((DWORD(*)(HANDLE))real_func)(Process);
malproxy::CallFuncResponse result;
malproxy::Argument retval_value; malproxy::Argument* retval = &retval_value;
retval->set_uint32_val((DWORD)raw_retval);
std::unique_ptr<malproxy::Argument> retval_allocated_ptr = std::make_unique<malproxy::Argument>(retval_value);
result.set_allocated_return_value(retval_allocated_ptr.release());
return result;
}

malproxy::CallFuncResponse OpenProcessToken_stub(const malproxy::CallFuncRequest& request, FARPROC real_func)
{
printf("Running function %s ! %s\n", request.dll_name().c_str(), request.function_name().c_str());
HANDLE ProcessHandle = (HANDLE)request.in_arguments(0).handle_val().handle();
DWORD DesiredAccess = (DWORD)request.in_arguments(1).uint32_val();
HANDLE TokenHandle_handle = nullptr;
HANDLE* TokenHandle = (HANDLE*)&TokenHandle_handle;
BOOL raw_retval =  ((BOOL(*)(HANDLE,DWORD,HANDLE*))real_func)(ProcessHandle,DesiredAccess,TokenHandle);
malproxy::CallFuncResponse result;
malproxy::Argument retval_value; malproxy::Argument* retval = &retval_value;
retval->set_bool_val((BOOL)raw_retval);
std::unique_ptr<malproxy::Argument> retval_allocated_ptr = std::make_unique<malproxy::Argument>(retval_value);
result.set_allocated_return_value(retval_allocated_ptr.release());
malproxy::Argument* out_TokenHandle = result.add_out_arguments();
std::unique_ptr<malproxy::HandleType> TokenHandle_handle_ptr = std::make_unique<malproxy::HandleType>();
TokenHandle_handle_ptr->set_handle((uint64_t)*TokenHandle);
out_TokenHandle->set_allocated_handle_val(TokenHandle_handle_ptr.release());

return result;
}

malproxy::CallFuncResponse NtQueryInformationProcess_stub(const malproxy::CallFuncRequest& request, FARPROC real_func)
{
printf("Running function %s ! %s\n", request.dll_name().c_str(), request.function_name().c_str());
HANDLE ProcessHandle = (HANDLE)request.in_arguments(0).handle_val().handle();
DWORD PROCESSINFOCLASS = (DWORD)request.in_arguments(1).uint32_val();
auto ProcessInformation_buffer = request.in_arguments(2).buffer_val();
auto ProcessInformation_buffer_data = ProcessInformation_buffer.data();
DWORD ProcessInformationLength = (DWORD)ProcessInformation_buffer.size();
LPVOID ProcessInformation = nullptr;
std::vector<char> ProcessInformation_temp_data(ProcessInformationLength);
if (ProcessInformationLength > 0) ProcessInformation = ProcessInformation_temp_data.data();

DWORD ReturnLength_val = { 0 }; DWORD* ReturnLength = &ReturnLength_val;
DWORD raw_retval =  ((DWORD(*)(HANDLE,DWORD,LPVOID,DWORD,DWORD*))real_func)(ProcessHandle,PROCESSINFOCLASS,ProcessInformation,ProcessInformationLength,ReturnLength);
malproxy::CallFuncResponse result;
malproxy::Argument retval_value; malproxy::Argument* retval = &retval_value;
retval->set_uint32_val((DWORD)raw_retval);
std::unique_ptr<malproxy::Argument> retval_allocated_ptr = std::make_unique<malproxy::Argument>(retval_value);
result.set_allocated_return_value(retval_allocated_ptr.release());
malproxy::Argument* out_ProcessInformation = result.add_out_arguments();
std::unique_ptr<malproxy::BufferArgument> ProcessInformation_buffer_ptr = std::make_unique<malproxy::BufferArgument>();
std::string out_ProcessInformation_data; out_ProcessInformation_data.assign((char*)ProcessInformation, ProcessInformationLength);
ProcessInformation_buffer_ptr->set_data(out_ProcessInformation_data);
ProcessInformation_buffer_ptr->set_size(ProcessInformationLength);
ProcessInformation_buffer_ptr->set_type(malproxy::BufferType::BufferType_UserAllocated);
std::unique_ptr<malproxy::DataRelocations> ProcessInformation_relocations = std::make_unique<malproxy::DataRelocations>();
ProcessInformation_relocations->set_base_address((unsigned long long)(ULONG_PTR)ProcessInformation);

ProcessInformation_buffer_ptr->set_allocated_relocations(ProcessInformation_relocations.release());
out_ProcessInformation->set_allocated_buffer_val(ProcessInformation_buffer_ptr.release());

malproxy::Argument* out_ReturnLength = result.add_out_arguments();
out_ReturnLength->set_uint32_val(*ReturnLength);

return result;
}

malproxy::CallFuncResponse ReadProcessMemory_stub(const malproxy::CallFuncRequest& request, FARPROC real_func)
{
printf("Running function %s ! %s\n", request.dll_name().c_str(), request.function_name().c_str());
HANDLE hProcess = (HANDLE)request.in_arguments(0).handle_val().handle();
LPVOID lpBaseAddress = (LPVOID)request.in_arguments(1).uint64_val();
auto lpBuffer_buffer = request.in_arguments(2).buffer_val();
auto lpBuffer_buffer_data = lpBuffer_buffer.data();
DWORD nSize = (DWORD)lpBuffer_buffer.size();
LPVOID lpBuffer = nullptr;
std::vector<char> lpBuffer_temp_data(nSize);
if (nSize > 0) lpBuffer = lpBuffer_temp_data.data();

SIZE_T lpNumberOfBytesRead_val = { 0 }; SIZE_T* lpNumberOfBytesRead = &lpNumberOfBytesRead_val;
DWORD raw_retval =  ((DWORD(*)(HANDLE,LPVOID,LPVOID,DWORD,SIZE_T*))real_func)(hProcess,lpBaseAddress,lpBuffer,nSize,lpNumberOfBytesRead);
malproxy::CallFuncResponse result;
malproxy::Argument retval_value; malproxy::Argument* retval = &retval_value;
retval->set_uint32_val((DWORD)raw_retval);
std::unique_ptr<malproxy::Argument> retval_allocated_ptr = std::make_unique<malproxy::Argument>(retval_value);
result.set_allocated_return_value(retval_allocated_ptr.release());
malproxy::Argument* out_lpBuffer = result.add_out_arguments();
std::unique_ptr<malproxy::BufferArgument> lpBuffer_buffer_ptr = std::make_unique<malproxy::BufferArgument>();
std::string out_lpBuffer_data; out_lpBuffer_data.assign((char*)lpBuffer, nSize);
lpBuffer_buffer_ptr->set_data(out_lpBuffer_data);
lpBuffer_buffer_ptr->set_size(nSize);
lpBuffer_buffer_ptr->set_type(malproxy::BufferType::BufferType_UserAllocated);
std::unique_ptr<malproxy::DataRelocations> lpBuffer_relocations = std::make_unique<malproxy::DataRelocations>();
lpBuffer_relocations->set_base_address((unsigned long long)(ULONG_PTR)lpBuffer);

lpBuffer_buffer_ptr->set_allocated_relocations(lpBuffer_relocations.release());
out_lpBuffer->set_allocated_buffer_val(lpBuffer_buffer_ptr.release());

malproxy::Argument* out_lpNumberOfBytesRead = result.add_out_arguments();
out_lpNumberOfBytesRead->set_uint64_val(*lpNumberOfBytesRead);

return result;
}

malproxy::CallFuncResponse RtlAdjustPrivilege_stub(const malproxy::CallFuncRequest& request, FARPROC real_func)
{
printf("Running function %s ! %s\n", request.dll_name().c_str(), request.function_name().c_str());
DWORD Privilege = (DWORD)request.in_arguments(0).uint32_val();
BOOL Enable = (BOOL)request.in_arguments(1).bool_val();
BOOL CurrentThread = (BOOL)request.in_arguments(2).bool_val();
BOOL Enabled_val = { 0 }; BOOL* Enabled = &Enabled_val;
DWORD raw_retval =  ((DWORD(*)(DWORD,BOOL,BOOL,BOOL*))real_func)(Privilege,Enable,CurrentThread,Enabled);
malproxy::CallFuncResponse result;
malproxy::Argument retval_value; malproxy::Argument* retval = &retval_value;
retval->set_uint32_val((DWORD)raw_retval);
std::unique_ptr<malproxy::Argument> retval_allocated_ptr = std::make_unique<malproxy::Argument>(retval_value);
result.set_allocated_return_value(retval_allocated_ptr.release());
malproxy::Argument* out_Enabled = result.add_out_arguments();
out_Enabled->set_bool_val(*Enabled);

return result;
}

std::map<std::string, std::map<std::string, std::function<malproxy::CallFuncResponse(const malproxy::CallFuncRequest&, FARPROC)>>> hooks = {
{
"kernel32.dll",
{
{ "CreateFileW", CreateFileW_stub },
{ "OutputDebugStringW", OutputDebugStringW_stub },
{ "OutputDebugStringA", OutputDebugStringA_stub },
{ "GetLastError", GetLastError_stub },
{ "OpenProcess", OpenProcess_stub },
{ "GetProcessId", GetProcessId_stub },
{ "ReadProcessMemory", ReadProcessMemory_stub },
}
},
{
"ntdll.dll",
{
{ "NtQuerySystemInformation", NtQuerySystemInformation_stub },
{ "NtQueryInformationProcess", NtQueryInformationProcess_stub },
{ "RtlAdjustPrivilege", RtlAdjustPrivilege_stub },
}
},
{
"advapi32.dll",
{
{ "OpenProcessToken", OpenProcessToken_stub },
}
},
};
