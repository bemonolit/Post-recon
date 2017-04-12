/*
This file is part of Post-recon
Copyright (C) 2017 @maldevel
https://github.com/maldevel/Post-recon

Post-recon - post-exploitation reconnaissance toolkit.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

For more see the file 'LICENSE' for copying permission.
*/

#include "prCore.h"
#include "prCommon.h"
#include <wbemidl.h>
#include <VersionHelpers.h>
#include <stdio.h>

static IWbemLocator *_locator = 0;
static IWbemServices *_services = 0;
static CLSID CLSID_WbemLocator2 = { 0x4590F811, 0x1D3A, 0x11D0,{ 0x89, 0x1F, 0, 0xAA, 0, 0x4B, 0x2E, 0x24 } };
static bool _wminInitialized = false;


// .:: WMI ::.

//initialize wmi
static bool wmiInitialize(void)
{
	HRESULT result = S_FALSE;
	bool _init_success = false, _initsec_success = false;

	result = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(result)) {
		return false;
	}

	_init_success = (result == S_OK || result == S_FALSE || result == RPC_E_CHANGED_MODE);

	result = CoInitializeSecurity(
		NULL, -1, NULL, NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL, EOAC_NONE, NULL
	);

	if (FAILED(result)) {
		return false;
	}

	_initsec_success = (result == S_OK || result == RPC_E_TOO_LATE);
	_wminInitialized = true;

	return (_init_success && _initsec_success);
}

//execute wmi query
static void* wmiExecQuery(wchar_t *query, bool forwardOnly)
{
	if (_services == NULL || query == NULL || SysStringLen(query) == 0) return NULL;

	HRESULT result = S_FALSE;
	IEnumWbemClassObject *pEnumerator = NULL;
	wchar_t *language;

	if ((language = SysAllocString(L"WQL")) == NULL) {
		return NULL;
	}

	result = _services->ExecQuery(
		language,
		query,
		forwardOnly ? (WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY) : WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL,
		&pEnumerator);

	Common::SysFreeStr(language);

	if (FAILED(result)) {
		return NULL;
	}

	if (result != WBEM_S_NO_ERROR || pEnumerator == NULL) {
		return NULL;
	}

	return pEnumerator;
}

//retrieve string field value
static int wmiGetStringField(IEnumWbemClassObject *enumerator, char **buf, const wchar_t *fieldname)
{
	if (enumerator == NULL || fieldname == NULL || wcslen(fieldname) == 0) return -1;

	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;
	HRESULT result = S_FALSE;
	HRESULT hres = WBEM_S_NO_ERROR;
	int size = -1;
	int totalSize = 0;
	char *tmp = 0;
	VARIANT v;

	while (enumerator && hres == WBEM_S_NO_ERROR)
	{
		hres = enumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

		if (FAILED(hres) || uReturn == 0) {
			break;
		}

		result = pclsObj->Get(fieldname, 0, &v, 0, 0);
		if (FAILED(result) /*|| V_VT(&vtProp) != VT_BSTR*/) {
			pclsObj->Release();
			continue;
		}

		size = wcslen(v.bstrVal);
		tmp = Common::WcharToChar(v.bstrVal, size);

		if (*buf == NULL) {
			totalSize = size + 1;

			if ((*buf = (char*)Common::hAlloc(totalSize * sizeof(char))) == NULL) {
				VariantClear(&v);
				pclsObj->Release();
				return -1;
			}

			if (Common::CopyString(*buf, totalSize, tmp) != 0) {
				Common::hFree(*buf);
				VariantClear(&v);
				pclsObj->Release();
				return -1;
			}

		}
		else {
			totalSize += strlen(*buf) + size + 2;

			if ((*buf = (char*)Common::hReAlloc(*buf, totalSize)) == NULL) {
				Common::hFree(*buf);
				VariantClear(&v);
				pclsObj->Release();
				return -1;
			}

			if (Common::ConcatString(*buf, totalSize, ",") == S_FALSE) {
				Common::hFree(*buf);
				VariantClear(&v);
				pclsObj->Release();
				return -1;
			}

			if (Common::ConcatString(*buf, totalSize, tmp) == S_FALSE) {
				Common::hFree(*buf);
				VariantClear(&v);
				pclsObj->Release();
				return -1;
			}
		}

		VariantClear(&v);
		pclsObj->Release();
	}

	return totalSize - 1;
}

//create wmi instance/interface
static void* wmiCreate(void)
{
	HRESULT result = S_FALSE;
	IWbemLocator *locator = NULL;

	result = CoCreateInstance(
		CLSID_WbemLocator2, NULL,
		CLSCTX_INPROC_SERVER | CLSCTX_NO_FAILURE_LOG | CLSCTX_NO_CODE_DOWNLOAD,
		IID_IWbemLocator, (LPVOID *)&locator);

	if (FAILED(result)) {
		return NULL;
	}

	if (result != S_OK || locator == NULL) {
		return NULL;
	}

	return locator;
}


//connect to wmi services
static void* wmiConnect(wchar_t *resource)
{
	if (_locator == NULL || resource == NULL || SysStringLen(resource) == 0) return NULL;

	HRESULT result = S_FALSE;
	IWbemServices *services = NULL;
	bool _connect_success = false, _setproxy_success = false;

	result = _locator->ConnectServer(
		resource,
		NULL,
		NULL,
		NULL,
		0,
		NULL,
		NULL,
		&services
	);

	if (FAILED(result)) {
		return NULL;
	}

	_connect_success = (result == WBEM_S_NO_ERROR);

	result = CoSetProxyBlanket(
		(IUnknown *)services,
		RPC_C_AUTHN_WINNT,
		RPC_C_AUTHZ_NONE,
		NULL,
		RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL,
		EOAC_NONE
	);

	if (FAILED(result)) {
		services->Release();
		return NULL;
	}

	_setproxy_success = (result == S_OK);

	if (!_connect_success || !_setproxy_success) {
		return NULL;
	}

	return services;
}

///////////////////////////////////////////////////////////////////////////////////////////////////

//check windows version
static bool IsWindowsVersion(unsigned short wMajorVersion, unsigned short wMinorVersion, unsigned short wServicePackMajor)
{
	if (wMajorVersion < 0 || wMinorVersion < 0 || wServicePackMajor < 0) return false;

	DWORDLONG dwlConditionMask = 0;
	OSVERSIONINFOEX osvi;

	VER_SET_CONDITION(dwlConditionMask, VER_MAJORVERSION, VER_GREATER_EQUAL);
	VER_SET_CONDITION(dwlConditionMask, VER_MINORVERSION, VER_GREATER_EQUAL);
	VER_SET_CONDITION(dwlConditionMask, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

	Common::hZero(&osvi, sizeof(OSVERSIONINFOEX));
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;

	return VerifyVersionInfo(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != false;
}

//get cpu architecture
static int Architecture(void)
{
	SYSTEM_INFO si;

	GetNativeSystemInfo(&si);

	if (si.wProcessorArchitecture == NULL) {
		return Arch_Unknown;
	}

	switch (si.wProcessorArchitecture) {
	case PROCESSOR_ARCHITECTURE_INTEL:
		return Arch_x86;
	case PROCESSOR_ARCHITECTURE_AMD64:
		return Arch_x64;
	case PROCESSOR_ARCHITECTURE_IA64:
		return Arch_Itanium;
	default:
		return Arch_Unknown;
	}
}

//get windows version
static int WinVer(void)
{
	if (!IsWindowsServer())
	{
		if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_WIN10), LOBYTE(_WIN32_WINNT_WIN10), 0))
			return Windows_10;
		else if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_WINBLUE), LOBYTE(_WIN32_WINNT_WINBLUE), 0))
			return Windows_81;
		else if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_WIN8), LOBYTE(_WIN32_WINNT_WIN8), 0))
			return Windows_8;
		else if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_WIN7), LOBYTE(_WIN32_WINNT_WIN7), 1))
			return Windows_7SP1;
		else if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_WIN7), LOBYTE(_WIN32_WINNT_WIN7), 0))
			return Windows_7;
		else if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 2))
			return Windows_VISTASP2;
		else if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 1))
			return Windows_VISTASP1;
		else if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_VISTA), LOBYTE(_WIN32_WINNT_VISTA), 0))
			return Windows_VISTA;
		else if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 3))
			return Windows_XPSP3;
		else if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 2))
			return Windows_XPSP2;
		else if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 1))
			return Windows_XPSP1;
		else if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_WS03), LOBYTE(_WIN32_WINNT_WS03), 0))
			return Windows_XP64PRO;
		else if (IsWindowsVersion(HIBYTE(_WIN32_WINNT_WINXP), LOBYTE(_WIN32_WINNT_WINXP), 0))
			return Windows_XP;
		else return Windows_Unknown;
	}
	else
	{
		if (IsWindowsVersion(HIBYTE(WIN_S03), LOBYTE(WIN_S03), 0))
			return Windows_S2003;
		else if (IsWindowsVersion(HIBYTE(WIN_S08), LOBYTE(WIN_S08), 0))
			return Windows_S2008;
		else if (IsWindowsVersion(HIBYTE(WIN_S08R2), LOBYTE(WIN_S08R2), 0))
			return Windows_S2008R2;
		else if (IsWindowsVersion(HIBYTE(WIN_S12), LOBYTE(WIN_S12), 0))
			return Windows_S2012;
		else if (IsWindowsVersion(HIBYTE(WIN_S12R2), LOBYTE(WIN_S12R2), 0))
			return Windows_S2012R2;
		else if (IsWindowsVersion(HIBYTE(WIN_S16), LOBYTE(WIN_S16), 0))
			return Windows_S2016;
		else return Windows_Unknown;
	}
}

//retrieve information
static int getValue(char **buf, const wchar_t *queryStr, const wchar_t *fieldname)
{
	if (_locator == NULL || _services == NULL) return -1;

	int size = 0;
	IEnumWbemClassObject *pEnumerator = NULL;
	wchar_t *query;

	if ((query = SysAllocString(queryStr)) == NULL) {
		return -1;
	}

	if ((pEnumerator = (IEnumWbemClassObject *)wmiExecQuery(query, true)) == NULL) {
		Common::SysFreeStr(query);
		return -1;
	}

	size = wmiGetStringField(pEnumerator, buf, fieldname);

	pEnumerator->Release();
	Common::SysFreeStr(query);

	return size;
}

//retrieve motherboard details
static int MotherBoard(char **buf)
{
	if (_locator == NULL || _services == NULL) return -1;

	IEnumWbemClassObject *enumerator = NULL;
	int size = 0;
	int tmp = 0;
	wchar_t *query;
	char *manufacturer = 0;
	char *product = 0;
	char *serial = 0;

	if ((query = SysAllocString(L"Select * from Win32_BaseBoard")) == NULL) {
		return -1;
	}

	if ((enumerator = (IEnumWbemClassObject *)wmiExecQuery(query, false)) == NULL) {
		Common::SysFreeStr(query);
		return -1;
	}

	if ((tmp = wmiGetStringField(enumerator, &manufacturer, L"Manufacturer")) == -1) {
		Common::hFree(manufacturer);
		enumerator->Release();
		Common::SysFreeStr(query);
		return -1;
	}
	size += tmp;
	if (enumerator->Reset() != WBEM_S_NO_ERROR) {
		Common::hFree(manufacturer);
		enumerator->Release();
		Common::SysFreeStr(query);
		return -1;
	}

	if ((tmp = wmiGetStringField(enumerator, &product, L"Product")) == -1) {
		Common::hFree(manufacturer);
		Common::hFree(product);
		enumerator->Release();
		Common::SysFreeStr(query);
		return -1;
	}
	size += tmp;
	if (enumerator->Reset() != WBEM_S_NO_ERROR) {
		Common::hFree(manufacturer);
		Common::hFree(product);
		enumerator->Release();
		Common::SysFreeStr(query);
		return -1;
	}

	if ((tmp = wmiGetStringField(enumerator, &serial, L"SerialNumber")) == -1) {
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		enumerator->Release();
		Common::SysFreeStr(query);
	}
	size += tmp + 3;	//2 spaces and a null character

	if ((*buf = (char*)Common::hAlloc(size * sizeof(char))) == NULL) {
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		enumerator->Release();
		Common::SysFreeStr(query);
		return -1;
	}

	if (Common::ConcatString(*buf, size, manufacturer) == S_FALSE) {
		Common::hFree(*buf);
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		Common::SysFreeStr(query);
		enumerator->Release();
		return -1;
	}

	if (Common::ConcatString(*buf, size, " ") == S_FALSE) {
		Common::hFree(*buf);
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		Common::SysFreeStr(query);
		enumerator->Release();
		return -1;
	}

	if (Common::ConcatString(*buf, size, product) == S_FALSE) {
		Common::hFree(*buf);
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		Common::SysFreeStr(query);
		enumerator->Release();
		return -1;
	}

	if (Common::ConcatString(*buf, size, " ") == S_FALSE) {
		Common::hFree(*buf);
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		Common::SysFreeStr(query);
		enumerator->Release();
		return -1;
	}

	if (Common::ConcatString(*buf, size, serial) == S_FALSE) {
		Common::hFree(*buf);
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		Common::SysFreeStr(query);
		enumerator->Release();
		return -1;
	}

	Common::hFree(manufacturer);
	Common::hFree(product);
	Common::hFree(serial);
	enumerator->Release();
	Common::SysFreeStr(query);

	return size - 1;
}

//check if user is administrator
static bool isAdmin(void) {

	BOOL isadmin = FALSE;
	SID_IDENTIFIER_AUTHORITY NtAuthority = { SECURITY_NT_AUTHORITY };
	PSID AdministratorsGroup;

	isadmin = AllocateAndInitializeSid(
		&NtAuthority, 2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup);

	if (isadmin) {
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &isadmin))
			isadmin = FALSE;
		FreeSid(AdministratorsGroup);
	}

	return isadmin == FALSE ? false : true;
}

//initialize core library
void Core::init(void)
{
	char *cpu = 0;
	char *gpu = 0;
	char *motherBoard = 0;

	int cpuSize = 0;
	int gpuSize = 0;
	int motherBoardSize = 0;

	wchar_t *resource;

	//init wmi
	if (!wmiInitialize()) {
		return;
	}

	//create wmi
	if ((_locator = (IWbemLocator *)wmiCreate()) == NULL) {
		return;
	}

	if (IsWindowsVistaOrGreater()) {
		resource = SysAllocString(L"ROOT\\SecurityCenter2");
	}
	else {
		resource = SysAllocString(L"ROOT\\SecurityCenter");
	}

	if (resource == NULL) {
		_locator->Release();
		_locator = NULL;
		return;
	}

	//connect to wmi
	if ((_services = (IWbemServices *)wmiConnect(resource)) == NULL) {
		_locator->Release();
		_locator = NULL;
		Common::SysFreeStr(resource);
		return;
	}

	_services->Release();
	Common::SysFreeStr(resource);

	if ((resource = SysAllocString(L"ROOT\\cimv2")) == NULL) {
		_locator->Release();
		_locator = NULL;
		return;
	}

	if ((_services = (IWbemServices *)wmiConnect(resource)) == NULL) {
		_locator->Release();
		_locator = NULL;
		Common::SysFreeStr(resource);
	}

	///////////////////////////////////////
	//TESTING
	printf("TESTING\n");

	//get cpu
	if ((cpuSize = getValue(&cpu, L"SELECT * FROM Win32_Processor", L"Name")) != -1) {
		Common::PrintDebug("CPU", cpuSize, "%s", cpu);
		printf("CPU: %s\n", cpu);
		Common::hFree(cpu);
	}

	//get architecture
	switch (Architecture()) {
	case  Arch_x86:
		Common::PrintDebug("Architecture", 3, "%s", "x86"); printf("Architecture: x86\n"); break;
	case Arch_x64:
		Common::PrintDebug("Architecture", 3, "%s", "x64"); printf("Architecture: x64\n"); break;
	default:
		Common::PrintDebug("Architecture", 7, "%s", "unknown"); printf("Architecture: unknown\n"); break;
	}

	//get os version(windowns)
	switch (WinVer()) {
	case  Windows_7:
		Common::PrintDebug("Windows", 9, "%s", "Windows 7"); printf("Windows: Windows 7\n"); break;
	case Windows_7SP1:
		Common::PrintDebug("Windows", 13, "%s", "Windows 7 SP1"); printf("Windows 7 SP1\n"); break;
	case Windows_8:
		Common::PrintDebug("Windows", 10, "%s", "Windows 8"); printf("Windows: Windows 8\n"); break;
	case Windows_81:
		Common::PrintDebug("Windows", 11, "%s", "Windows 8.1"); printf("Windows: Windows 8.1\n"); break;
	case Windows_10:
		Common::PrintDebug("Windows", 10, "%s", "Windows 10"); printf("Windows: Windows 10\n"); break;
	default:
		Common::PrintDebug("Windows", 7, "%s", "unknown"); printf("Windows: unknown\n"); break;
	}

	//get cpu
	if ((gpuSize = getValue(&gpu, L"SELECT Caption FROM Win32_VideoController", L"Caption")) != -1) {
		Common::PrintDebug("GPU", gpuSize, "%s", gpu);
		printf("GPU: %s\n", gpu);
		Common::hFree(gpu);
	}

	//is admin?
	printf("Is Admin? %s\n", (isAdmin() ? "yes" : "no"));
	Common::PrintDebug("Is Admin?", 3, "%s", (isAdmin() ? "yes" : "no"));

	//get motherBoard
	if ((motherBoardSize = MotherBoard(&motherBoard)) != -1) {
		Common::PrintDebug("Motherboard", motherBoardSize, "%s", motherBoard);
		printf("Motherboard: %s\n", motherBoard);
		Common::hFree(motherBoard);
	}

	//END of TESTING
	///////////////////////////////////////

	Common::SysFreeStr(resource);
}

//un-initialize core library stuff initialized with init function
void Core::uninit(void)
{
	if (_locator != NULL) {
		_locator->Release();
		_locator = NULL;
	}

	if (_services != NULL) {
		_services->Release();
	}

	if (_wminInitialized == true) {
		CoUninitialize();
		_wminInitialized = false;
	}
}

//generate computer unique id
HRESULT Core::UniqueID(char *id)
{
	return S_OK;
}
