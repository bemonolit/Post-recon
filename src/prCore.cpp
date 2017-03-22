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
static void* wmiExecQuery(wchar_t *query)
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
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
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
static int wmiGetStringField(IEnumWbemClassObject *classObject, char **buf, const wchar_t *fieldname)
{
	if (classObject == NULL || fieldname == NULL || wcslen(fieldname) == 0) return -1;

	IWbemClassObject *pclsObj = NULL;
	ULONG uReturn = 0;
	HRESULT result = S_FALSE;
	HRESULT hres = WBEM_S_NO_ERROR;
	int size = -1;

	while (classObject && hres == WBEM_S_NO_ERROR)
	{
		hres = classObject->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (FAILED(hres) || uReturn == 0) {
			break;
		}

		VARIANT v;
		result = pclsObj->Get(fieldname, 0, &v, 0, 0);
		if (FAILED(result) /*|| V_VT(&vtProp) != VT_BSTR*/) {
			pclsObj->Release();
			continue;
		}

		size = wcslen(v.bstrVal);

		//xwconcat(buf, buflen, vtProp.bstrVal);
		//xwconcat(buf, buflen, L",");

		VariantClear(&v);
		pclsObj->Release();
	}

	return size;
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

//check if we are running in a windows server
static bool IsWindowsServer(void)
{
	OSVERSIONINFOEX osvi = { sizeof(osvi), 0, 0, 0, 0,{ 0 }, 0, 0, 0, VER_NT_WORKSTATION };
	DWORDLONG        const dwlConditionMask = VerSetConditionMask(0, VER_PRODUCT_TYPE, VER_EQUAL);

	return !VerifyVersionInfo(&osvi, VER_PRODUCT_TYPE, dwlConditionMask);
}

//check windows version
static bool IsWindowsVersion(unsigned short wMajorVersion, unsigned short wMinorVersion, unsigned short wServicePackMajor, int comparisonType)
{
	if (wMajorVersion < 0 || wMinorVersion < 0 || wServicePackMajor < 0 || comparisonType < 0) return false;

	OSVERSIONINFOEX osvi = { sizeof(osvi), 0, 0, 0, 0,{ 0 }, 0, 0 };
	DWORDLONG        const dwlConditionMask = VerSetConditionMask(
		VerSetConditionMask(VerSetConditionMask(
			0, VER_MAJORVERSION, comparisonType),
			VER_MINORVERSION, comparisonType),
		VER_SERVICEPACKMAJOR, comparisonType);

	osvi.dwMajorVersion = wMajorVersion;
	osvi.dwMinorVersion = wMinorVersion;
	osvi.wServicePackMajor = wServicePackMajor;

	return VerifyVersionInfo(&osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask) != false;
}

//is vista or greater??
static bool IsWindowsVistaOrGreater(void)
{
	return IsWindowsVersion(HIBYTE(WIN_VISTA), LOBYTE(WIN_VISTA), 0, VER_GREATER_EQUAL);
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
static int OsVersion(void)
{
	if (!IsWindowsServer()) {
		if (IsWindowsVersion(HIBYTE(WIN_XP), LOBYTE(WIN_XP), 0, VER_EQUAL)) return Windows_XP;
		else if (IsWindowsVersion(HIBYTE(WIN_XP64PRO), LOBYTE(WIN_XP64PRO), 0, VER_EQUAL)) return Windows_XP64PRO;
		else if (IsWindowsVersion(HIBYTE(WIN_XP), LOBYTE(WIN_XP), 1, VER_EQUAL)) return Windows_XPSP1;
		else if (IsWindowsVersion(HIBYTE(WIN_XP), LOBYTE(WIN_XP), 2, VER_EQUAL)) return Windows_XPSP2;
		else if (IsWindowsVersion(HIBYTE(WIN_XP), LOBYTE(WIN_XP), 3, VER_EQUAL)) return Windows_XPSP3;
		else if (IsWindowsVersion(HIBYTE(WIN_VISTA), LOBYTE(WIN_VISTA), 0, VER_EQUAL)) return Windows_VISTA;
		else if (IsWindowsVersion(HIBYTE(WIN_VISTA), LOBYTE(WIN_VISTA), 1, VER_EQUAL)) return Windows_VISTASP1;
		else if (IsWindowsVersion(HIBYTE(WIN_VISTA), LOBYTE(WIN_VISTA), 2, VER_EQUAL)) return Windows_VISTASP2;
		else if (IsWindowsVersion(HIBYTE(WIN_WIN7), LOBYTE(WIN_WIN7), 0, VER_EQUAL)) return Windows_7;
		else if (IsWindowsVersion(HIBYTE(WIN_WIN7), LOBYTE(WIN_WIN7), 1, VER_EQUAL)) return Windows_7SP1;
		else if (IsWindowsVersion(HIBYTE(WIN_WIN8), LOBYTE(WIN_WIN8), 0, VER_EQUAL)) return Windows_8;
		else if (IsWindowsVersion(HIBYTE(WIN_WIN81), LOBYTE(WIN_WIN81), 0, VER_EQUAL)) return Windows_81;
		else return Windows_Unknown;
	}
	else {
		if (IsWindowsVersion(HIBYTE(WIN_S03), LOBYTE(WIN_S03), 0, VER_EQUAL)) return Windows_S2003;
		else if (IsWindowsVersion(HIBYTE(WIN_S08), LOBYTE(WIN_S08), 0, VER_EQUAL)) return Windows_S2008;
		else if (IsWindowsVersion(HIBYTE(WIN_S08R2), LOBYTE(WIN_S08R2), 0, VER_EQUAL)) return Windows_S2008R2;
		else if (IsWindowsVersion(HIBYTE(WIN_S12), LOBYTE(WIN_S12), 0, VER_EQUAL)) return Windows_S2012;
		else if (IsWindowsVersion(HIBYTE(WIN_S12R2), LOBYTE(WIN_S12R2), 0, VER_EQUAL)) return Windows_S2012R2;
		else return Windows_Unknown;
	}
}

//get CPU details
static int CPU(char **buf)
{
	if (_locator == NULL || _services == NULL) return -1;

	int size = 0;
	IEnumWbemClassObject *pEnumerator = NULL;
	wchar_t *query;

	if ((query = SysAllocString(L"SELECT Name FROM Win32_Processor")) == NULL) {
		return -1;
	}

	if ((pEnumerator = (IEnumWbemClassObject *)wmiExecQuery(query)) == NULL) {
		Common::SysFreeStr(query);
		//Common::CopyString(buf, buflen, "invalid");
		return -1;
	}

	size = wmiGetStringField(pEnumerator, buf, L"Name");

	pEnumerator->Release();
	Common::SysFreeStr(query);

	return size;
}

//initialize core library
void Core::init(void)
{
	char *cpu = 0;
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

	//TESTING
	if (CPU(&cpu) != -1) {
		printf("%s\n", cpu);
	}

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
