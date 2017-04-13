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

#include "prCommon.h"
#include "prCore.h"
#include <wbemidl.h>
#include <VersionHelpers.h>
#include <security.h>
#include "prHash.h"

#include <stdio.h>

//static IWbemLocator *_locator = 0;
//static IWbemServices *_services = 0;
static CLSID CLSID_WbemLocator2 = { 0x4590F811, 0x1D3A, 0x11D0,{ 0x89, 0x1F, 0, 0xAA, 0, 0x4B, 0x2E, 0x24 } };
//static bool _wminInitialized = false;


// .:: WMI ::.

//initialize wmi
static bool wmiInitialize(void)
{
	HRESULT result = S_FALSE;

	result = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(result)) {
		return false;
	}

	result = CoInitializeSecurity(
		NULL, -1, NULL, NULL,
		RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE,
		NULL, EOAC_NONE, NULL);

	if (FAILED(result)) {
		return false;
	}

	return true;
}

//execute wmi query
static void* wmiExecQuery(IWbemServices *services, wchar_t *query, bool forwardOnly)
{
	if (services == NULL || query == NULL || SysStringLen(query) == 0) return NULL;

	HRESULT result = S_FALSE;
	IEnumWbemClassObject *pEnumerator = NULL;
	wchar_t *language;

	if ((language = SysAllocString(L"WQL")) == NULL) {
		return NULL;
	}

	result = services->ExecQuery(
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

//retrieve unisgned short from array
static unsigned short wmiGetUShortFromArrayField(IEnumWbemClassObject *enumerator, const wchar_t *fieldname)
{
	if (enumerator == NULL || fieldname == NULL || wcslen(fieldname) == 0) return 0;

	IWbemClassObject *pclsObj = NULL;
	unsigned long uReturn = 0;
	HRESULT result = S_FALSE;
	HRESULT hres = WBEM_S_NO_ERROR;
	int val = 0;
	VARIANT v;
	long lLower = 0;
	long lUpper = 0;
	long i = 0;
	SAFEARRAY *pSafeArray;

	hres = enumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
	if (FAILED(hres) || uReturn == 0) {
		return 0;
	}

	result = pclsObj->Get(fieldname, 0, &v, 0, 0);
	if (FAILED(result)) {
		pclsObj->Release();
		return 0;
	}

	if ((v.vt & VT_ARRAY))
	{
		pSafeArray = v.parray;
		SafeArrayGetLBound(pSafeArray, 1, &lLower);
		SafeArrayGetUBound(pSafeArray, 1, &lUpper);

		result = SafeArrayGetElement(pSafeArray, &i, &val);
		if (FAILED(result)) {
			SafeArrayDestroy(pSafeArray);
			pclsObj->Release();
			return 0;
		}
	}

	SafeArrayDestroy(pSafeArray);
	pclsObj->Release();

	return val;
}

//retrieve string field value
static unsigned int wmiGetStringField(IEnumWbemClassObject *enumerator, char **buf, const wchar_t *fieldname)
{
	if (enumerator == NULL || fieldname == NULL || wcslen(fieldname) == 0) return 0;

	IWbemClassObject *pclsObj = NULL;
	unsigned long uReturn = 0;
	HRESULT result = S_FALSE;
	HRESULT hres = WBEM_S_NO_ERROR;
	unsigned int size = 0;
	unsigned int totalSize = 0;
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
				return 0;
			}

			if (Common::CopyString(*buf, totalSize, tmp) != 0) {
				Common::hFree(*buf);
				VariantClear(&v);
				pclsObj->Release();
				return 0;
			}

		}
		else {
			totalSize += strlen(*buf) + size + 2;

			if ((*buf = (char*)Common::hReAlloc(*buf, totalSize)) == NULL) {
				Common::hFree(*buf);
				VariantClear(&v);
				pclsObj->Release();
				return 0;
			}

			if (Common::ConcatString(*buf, totalSize, ",") == S_FALSE) {
				Common::hFree(*buf);
				VariantClear(&v);
				pclsObj->Release();
				return 0;
			}

			if (Common::ConcatString(*buf, totalSize, tmp) == S_FALSE) {
				Common::hFree(*buf);
				VariantClear(&v);
				pclsObj->Release();
				return 0;
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
static void* wmiConnect(IWbemLocator *locator, wchar_t *resource)
{
	if (locator == NULL || resource == NULL || SysStringLen(resource) == 0) return NULL;

	HRESULT result = S_FALSE;
	IWbemServices *services = NULL;

	result = locator->ConnectServer(
		resource, NULL,
		NULL, NULL,
		0, NULL,
		NULL, &services
	);

	if (FAILED(result)) {
		return NULL;
	}

	result = CoSetProxyBlanket(
		(IUnknown *)services,
		RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE,
		NULL, RPC_C_AUTHN_LEVEL_CALL,
		RPC_C_IMP_LEVEL_IMPERSONATE, NULL,
		EOAC_NONE
	);

	if (FAILED(result)) {
		services->Release();
		return NULL;
	}

	return services;
}

///////////////////////////////////////////////////////////////////////////////////////////////////

//check windows version
static bool IsWindowsVersion(unsigned short wMajorVersion, unsigned short wMinorVersion, unsigned short wServicePackMajor)
{
	if (wMajorVersion < 0 || wMinorVersion < 0 || wServicePackMajor < 0) return false;

	unsigned long long dwlConditionMask = 0;
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
static unsigned int getValue(IWbemServices *services, char **buf, const wchar_t *queryStr, const wchar_t *fieldname)
{
	if (queryStr == NULL || fieldname == NULL) return 0;

	unsigned int size = 0;
	IEnumWbemClassObject *enumerator = NULL;
	wchar_t *query;

	if ((query = SysAllocString(queryStr)) == NULL) {
		return 0;
	}

	if ((enumerator = (IEnumWbemClassObject *)wmiExecQuery(services, query, true)) == NULL) {
		Common::SysFreeStr(query);
		return 0;
	}

	size = wmiGetStringField(enumerator, buf, fieldname);

	enumerator->Release();
	Common::SysFreeStr(query);

	return size;
}

static unsigned short getValue(IWbemServices *services, const wchar_t *queryStr, const wchar_t *fieldname)
{
	if (queryStr == NULL || fieldname == NULL) return 2;

	IEnumWbemClassObject *enumerator = NULL;
	wchar_t *query;
	unsigned short val = 0;

	if ((query = SysAllocString(queryStr)) == NULL) {
		return 2;
	}

	if ((enumerator = (IEnumWbemClassObject *)wmiExecQuery(services, query, true)) == NULL) {
		Common::SysFreeStr(query);
		return 2;
	}

	val = wmiGetUShortFromArrayField(enumerator, fieldname);

	enumerator->Release();
	Common::SysFreeStr(query);

	return val;
}

//retrieve motherboard details
static unsigned long getValue(IWbemServices *services, char **buf, const wchar_t *queryStr, const wchar_t *fieldname1, const wchar_t *fieldname2, const wchar_t *fieldname3)
{
	if (queryStr == NULL || fieldname1 == NULL || fieldname2 == NULL || fieldname3 == NULL) return 0;

	IEnumWbemClassObject *enumerator = NULL;
	unsigned long size = 0;
	unsigned long tmp = 0;
	wchar_t *query;
	char *manufacturer = 0;
	char *product = 0;
	char *serial = 0;

	if ((query = SysAllocString(queryStr)) == NULL) {
		return 0;
	}

	if ((enumerator = (IEnumWbemClassObject *)wmiExecQuery(services, query, false)) == NULL) {
		Common::SysFreeStr(query);
		return 0;
	}

	if ((tmp = wmiGetStringField(enumerator, &manufacturer, fieldname1)) == 0) {
		Common::hFree(manufacturer);
		enumerator->Release();
		Common::SysFreeStr(query);
		return 0;
	}
	size += tmp;
	if (enumerator->Reset() != WBEM_S_NO_ERROR) {
		Common::hFree(manufacturer);
		enumerator->Release();
		Common::SysFreeStr(query);
		return 0;
	}

	if ((tmp = wmiGetStringField(enumerator, &product, fieldname2)) == 0) {
		Common::hFree(manufacturer);
		Common::hFree(product);
		enumerator->Release();
		Common::SysFreeStr(query);
		return 0;
	}
	size += tmp;
	if (enumerator->Reset() != WBEM_S_NO_ERROR) {
		Common::hFree(manufacturer);
		Common::hFree(product);
		enumerator->Release();
		Common::SysFreeStr(query);
		return 0;
	}

	if ((tmp = wmiGetStringField(enumerator, &serial, fieldname3)) == 0) {
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		enumerator->Release();
		Common::SysFreeStr(query);
		return 0;
	}
	size += tmp + 3;	//2 spaces and a null character

	if ((*buf = (char*)Common::hAlloc(size * sizeof(char))) == NULL) {
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		enumerator->Release();
		Common::SysFreeStr(query);
		return 0;
	}

	if (Common::ConcatString(*buf, size, manufacturer) == S_FALSE) {
		Common::hFree(*buf);
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		Common::SysFreeStr(query);
		enumerator->Release();
		return 0;
	}

	if (Common::ConcatString(*buf, size, " ") == S_FALSE) {
		Common::hFree(*buf);
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		Common::SysFreeStr(query);
		enumerator->Release();
		return 0;
	}

	if (Common::ConcatString(*buf, size, product) == S_FALSE) {
		Common::hFree(*buf);
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		Common::SysFreeStr(query);
		enumerator->Release();
		return 0;
	}

	if (Common::ConcatString(*buf, size, " ") == S_FALSE) {
		Common::hFree(*buf);
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		Common::SysFreeStr(query);
		enumerator->Release();
		return 0;
	}

	if (Common::ConcatString(*buf, size, serial) == S_FALSE) {
		Common::hFree(*buf);
		Common::hFree(manufacturer);
		Common::hFree(product);
		Common::hFree(serial);
		Common::SysFreeStr(query);
		enumerator->Release();
		return 0;
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

//get current username
static unsigned long getUser(char **buf)
{
	unsigned long size = 0;
	(void)GetUserNameEx(NameSamCompatible, NULL, &size);

	if ((*buf = (char*)Common::hAlloc(size * sizeof(char))) == NULL) {
		return 0;
	}

	if (GetUserNameEx(NameSamCompatible, *buf, &size) == 0) {
		Common::hFree(*buf);
		return 0;
	}

	(*buf)[size] = 0;

	return size;
}

//get current username
static unsigned long getPc(char **buf)
{
	unsigned long size = 0;
	(void)GetComputerNameEx(ComputerNameNetBIOS, NULL, &size);

	if ((*buf = (char*)Common::hAlloc(size * sizeof(char))) == NULL) {
		return 0;
	}

	if (GetComputerNameEx(ComputerNameNetBIOS, *buf, &size) == 0) {
		Common::hFree(*buf);
		return 0;
	}

	(*buf)[size] = 0;

	return size;
}

//get total available ram
static unsigned long getRam(void)
{
	MEMORYSTATUSEX statex;
	statex.dwLength = sizeof(statex);

	if (GlobalMemoryStatusEx(&statex) == 0) {
		return 0;
	}

	return (unsigned long)(statex.ullTotalPhys / (1024.0 * 1024.0));
}

//get first physical address
static unsigned long getFirstMacAddress(char **buf)
{
	unsigned long size = 0;
	unsigned long macSize = 17;
	PIP_ADAPTER_ADDRESSES pAddresses;

	(void)GetAdaptersAddresses(0, 0, 0, 0, &size);

	if (!size) {
		return 0;
	}

	if ((pAddresses = (IP_ADAPTER_ADDRESSES*)Common::hAlloc(size)) == NULL) {
		return 0;
	}

	if (GetAdaptersAddresses(0, 0, 0, pAddresses, &size) != NO_ERROR) {
		Common::hFree(pAddresses);
		return 0;
	}

	while (pAddresses)
	{
		if (pAddresses->PhysicalAddressLength != 6)
			continue;

		if ((*buf = (char*)Common::hAlloc((macSize + 1) * sizeof(char))) == NULL) {
			Common::hFree(pAddresses);
			return 0;
		}

		if (Common::FormatString(*buf, macSize + 1, "%02X-%02X-%02X-%02X-%02X-%02X",
			pAddresses->PhysicalAddress[0], pAddresses->PhysicalAddress[1],
			pAddresses->PhysicalAddress[2], pAddresses->PhysicalAddress[3],
			pAddresses->PhysicalAddress[4], pAddresses->PhysicalAddress[5]) == 0)
		{
			Common::hFree(*buf);
			Common::hFree(pAddresses);
			return 0;
		}

		break;
	}

	Common::hFree(pAddresses);

	return macSize;
}

//initialize core library
HRESULT Core::UniqueID(char **id)
{
	IWbemLocator *_locator = 0;
	IWbemServices *_services = 0;
	HRESULT result = S_FALSE;

	char *cpu = 0;
	char *gpu = 0;
	char *motherBoard = 0;
	char *username = 0;
	char *pcname = 0;
	char *bios = 0;
	char *mac = 0;
	char *output = 0;

	unsigned long tmp = 0;
	unsigned long ram = 0;
	unsigned long totalSize = 0;

	unsigned int architecture = 0;
	unsigned int winOS = 0;
	unsigned int isadmin = 0;
	unsigned int chassisType = 0;

	wchar_t *resource;

	//init wmi
	if (!wmiInitialize()) {
		return S_FALSE;
	}

	//create wmi
	if ((_locator = (IWbemLocator *)wmiCreate()) == NULL) {
		CoUninitialize();
		return S_FALSE;
	}

	// **** ROOT\\SecurityCenter ****

	//if (IsWindowsVistaOrGreater()) {
	//	resource = SysAllocString(L"ROOT\\SecurityCenter2");
	//}
	//else {
	//	resource = SysAllocString(L"ROOT\\SecurityCenter");
	//}

	//if (resource == NULL) {
	//	_locator->Release();
	//	_locator = NULL;
	//	return;
	//}

	////connect to wmi
	//if ((_services = (IWbemServices *)wmiConnect(_locator, resource)) == NULL) {
	//	_locator->Release();
	//	_locator = NULL;
	//	Common::SysFreeStr(resource);
	//	return;
	//}

	//_services->Release();
	//_services = NULL;
	//Common::SysFreeStr(resource);

	// **** ROOT\\cimv2 ****

	if ((resource = SysAllocString(L"ROOT\\cimv2")) == NULL) {
		_locator->Release();
		_locator = NULL;
		CoUninitialize();
		return S_FALSE;
	}

	//connect to wmi
	if ((_services = (IWbemServices *)wmiConnect(_locator, resource)) == NULL) {
		Common::SysFreeStr(resource);
		_locator->Release();
		_locator = NULL;
		CoUninitialize();
		return S_FALSE;
	}

	//get cpu
	if ((tmp = getValue(_services, &cpu, L"SELECT * FROM Win32_Processor", L"Name")) > 0) {
		totalSize += tmp;
	}

	//get architecture
	architecture = Architecture();
	totalSize += Common::NumOfDigits(architecture);

	//get os version(windowns)
	winOS = WinVer();
	totalSize += Common::NumOfDigits(winOS);

	//get gpu
	if ((tmp = getValue(_services, &gpu, L"SELECT Caption FROM Win32_VideoController", L"Caption")) > 0) {
		totalSize += tmp;
	}

	//is admin?
	isadmin = isAdmin() ? 2 : 1;
	totalSize += Common::NumOfDigits(isadmin);

	//get motherBoard
	if ((tmp = getValue(_services, &motherBoard, L"Select * from Win32_BaseBoard", L"Manufacturer", L"Product", L"SerialNumber")) > 0) {
		totalSize += tmp;
	}

	//get chassis type
	chassisType = getValue(_services, L"SELECT ChassisTypes FROM Win32_SystemEnclosure", L"ChassisTypes");
	totalSize += Common::NumOfDigits(chassisType);

	//get username
	if ((tmp = getUser(&username)) > 0) {
		totalSize += tmp;
	}

	//get pcname
	if ((tmp = getPc(&pcname)) > 0) {
		totalSize += tmp;
	}

	//get ram
	ram = getRam();
	totalSize += Common::NumOfDigits(ram);

	//get bios
	if ((tmp = getValue(_services, &bios, L"Select * from Win32_BIOS", L"Caption", L"Manufacturer", L"SerialNumber")) > 0) {
		totalSize += tmp;
	}

	//get first mac address
	if ((tmp = getFirstMacAddress(&mac)) > 0) {
		totalSize += tmp;
	}

	totalSize += 1;

	if (cpu && gpu && motherBoard && username && pcname && bios && mac)
	{

		if ((output = (char*)Common::hAlloc(totalSize * sizeof(char))) != NULL)
		{

			//arch+winver+cpu+gpu+isadmin+motherboard+chassistype+username+pcname+ram+bios+mac
			if (Common::FormatString(output, totalSize, "%u%u%s%s%u%s%u%s%s%lu%s%s",
				architecture, winOS, cpu, gpu, isadmin, motherBoard, chassisType, username, pcname, ram, bios, mac) != -1)
			{

				//calc sha-2 hash
				result = LibHash::sha256((unsigned char *)output, totalSize - 1, id) ? S_OK : S_FALSE;
			}
		}
		Common::hFree(output);
	}

	Common::hFree(cpu);
	Common::hFree(gpu);
	Common::hFree(motherBoard);
	Common::hFree(username);
	Common::hFree(pcname);
	Common::hFree(bios);
	Common::hFree(mac);


	Common::SysFreeStr(resource);
	_services->Release();
	_services = NULL;
	_locator->Release();
	_locator = NULL;
	CoUninitialize();

	return result;
}
