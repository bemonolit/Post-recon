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

//get cpu architecture
int Core::SystemArchitecture(void)
{
	SYSTEM_INFO si;

	GetNativeSystemInfo(&si);

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
int Core::SystemOsVersion(void)
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
