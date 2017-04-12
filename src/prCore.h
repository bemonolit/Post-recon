#pragma once

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


//#include <winsock2.h>
//#include <windows.h>
//#include <iphlpapi.h>

#define SECURITY_WIN32

#define _WIN32_WINNT_WIN10		0x0A00

#define WIN_S03			0x0502
#define WIN_S08			0x0600
#define WIN_S08R2		0x0601
#define WIN_S12			0x0602
#define WIN_S12R2		0x0603
#define WIN_S16			0x0604

enum Architecture
{
	Arch_x86,
	Arch_Itanium,
	Arch_x64,
	Arch_Unknown
};

enum OSVersion
{
	Windows_Unknown,
	Windows_XP,
	Windows_XP64PRO,
	Windows_XPSP1,
	Windows_XPSP2,
	Windows_XPSP3,
	Windows_S2003,
	Windows_VISTA,
	Windows_VISTASP1,
	Windows_VISTASP2,
	Windows_S2008,
	Windows_S2008R2,
	Windows_7,
	Windows_7SP1,
	Windows_S2012,
	Windows_8,
	Windows_S2012R2,
	Windows_81,
	Windows_10,
	Windows_S2016
};

enum ChassisType
{
	ChassisType_Other = 1,
	ChassisType_Unknown = 2,
	ChassisType_Desktop = 3,
	ChassisType_LowProfileDesktop = 4,
	ChassisType_PizzaBox = 5,
	ChassisType_MiniTower = 6,
	ChassisType_Tower = 7,
	ChassisType_Portable = 8,
	ChassisType_Laptop = 9,
	ChassisType_Notebook = 10,
	ChassisType_Handheld = 11,
	ChassisType_DockingStation = 12,
	ChassisType_AllInOne = 13,
	ChassisType_SubNotebook = 14,
	ChassisType_SpaceSaving = 15,
	ChassisType_LunchBox = 16,
	ChassisType_MainSystemChassis = 17,
	ChassisType_ExpansionChassis = 18,
	ChassisType_SubChassis = 19,
	ChassisType_BusExpansionChassis = 20,
	ChassisType_PeripheralChassis = 21,
	ChassisType_StorageChassis = 22,
	ChassisType_RackMountChassis = 23,
	ChassisType_SealedCasePC = 24
};

namespace Core
{
	//initialize core lib stuff
	void init(void);

	//un-initialize core lib stuff
	void uninit(void);

	//client unique id
	HRESULT UniqueID(char *id);
}
