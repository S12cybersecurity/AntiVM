#include <string>
#include <codecvt>
#include <locale>
#include <WS2tcpip.h>
#include <iphlpapi.h>
#include <tchar.h>


#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Mpr.lib")


using namespace std;

class AntiVM{
public:
	AntiVM() {
        const std::wstring vmwareSubKey = s2ws("SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000");
        bool vmwareDriverDescCheck = CheckRegistryKey(HKEY_LOCAL_MACHINE, vmwareSubKey, s2ws("DriverDesc"), s2ws("VMware SCSI Controller"));
        bool vmwareProviderNameCheck = CheckRegistryKey(HKEY_LOCAL_MACHINE, vmwareSubKey, s2ws("ProviderName"), s2ws("VMware, Inc."));

        // VirtualBox keys
        const std::wstring virtualboxSubKey = s2ws("SOFTWARE\\Oracle\\VirtualBox Guest Additions");
        //bool virtualboxCheck = CheckRegistryKeyExists(HKEY_LOCAL_MACHINE, virtualboxSubKey);


        //if (vmwareProviderNameCheck || virtualboxCheck || vmwareDriverDescCheck) {
        if (vmwareProviderNameCheck || vmwareDriverDescCheck) {
			exit(0);
        }

        //checkProvider();
        //detectVMViaMac();   
        checkVirtualBoxSharedFolders();
	}

private:
    bool x = false;
    int __cdecl Handler(EXCEPTION_RECORD* pRec, void* est, unsigned char* pContext, void* disp)
    {
        x = true;
        (*(unsigned long*)(pContext + 0xB8)) += 4;
        return ExceptionContinueExecution;
    }

	int getRam() {
		MEMORYSTATUSEX memInfo;
		memInfo.dwLength = sizeof(memInfo);
		GlobalMemoryStatusEx(&memInfo);
		return memInfo.ullTotalPhys / 1024 / 1024;
	}

    std::wstring s2ws(const std::string& str) {
        std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
        return converter.from_bytes(str);
    }

    bool CheckRegistryKey(HKEY hKeyRoot, const std::wstring& subKey, const std::wstring& valueName, const std::wstring& expectedValue) {
        HKEY hKey;
        if (RegOpenKeyExW(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return false;
        }

        wchar_t value[256];
        DWORD valueLength = sizeof(value);
        if (RegQueryValueExW(hKey, valueName.c_str(), nullptr, nullptr, (LPBYTE)value, &valueLength) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return false;
        }

        RegCloseKey(hKey);

        return std::wstring(value, valueLength / sizeof(wchar_t) - 1) == expectedValue;
    }

    bool CheckRegistryKeyExists(HKEY hKeyRoot, const std::wstring& subKey) {
        HKEY hKey;
        if (RegOpenKeyExW(hKeyRoot, subKey.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        return false;
    }

    int checkProvider() {
        unsigned long pnsize = 0x1000;
        LPWSTR provider = (LPWSTR)LocalAlloc(LMEM_ZEROINIT, pnsize * sizeof(WCHAR));
        int retv = WNetGetProviderName(WNNC_NET_RDR2SAMPLE, provider, &pnsize);
        if (retv == NO_ERROR)
        {
            if (lstrcmpi(provider, L"VirtualBox Shared Folders") == 0)
            {
                ExitProcess(9);
            }
        }
        return 0;
    }

    int detectVMViaMac() {
        WSADATA WSD;
        if (!WSAStartup(MAKEWORD(2, 2), &WSD))
        {
            unsigned long tot_size = 0;
            int ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, 0, 0, &tot_size);
            if (ret == ERROR_BUFFER_OVERFLOW)
            {
                IP_ADAPTER_ADDRESSES* px = (IP_ADAPTER_ADDRESSES*)LocalAlloc(LMEM_ZEROINIT, tot_size);
                if (px)
                {
                    ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, 0, px, &tot_size);
                    IP_ADAPTER_ADDRESSES* pxx = px;
                    //Traverse a singly-linked list
                    for (pxx; pxx; pxx = pxx->Next)
                    {
                        if (pxx->PhysicalAddressLength == 0x6)
                        {
                            if (_wcsicmp(pxx->FriendlyName, L"VirtualBox Host-Only Network"))  //We don't want to detect the HOST OS
                            {
                                char xx[0x6] = { 0 };
                                memcpy(xx, pxx->PhysicalAddress, 0x6);
                                if (xx[0] == 0x08 && xx[1] == 0x00 && xx[2] == 0x27) //Cadmus Computer Systems Mac address
                                {
                                     exit(0);
                                }
                            }
                        }
                    }
                    LocalFree(px);
                }
            }
            WSACleanup();
        }
    }

    int checkVirtualBoxSharedFolders() {
        for (WCHAR x = L'A'; x <= L'Z'; x++) {
            WCHAR drv[4] = { 0 };
            drv[0] = x;
            drv[1] = L':';
            drv[2] = L'\\';

            if (DRIVE_REMOTE == GetDriveType(drv)) {
                WCHAR FSName[0x110] = { 0 };
                if (GetVolumeInformation(drv, NULL, 0, NULL, NULL, NULL, FSName, 0x100)) {
                    if (lstrcmpiW(L"VBoxSharedFolderFS", FSName) == 0) {
                        exit(0);
                    }
                    else {
                        wprintf(L"%s %s\r\n", drv, FSName);
                    }
                }
            }
        }
        return 0;
    }



};