#pragma once

#include <iostream>
#include <Windows.h>
#include <string>
#include <filesystem>
#include <ShlObj_core.h>
#include "BdApiUtilSys.h"  // your new header with driver bytes

class DropOut {

private:
    SC_HANDLE hSC = NULL, hService = NULL;

    auto DropDriverOnDisk() -> BOOLEAN {
        HANDLE hFile = ::CreateFileA(
            "BdApiUtil.sys",
            GENERIC_WRITE,
            0,
            NULL,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hFile == INVALID_HANDLE_VALUE) {
            std::printf("[X] Failed to create BdApiUtil.sys: %d\n", GetLastError());
            return FALSE;
        }

        DWORD written = 0;
        if (!::WriteFile(hFile, BdApiUtilSys, BdApiUtilSysSize, &written, NULL) || written != BdApiUtilSysSize) {
            std::printf("[X] Failed to write driver to disk!\n");
            ::CloseHandle(hFile);
            return FALSE;
        }

        ::CloseHandle(hFile);
        std::printf("[!] Driver dropped successfully\n");
        return TRUE;
    }

    auto InstallDriver() -> BOOLEAN {
        this->hSC = ::OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
        if (this->hSC == NULL) return FALSE;

        this->hService = ::CreateServiceA(
            this->hSC,
            "BdApiUtil",
            "BdApiUtil",
            SC_MANAGER_ALL_ACCESS,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            std::string(std::filesystem::current_path().string()).append("\\BdApiUtil.sys").c_str(),
            NULL, NULL, NULL, NULL, NULL
        );

        if (hService == NULL) {
            this->hService = ::OpenServiceA(this->hSC, "BdApiUtil", SERVICE_ALL_ACCESS);
            if (hService == NULL) {
                ::CloseServiceHandle(this->hSC);
                return FALSE;
            }
        }

        ::CloseServiceHandle(this->hSC);
        ::CloseServiceHandle(this->hService);
        return TRUE;
    }

    auto StartDriver() -> BOOLEAN {
        this->hSC = ::OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (this->hSC == NULL) return FALSE;

        this->hService = ::OpenServiceA(this->hSC, "BdApiUtil", SERVICE_START);
        if (this->hService == NULL) {
            ::CloseServiceHandle(this->hSC);
            return FALSE;
        }

        BOOL started = ::StartServiceA(this->hService, 0, NULL);

        ::CloseServiceHandle(this->hService);
        ::CloseServiceHandle(this->hSC);

        return started;
    }

    auto StopDriver() -> BOOLEAN {
        this->hSC = ::OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
        if (this->hSC == NULL) return FALSE;

        this->hService = ::OpenServiceA(this->hSC, "BdApiUtil", SERVICE_STOP | DELETE);
        if (this->hService == NULL) {
            ::CloseServiceHandle(this->hSC);
            return FALSE;
        }

        SERVICE_STATUS status;
        BOOL result = ::ControlService(this->hService, SERVICE_CONTROL_STOP, &status) && ::DeleteService(this->hService);

        ::CloseServiceHandle(this->hService);
        ::CloseServiceHandle(this->hSC);
        return result;
    }

public:

    DropOut() {
        if (!this->DropDriverOnDisk()) {
            std::printf("[X] Failed to drop driver\n");
            return;
        }

        if (!this->InstallDriver()) {
            std::printf("[X] Failed to install driver\n");
            return;
        }

        if (!this->StartDriver()) {
            std::printf("[X] Failed to start driver\n");
            return;
        }
    }

    auto KillProcessByPID(DWORD dwPID) -> void {
        const wchar_t* deviceName = L"\\\\.\\BdApiUtil";
        const DWORD ioctlTerminateProcess = 0x800024B4;

        HANDLE hDriver = ::CreateFileW(
            deviceName,
            GENERIC_READ | GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hDriver == INVALID_HANDLE_VALUE) {
            std::printf("[X] Failed to open device: %d\n", GetLastError());
            return;
        }

        DWORD bytesReturned = 0;

        BOOL result = ::DeviceIoControl(
            hDriver,
            ioctlTerminateProcess,
            &dwPID,
            sizeof(dwPID),
            NULL,
            0,
            &bytesReturned,
            NULL
        );

        if (!result) {
            std::printf("[X] DeviceIoControl failed: %d\n", GetLastError());
        } else {
            std::printf("[!] DeviceIoControl succeeded\n");
        }

        ::CloseHandle(hDriver);
    }

    ~DropOut() {
        if (!this->StopDriver()) {
            std::printf("[X] Failed to stop and delete driver\n");
        }

        if (!::DeleteFileA("BdApiUtil.sys")) {
            std::printf("[X] Failed to delete BdApiUtil.sys\n");
        } else {
            std::printf("[!] Driver file BdApiUtil.sys deleted\n");
        }

        std::printf("[!] Cleanup complete\n");
    }

};
