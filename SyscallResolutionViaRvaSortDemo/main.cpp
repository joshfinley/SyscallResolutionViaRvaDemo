// https://www.mdsec.co.uk/2020/12/bypassing-user-mode-hooks-and-direct-invocation-of-system-calls-for-red-teams/
// https://d01a.github.io/syscalls/
#include <windows.h>
#include "nt_api.hpp"

#define RVA2VA(Type, DllBase, Rva) (Type)( (ULONG_PTR) DllBase + Rva )

BOOL ResolveSyscalls(PSYSCALL_TABLE SyscallTable)
{
    BOOL Status = FALSE;
    PCHAR DllName = NULL;
    PCHAR FunctionName = NULL;
    DWORD i, j = NULL;
    SIZE_T NameLen = NULL;
    DWORD SyscallRVA = NULL;
    DWORD NumberOfNames = NULL;
    DWORD VirtualAddress = NULL;
    DWORD Entires = NULL;
    DWORD CurrentSyscallNum = NULL;
    PDWORD Functions = NULL;
    PDWORD Names = NULL;
    PWORD Ordinals = NULL;
    HMODULE NtdllBase = NULL;

    PIMAGE_DOS_HEADER DosHeader = NULL;
    PIMAGE_NT_HEADERS NtHeaders = NULL;
    PIMAGE_DATA_DIRECTORY DataDir = NULL;
    PIMAGE_EXPORT_DIRECTORY ExportDir = NULL;
    PSYSCALL_ENTRY TableEntry = NULL;
    SYSCALL_ENTRY CurrentEntry = { NULL };

    // Check params
    if (!SyscallTable)
    {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    // Resolve headers
    NtdllBase = GetModuleHandle(L"ntdll.dll"); // WINAPI use for brevity
    if (!NtdllBase) 
    {
        SetLastError(ERROR_NOT_FOUND);
        return FALSE;
    }

    DosHeader = (PIMAGE_DOS_HEADER)((PBYTE)NtdllBase);
    NtHeaders = RVA2VA(PIMAGE_NT_HEADERS, NtdllBase, DosHeader->e_lfanew);
    if (!NtHeaders)
    {
        SetLastError(ERROR_NOT_FOUND);
        return FALSE;
    }

    DataDir = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
    VirtualAddress = DataDir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!VirtualAddress)
    {
        SetLastError(ERROR_NOT_FOUND);
        return FALSE;
    }

    ExportDir = (PIMAGE_EXPORT_DIRECTORY)RVA2VA(ULONG_PTR, NtdllBase, VirtualAddress);
    if (!ExportDir)
    {
        SetLastError(ERROR_NOT_FOUND);
        return FALSE;
    }

    NumberOfNames = ExportDir->NumberOfNames;

    Functions = RVA2VA(PDWORD, NtdllBase, ExportDir->AddressOfFunctions);
    Names = RVA2VA(PDWORD, NtdllBase, ExportDir->AddressOfNames);
    Ordinals = RVA2VA(PWORD, NtdllBase, ExportDir->AddressOfNameOrdinals);
    
    // Iterate export names and populate fields for Nt* functions
    i = 0;
    do {
        FunctionName = RVA2VA(PCHAR, NtdllBase, Names[NumberOfNames - 1]);
        if (*(PUSHORT)FunctionName != 'wZ') continue;

        TableEntry = SYSCALL_TABLE_ENTRY(SyscallTable, i);

        // Check entry memory
        if (!TableEntry)
        {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }

        // Copy the syscall name
        NameLen = strlen(FunctionName);
        if (NameLen > MAX_PATH)
        {
            SetLastError(ERROR_BAD_FORMAT);
            return FALSE;
        }

        strcpy(TableEntry->SyscallName, FunctionName);

        // Mapping of name to system call number will happen later
        // For now, just set the RVA
        TableEntry->RVA = Functions[Ordinals[NumberOfNames - 1]];
        if (TableEntry->RVA == NULL)
        {
            SetLastError(ERROR_BAD_FORMAT);
        }

        i++;

    } while (--NumberOfNames && i < MAX_SYSCALL_ENTRIES);

    SyscallTable->NumEntries = i;

    for (i = 0; i < SyscallTable->NumEntries - 1; i++) {
        for (j = 0; j < SyscallTable->NumEntries - i - 1; j++) {
            if (SyscallTable->Entries[j].RVA > SyscallTable->Entries[j + 1].RVA) {
                //
                // Swap entries.
                //
                strcpy_s(
                    CurrentEntry.SyscallName, 
                    MAX_PATH, 
                    SyscallTable->Entries[j].SyscallName
                );
                CurrentEntry.RVA = SyscallTable->Entries[j].RVA;

                strcpy_s(
                    SyscallTable->Entries[j].SyscallName,
                    MAX_PATH,
                    SyscallTable->Entries[j + 1].SyscallName
                );
                SyscallTable->Entries[j].RVA = SyscallTable->Entries[j + 1].RVA;

                strcpy_s(
                    SyscallTable->Entries[j + 1].SyscallName,
                    MAX_PATH,
                    CurrentEntry.SyscallName
                );
                SyscallTable->Entries[j + 1].RVA = CurrentEntry.RVA;
            }
        }
    }

    // Assign syscall numbers based on the sorted order
    for (i = 0; i < SyscallTable->NumEntries; ++i) {
        SyscallTable->Entries[i].SyscallNumber = i;
    }

    Status = TRUE;
    return Status;
}

INT main()
{
    BOOL Ok = FALSE;
    DWORD Status = ERROR_SUCCESS;
    PSYSCALL_TABLE SyscallTable = NULL;

    SyscallTable = (PSYSCALL_TABLE)HeapAlloc(
        GetProcessHeap(), NULL, sizeof(SYSCALL_TABLE)
    );

    if (!SyscallTable) return GetLastError();

    Ok = ResolveSyscalls(SyscallTable);
    if (!Ok) return GetLastError();

    return Status;
}

