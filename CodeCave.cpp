#include "CodeCave.h"

CodeCaveManager::~CodeCaveManager() {
    for (CONST auto& entry : vecCaves) {
        VirtualFree(entry.pCaveBase, 0, MEM_RELEASE);
    }
}

DWORD CodeCaveManager::FindCodeCave(_In_ PVOID pSearchBase, _In_ UINT64 uNeededBytes, _Inout_ PCodeCave pCodeCave) {
    PBYTE pOrigin = (PBYTE) pSearchBase;

    SYSTEM_INFO si;
    GetSystemInfo(&si);
    
    ULONG_PTR uMinSize = (ULONG_PTR) (pOrigin - MEMORY_SEARCH_RANGE);
    ULONG_PTR uMaxSize = (ULONG_PTR) (pOrigin + MEMORY_SEARCH_RANGE);

    PBYTE pAddr = pOrigin - ((ULONG_PTR) pOrigin % si.dwAllocationGranularity) + si.dwAllocationGranularity;

    BOOL bFoundCave = FALSE;

    while ((ULONG_PTR) pAddr <= uMaxSize) {
        MEMORY_BASIC_INFORMATION memoryInfo;
        if (!VirtualQuery(pAddr, &memoryInfo, sizeof(memoryInfo))) {
            return CC_QUERY_FAILED;
        }
        if (memoryInfo.State == MEM_FREE) {
            bFoundCave = TRUE;
            break;
        }
        pAddr = (PBYTE) memoryInfo.BaseAddress + memoryInfo.RegionSize + (si.dwAllocationGranularity - 1);
        pAddr -= (ULONG_PTR) pAddr % si.dwAllocationGranularity;
    }
    if (bFoundCave) {
        if (!VirtualAlloc((LPVOID) pAddr, DEFAULT_WIN_PAGE_ALLOC_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE)) {
            return CC_ALLOC_FAILED;
        }
        CodeCave cave = { (MEMORY_PAGE) pAddr, DEFAULT_WIN_PAGE_ALLOC_SIZE, 0 };
        instCCManager->vecCaves.push_back(cave);
        *pCodeCave = cave;
        return CC_SUCCESS;
    }
    else {
        return CC_CAVE_NOT_FOUND;
    }
    return CC_SUCCESS;
}
