#pragma once

#include <Windows.h>
#include <vector>
#include <memory>

#define MEMORY_SEARCH_RANGE			256 * 1024 * 1024 // 256 MB
#define DEFAULT_WIN_PAGE_ALLOC_SIZE 0x1000

#define CC_SUCCESS					0x00;
#define CC_QUERY_FAILED				0x01;
#define CC_ALLOC_FAILED				0x02;
#define CC_CAVE_NOT_FOUND			0x03;

typedef PBYTE MEMORY_PAGE;

// TODO support 32 bit
typedef struct CodeCave {
	MEMORY_PAGE pCaveBase;
	UINT64 uLen;
	UINT64 uUsed;
} CodeCave, *PCodeCave;

typedef class CodeCaveManager {

private:
	std::vector<CodeCave> vecCaves;

public:
	~CodeCaveManager();

	DWORD FindCodeCave(_In_ PVOID pSearchBase, _In_ UINT64 uNeededBytes, _Inout_ PCodeCave pCodeCave);

} CodeCaveManager, *PCodeCaveManager;

inline std::unique_ptr<CodeCaveManager> instCCManager = std::make_unique<CodeCaveManager>();
