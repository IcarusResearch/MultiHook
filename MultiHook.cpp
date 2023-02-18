#include "MultiHook.h"

#include "CodeCave.h"

MultiHook::VMTHook::VMTHook(PVOID pObject, UINT uFuncCount) 
	: Hook(), pObject(static_cast<PVOID**>(pObject)),
	  uFuncCount(uFuncCount + 1), pVMTOriginal(*this->pObject), 
	  pVMTNew(std::make_unique<PVOID[]>(this->uFuncCount)) {
	std::copy_n(pVMTOriginal - 1, uFuncCount, pVMTNew.get());
}

BOOL MultiHook::VMTHook::Enable() {
	*pObject = pVMTNew.get() + 1;
	return TRUE;
}

BOOL MultiHook::VMTHook::Disable() {
	*pObject = pVMTOriginal;
	return TRUE;
}

BOOL MultiHook::VMTHook::PerformHook(UINT uIndex, PVOID pFunc) {
	pVMTNew[uIndex + 1] = pFunc;
	return TRUE;
}

BOOL MultiHook::VMTHook::PerformUnhook(UINT uIndex) {
	pVMTNew[uIndex + 1] = pVMTOriginal[uIndex];
	return TRUE;
}

MultiHook::Hook::Hook() {}

LONG WINAPI MultiHook::VEHHook::ExceptionHandler(PEXCEPTION_POINTERS pExceptionPointers) {
	if (pExceptionPointers->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
		std::lock_guard<std::mutex> lock(VEHHook::mutexGlobalState);
		for (auto& iterator : mapActiveHooks) {
#ifdef _WIN64
			if ((ULONG_PTR) iterator.first == pExceptionPointers->ContextRecord->Rip) {
				pExceptionPointers->ContextRecord->Rip = (ULONG_PTR) iterator.second;
#elif
			if ((ULONG_PTR) iterator.first == pExceptionPointers->ContextRecord->Eip) {
				pExceptionPointers->ContextRecord->Eip = (ULONG_PTR) iterator.second;
#endif
				break;
			}
		}
		pExceptionPointers->ContextRecord->EFlags |= 0x100;
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	if (pExceptionPointers->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP) {
		DWORD dwOld;
		VirtualProtect(pExceptionPointers->ExceptionRecord->ExceptionAddress, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld);
		return EXCEPTION_CONTINUE_EXECUTION;
	}
	return EXCEPTION_CONTINUE_SEARCH;
}

MultiHook::VEHHook::VEHHook(PVOID pOriginal, PVOID pHooked) 
	: pOriginal(pOriginal), pHooked(pHooked), dwOldProtection(0) {}

BOOL MultiHook::VEHHook::Enable() {
	MEMORY_BASIC_INFORMATION mbiOriginal, mbiHooked;
	if (!VirtualQuery(pOriginal, &mbiOriginal, sizeof(mbiOriginal))) {
		return FALSE;
	}
	if (!VirtualQuery(pHooked, &mbiHooked, sizeof(mbiHooked))) {
		return FALSE;
	}
	if (mbiOriginal.BaseAddress == mbiHooked.BaseAddress) {
		// both functions are in the same memory page; PAGE_GUARD exceptions would recurse forever
		return FALSE;
	}
	std::lock_guard<std::mutex> lock(VEHHook::mutexGlobalState);
	if (!pVEH) {
		pVEH = AddVectoredExceptionHandler(TRUE, (PVECTORED_EXCEPTION_HANDLER) ExceptionHandler);
		if (!pVEH) {
			return FALSE;
		}
	}
	return TRUE;
}

BOOL MultiHook::VEHHook::Disable() {
	std::lock_guard<std::mutex> lock(VEHHook::mutexGlobalState);
	if (pVEH && mapActiveHooks.empty()) {
		if (!RemoveVectoredExceptionHandler(pVEH)) {
			return FALSE;
		} else {
			pVEH = NULL;
		}
	}
	return TRUE;
}

BOOL MultiHook::VEHHook::PerformHook() {
	std::lock_guard<std::mutex> lock(VEHHook::mutexGlobalState);
	mapActiveHooks[pOriginal] = pHooked;
	return pVEH && !!VirtualProtect(pOriginal, 0x01, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOldProtection);
}

BOOL MultiHook::VEHHook::PerformUnhook() {
	std::lock_guard<std::mutex> lock(VEHHook::mutexGlobalState);
	mapActiveHooks.erase(pOriginal);
	DWORD dwOld;
	return VirtualProtect(pOriginal, 0x01, dwOldProtection, &dwOld);
}

MultiHook::DetourHook::DetourHook(PVOID pOriginal, PVOID pHook, UINT uLen)
	: pOriginal(pOriginal), pHooked(pHook), uLen(uLen), pRealFunction(pOriginal), 
	  pBackupInst(new BYTE[uLen]) {}

MultiHook::DetourHook::~DetourHook() {
	delete[] pBackupInst;
}

BOOL MultiHook::DetourHook::Enable() {
	CodeCave cave = {};
	if (instCCManager->FindCodeCave(pOriginal, GATEWAY_INSTRUCTION_COUNT + uLen, &cave)) {
		return FALSE;
	}

	// copy old instructions
	DWORD dwOldFlags;
	VirtualProtect(pOriginal, uLen, PAGE_READONLY, &dwOldFlags);
	memcpy(pBackupInst, pOriginal, uLen);
	VirtualProtect(pOriginal, uLen, dwOldFlags, &dwOldFlags);

	ULONG_PTR uCaveUseBase = (ULONG_PTR) cave.pCaveBase + cave.uUsed;
	uCaveOffset = uCaveUseBase;

	// absolute jump to hook
	CONST JMP_ABS_IND_64 jmpHook = { 0x48, 0xB8, (ULONG_PTR) pHooked, 0xFF, 0xE0 };
	memcpy((PBYTE) uCaveUseBase, &jmpHook, sizeof(jmpHook));
	uCaveUseBase += sizeof(jmpHook);

	// original instructions for gateway
	pGateway = (PBYTE) uCaveUseBase;
	memcpy(pGateway, pBackupInst, uLen);
	uCaveUseBase += uLen;

	// relative jump to original function
	CONST JMP_REL_DIR_32 jmpOriginal = { 0xE9, (INT32) ((ULONG_PTR) pOriginal + uLen - (uCaveUseBase + sizeof(JMP_REL_DIR_32))) };
	memcpy((PBYTE) uCaveUseBase, &jmpOriginal, sizeof(JMP_REL_DIR_32));
	uCaveUseBase += sizeof(JMP_REL_DIR_32);

	cave.uUsed = uCaveUseBase - (ULONG_PTR) cave.pCaveBase;
	return TRUE;
}

BOOL MultiHook::DetourHook::Disable() {
	return TRUE;
}

BOOL MultiHook::DetourHook::PerformHook() {
	// relative jump to code cave
	DWORD dwOldFlags;
	VirtualProtect(pOriginal, uLen, PAGE_READWRITE, &dwOldFlags);
#pragma warning(push)
#pragma warning(disable: 4838 4244)
	CONST JMP_REL_DIR_32 jmpCave = { 0xE9, (INT32) ((ULONG_PTR) uCaveOffset) - ((ULONG_PTR) pOriginal + sizeof(JMP_REL_DIR_32)) };
#pragma warning(pop)
	memcpy(pOriginal, &jmpCave, sizeof(JMP_REL_DIR_32));
	VirtualProtect(pOriginal, uLen, dwOldFlags, &dwOldFlags);
	pRealFunction = pGateway;
	return TRUE;
}

// TODO this WILL crash the process if the RIP is pointing to the replaced instructions
BOOL MultiHook::DetourHook::PerformUnhook() {
	// restore original functionality
	DWORD dwOldFlags;
	VirtualProtect(pOriginal, uLen, PAGE_READWRITE, &dwOldFlags);
	memcpy(pOriginal, pBackupInst, uLen);
	VirtualProtect(pOriginal, uLen, dwOldFlags, &dwOldFlags);
	pRealFunction = pOriginal;
	return TRUE;
}
