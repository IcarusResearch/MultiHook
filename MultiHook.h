#pragma once

#include <type_traits>
#include <Windows.h>
#include <memory>
#include <unordered_map>
#include <mutex>

namespace MultiHook {

	class Hook {

	protected:
		Hook();

	public:
		virtual BOOL Enable() = 0;
		virtual BOOL Disable() = 0;

	};

	// hook by pointing to a different virtual function implementation in the virtual method table
	class VMTHook : public Hook {

	private:
		PVOID** pObject;
		UINT uFuncCount;
		PVOID* pVMTOriginal;
		std::unique_ptr<PVOID[]> pVMTNew;

	public:
		VMTHook(PVOID pObject, UINT uFuncCount);

		BOOL Enable() override;
		BOOL Disable() override;

		BOOL PerformHook(UINT uIndex, PVOID pFunc);
		BOOL PerformUnhook(UINT uIndex);

		template <typename T> T GetRealFunction(UINT uIndex);

	};

	template <typename T>
	inline T VMTHook::GetRealFunction(UINT uIndex) {
		return static_cast<T>(pVMTOriginal[uIndex]);
	}

	// hook by using vectored exception handlers with page guards
	class VEHHook : public Hook {
	
	private:
		static std::unordered_map<PVOID, PVOID> mapActiveHooks;
		static std::mutex mutexGlobalState;
		static PVOID pVEH;
		PVOID pOriginal;
		PVOID pHooked;
		DWORD dwOldProtection;

		static LONG WINAPI ExceptionHandler(PEXCEPTION_POINTERS pExceptionPointers);

	public:
		VEHHook(PVOID pOriginal, PVOID pHooked);

		BOOL Enable() override;
		BOOL Disable() override;

		BOOL PerformHook();
		BOOL PerformUnhook();

		// TODO allow original call
		//template <typename T> T GetRealFunction();

	};

	std::unordered_map<PVOID, PVOID> VEHHook::mapActiveHooks;
	std::mutex VEHHook::mutexGlobalState;
	PVOID VEHHook::pVEH = NULL;

	// hook by detouring the execution flow of the original function
	class DetourHook : Hook {

		static constexpr UINT GATEWAY_INSTRUCTION_COUNT = 17;

#pragma pack(push, 1)
		typedef struct JMP_ABS_IND_64 {
			BYTE op1;
			BYTE op2;
			UINT64 uAbsAddr;
			BYTE op3;
			BYTE op4;
		} JMP_ABS_IND_64, * PJMP_ABS_IND_64;
		typedef struct JMP_REL_DIR_32 {
			BYTE op1;
			INT32 relAddr;
		} JMP_REL_DIR_32, * PJMP_REL_DIR_32;
#pragma pack(pop)
		// TODO add 32 bit support

	private:
		PVOID pOriginal;
		PVOID pHooked;
		PVOID pGateway = NULL;
		PVOID pRealFunction;
		UINT64 uLen;
		UINT64 uCaveOffset = 0;
		PBYTE pBackupInst;

	public:
		DetourHook(PVOID pOriginal, PVOID pHook, UINT uLen);
		~DetourHook();

		BOOL Enable() override;
		BOOL Disable() override;

		BOOL PerformHook();
		BOOL PerformUnhook();

		template <typename T> T GetRealFunction();

	};

	template <typename T>
	inline T DetourHook::GetRealFunction() {
		return static_cast<T>(pRealFunction);
	}

}
