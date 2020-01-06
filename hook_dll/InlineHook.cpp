#include"InlineHook.h"
#include "pch.h"

#define HOOK_ORIADDR  0x004A6F7C
#define PATCH_LENGTH  8
DWORD dwHookAddr;
DWORD dwRetAddr;
//钩子函数
void _declspec (naked)  HookFunc() {

	_asm {
		//1 保存寄存器
		pushad
		pushfd





		popfd
		popad

	}


}
	//下钩函数
	void  HookFun() {
		//要hook的地址
		dwHookAddr = HOOK_ORIADDR;
		 //ret 返回的地址
		dwRetAddr = dwHookAddr+ PATCH_LENGTH;
		//初始化地址
		BYTE  byJmpCall[PATCH_LENGTH] = {0xE9};
		DWORD  dwOldProtect = 0;
		memset(&byJmpCall[1],0x90, PATCH_LENGTH - 1);
		memset(&byJmpCall[2], 0x90, PATCH_LENGTH - 2);
		memset(&byJmpCall[3], 0x90, PATCH_LENGTH - 3);
		//存储跳转地址
		*(DWORD*)&byJmpCall[1]=(DWORD)HookFunc - (DWORD)dwHookAddr - 5;
		//备份被之前覆盖的数据

		//修改内存属性
		VirtualProtect((LPVOID)HOOK_ORIADDR, PATCH_LENGTH, PAGE_EXECUTE_READWRITE,&dwOldProtect);
		memcpy((LPVOID)dwHookAddr, byJmpCall, PATCH_LENGTH);
	
	}


	void SetHook() {

		HookFun();

	}