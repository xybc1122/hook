#include"InlineHook.h"
#include "pch.h"
#include<iostream>

#define HOOK_ORIADDR  0x004A3AB8 //钩子起始地址


#define PATCH_LENGTH  6     

DWORD dwHookAddr; //hook地址

DWORD dwRetAddr; //hook返回地址

DWORD dwHookAppendAddr;

DWORD dwRetAppendAddr;

BYTE  byCall[PATCH_LENGTH]; // jmp 机器码

BYTE  oldCall[PATCH_LENGTH]; //卸载 机器码


DWORD  dwOldProtect;

char  szNewCode[] = "ba855-00000-88aa6-00000";



void  HookAppend();




void saveValue(DWORD v) {
	MessageBox(0, (LPCSTR)v,0,0);
}

DWORD pEax = 0;
//_declspec (naked)什么是一个裸函数 就是不做任何其他多余的操作
//钩子函数
void _declspec (naked)  HookFunc() {
	__asm {
		mov eax, dword ptr ss : [ebp - 0x2C4]
		mov dword ptr ss : [ebp - 0x2A8] , eax
		pushad
		pushfd
		mov pEax, eax
	}
	saveValue(pEax);
	__asm {
		popfd
		popad
		jmp dwRetAddr
	}



}

void UnHook() {
	//恢复原先字节
	memcpy((void*)dwHookAddr, oldCall, PATCH_LENGTH);
	//恢复属性
	DWORD p;
	VirtualProtect((void*)dwHookAddr, PATCH_LENGTH, dwOldProtect, &p);
}


	//下钩函数
	void  HookFun() {
			dwHookAddr = HOOK_ORIADDR;
			//ret 返回的地址
			dwRetAddr = dwHookAddr + PATCH_LENGTH;
			//初始化地址
			byCall[0] = { 0xE9 };
			dwOldProtect = 0;

			//设置后面的为nop 
			memset(&byCall[1], 0x90, PATCH_LENGTH - 1);

			//存储跳转地址 要跳转的地址 -  当前地址 - 5
			*(DWORD*)&byCall[1] = (DWORD)HookFunc - (DWORD)dwHookAddr - 5;
				
			// 一般代码段是不可写的,我们需要把其改为可读可写.
			VirtualProtect((LPVOID)dwHookAddr, PATCH_LENGTH, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			//获取自己进程的句柄
			HANDLE handle=OpenProcess(PROCESS_ALL_ACCESS,NULL,GetCurrentProcessId());
				
			//备份hook地址
			BOOL saveFlg=ReadProcessMemory(handle, (LPCVOID)dwHookAddr, oldCall, PATCH_LENGTH,NULL);
			if (!saveFlg) {
				MessageBox(0,"备份hook地址失败",0,0);
				return;
			}

			//替换原先字节  替换成 jmp e9 00000000
			BOOL writeFlg=WriteProcessMemory(handle, (LPVOID)dwHookAddr, byCall, PATCH_LENGTH,NULL);
			if (!writeFlg) {
				MessageBox(0, "备份hook写入失败", 0, 0);
				return;
			}
	}

	//瞬时下钩函数 未实现
	void  HookAppend() {
		
	}
	



	//普通钩子
	void SetHook() {

		HookFun();
	}
	//瞬时钩子
	void SetHookAppend() {
		HookAppend();
	}