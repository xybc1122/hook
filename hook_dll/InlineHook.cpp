#include"InlineHook.h"
#include "pch.h"
#include<iostream>

#define HOOK_ORIADDR  0x004A6F7C //钩子起始地址
#define PATCH_LENGTH  8      
DWORD dwHookAddr;
DWORD dwRetAddr;
BYTE  byCall[PATCH_LENGTH];
BYTE  oldCall[PATCH_LENGTH];
DWORD  dwOldProtect;

DWORD  dwCallAddressVp = 0x004A6F58; //判断是否是这个地址调的call

DWORD c = 0x004052BC;//内联汇编跳转的call 地址

char  szNewCode[] = "ba855-00000-88aa6-00000";





void setCode() {



}
//瞬时钩子
void _declspec (naked)  HookFunAppend() {
	__asm {
		//保存寄存器
		pushad;
		pushfd;
		mov eax, dword ptr ss : [esp - 0x4];
		cmp eax, dwCallAddressVp;
		jnz Lable;
		//做点啥

		//恢复寄存器
		popfd;
		popad;

	Lable:
		popfd;
		popad;
	}
}

//钩子函数
void _declspec (naked)  HookFunc() {
	__asm {
		//保存寄存器
		pushad;
		pushfd;
		// 修改数据
		lea eax, DWORD PTR DS:[szNewCode];
		mov dword ptr ss : [ebp - 0x4] , eax;
		//恢复寄存器
		popfd;
		popad;
		mov edx, dword ptr ss : [ebp - 0x4] ;
		call c;
		jmp dwRetAddr;
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
			
			//保存原先字节
			memcpy(oldCall, (void*)dwHookAddr, PATCH_LENGTH);

			//替换原先字节  替换成 jmp e9 00000000
			memcpy((void*)dwHookAddr, byCall, PATCH_LENGTH);
	}	
		
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