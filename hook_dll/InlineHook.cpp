#include"InlineHook.h"
#include "pch.h"

#define HOOK_ORIADDR  0x004A6F7C
#define PATCH_LENGTH  8
DWORD dwHookAddr;
DWORD dwRetAddr;
//���Ӻ���
void _declspec (naked)  HookFunc() {

	_asm {
		//1 ����Ĵ���
		pushad
		pushfd





		popfd
		popad

	}


}
	//�¹�����
	void  HookFun() {
		//Ҫhook�ĵ�ַ
		dwHookAddr = HOOK_ORIADDR;
		 //ret ���صĵ�ַ
		dwRetAddr = dwHookAddr+ PATCH_LENGTH;
		//��ʼ����ַ
		BYTE  byJmpCall[PATCH_LENGTH] = {0xE9};
		DWORD  dwOldProtect = 0;
		memset(&byJmpCall[1],0x90, PATCH_LENGTH - 1);
		memset(&byJmpCall[2], 0x90, PATCH_LENGTH - 2);
		memset(&byJmpCall[3], 0x90, PATCH_LENGTH - 3);
		//�洢��ת��ַ
		*(DWORD*)&byJmpCall[1]=(DWORD)HookFunc - (DWORD)dwHookAddr - 5;
		//���ݱ�֮ǰ���ǵ�����

		//�޸��ڴ�����
		VirtualProtect((LPVOID)HOOK_ORIADDR, PATCH_LENGTH, PAGE_EXECUTE_READWRITE,&dwOldProtect);
		memcpy((LPVOID)dwHookAddr, byJmpCall, PATCH_LENGTH);
	
	}


	void SetHook() {

		HookFun();

	}