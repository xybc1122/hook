#include"InlineHook.h"
#include "pch.h"
#include<iostream>

#define HOOK_ORIADDR  0x004A6F7C //������ʼ��ַ
#define PATCH_LENGTH  8      
DWORD dwHookAddr;
DWORD dwRetAddr;
BYTE  byCall[PATCH_LENGTH];
BYTE  oldCall[PATCH_LENGTH];
DWORD  dwOldProtect;

DWORD  dwCallAddressVp = 0x004A6F58; //�ж��Ƿ��������ַ����call

DWORD c = 0x004052BC;//���������ת��call ��ַ

char  szNewCode[] = "ba855-00000-88aa6-00000";





void setCode() {



}
//˲ʱ����
void _declspec (naked)  HookFunAppend() {
	__asm {
		//����Ĵ���
		pushad;
		pushfd;
		mov eax, dword ptr ss : [esp - 0x4];
		cmp eax, dwCallAddressVp;
		jnz Lable;
		//����ɶ

		//�ָ��Ĵ���
		popfd;
		popad;

	Lable:
		popfd;
		popad;
	}
}

//���Ӻ���
void _declspec (naked)  HookFunc() {
	__asm {
		//����Ĵ���
		pushad;
		pushfd;
		// �޸�����
		lea eax, DWORD PTR DS:[szNewCode];
		mov dword ptr ss : [ebp - 0x4] , eax;
		//�ָ��Ĵ���
		popfd;
		popad;
		mov edx, dword ptr ss : [ebp - 0x4] ;
		call c;
		jmp dwRetAddr;
	}
}

void UnHook() {
	//�ָ�ԭ���ֽ�
	memcpy((void*)dwHookAddr, oldCall, PATCH_LENGTH);
	//�ָ�����
	DWORD p;
	VirtualProtect((void*)dwHookAddr, PATCH_LENGTH, dwOldProtect, &p);
}


	//�¹�����
	void  HookFun() {
			dwHookAddr = HOOK_ORIADDR;
			//ret ���صĵ�ַ
			dwRetAddr = dwHookAddr + PATCH_LENGTH;
			//��ʼ����ַ
			byCall[0] = { 0xE9 };
			dwOldProtect = 0;

			//���ú����Ϊnop 
			memset(&byCall[1], 0x90, PATCH_LENGTH - 1);


			//�洢��ת��ַ Ҫ��ת�ĵ�ַ -  ��ǰ��ַ - 5
			*(DWORD*)&byCall[1] = (DWORD)HookFunc - (DWORD)dwHookAddr - 5;

			// һ�������ǲ���д��,������Ҫ�����Ϊ�ɶ���д.
			VirtualProtect((LPVOID)dwHookAddr, PATCH_LENGTH, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			
			//����ԭ���ֽ�
			memcpy(oldCall, (void*)dwHookAddr, PATCH_LENGTH);

			//�滻ԭ���ֽ�  �滻�� jmp e9 00000000
			memcpy((void*)dwHookAddr, byCall, PATCH_LENGTH);
	}	
		
	void  HookAppend() {
	
	
	
	}
	//��ͨ����
	void SetHook() {

		HookFun();
	}
	//˲ʱ����
	void SetHookAppend() {

		HookAppend();
	}