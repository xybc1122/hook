#include"InlineHook.h"
#include "pch.h"
#include<iostream>

#define HOOK_ORIADDR  0x004A3AB8 //������ʼ��ַ


#define PATCH_LENGTH  6     

DWORD dwHookAddr; //hook��ַ

DWORD dwRetAddr; //hook���ص�ַ

DWORD dwHookAppendAddr;

DWORD dwRetAppendAddr;

BYTE  byCall[PATCH_LENGTH]; // jmp ������

BYTE  oldCall[PATCH_LENGTH]; //ж�� ������


DWORD  dwOldProtect;

char  szNewCode[] = "ba855-00000-88aa6-00000";



void  HookAppend();




void saveValue(DWORD v) {
	MessageBox(0, (LPCSTR)v,0,0);
}

DWORD pEax = 0;
//_declspec (naked)ʲô��һ���㺯�� ���ǲ����κ���������Ĳ���
//���Ӻ���
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
			//��ȡ�Լ����̵ľ��
			HANDLE handle=OpenProcess(PROCESS_ALL_ACCESS,NULL,GetCurrentProcessId());
				
			//����hook��ַ
			BOOL saveFlg=ReadProcessMemory(handle, (LPCVOID)dwHookAddr, oldCall, PATCH_LENGTH,NULL);
			if (!saveFlg) {
				MessageBox(0,"����hook��ַʧ��",0,0);
				return;
			}

			//�滻ԭ���ֽ�  �滻�� jmp e9 00000000
			BOOL writeFlg=WriteProcessMemory(handle, (LPVOID)dwHookAddr, byCall, PATCH_LENGTH,NULL);
			if (!writeFlg) {
				MessageBox(0, "����hookд��ʧ��", 0, 0);
				return;
			}
	}

	//˲ʱ�¹����� δʵ��
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