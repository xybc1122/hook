#include"InlineHook.h"
#include "pch.h"

#define HOOK_ORIADDR  0x004A6F7C //������ʼ��ַ
#define PATCH_LENGTH  8
DWORD dwHookAddr;
BYTE  byCall[PATCH_LENGTH];
BYTE  oldCall[PATCH_LENGTH];
DWORD dwRetAddr;
DWORD  dwOldProtect;

DWORD c = 0x004052BC;//���������ת��call ��ַ

char  szNewCode[] = "7e321-00000-d41d8-00000";





void setCode() {



}




//���Ӻ���
void _declspec (naked)  HookFunc() {
	__asm {
		//����Ĵ���
		// �޸�����
		lea eax, DWORD PTR DS:[szNewCode];
		mov dword ptr ss : [ebp - 0x4] , eax;
		//�ָ��Ĵ���
		mov edx, dword ptr ss : [ebp - 0x4]
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
			//Ҫhook�ĵ�ַ
			dwHookAddr = HOOK_ORIADDR;
			// //ret ���صĵ�ַ
			dwRetAddr = dwHookAddr + PATCH_LENGTH;
			//��ʼ����ַ
			byCall[0] = { 0xE9 };
			dwOldProtect = 0;

			//���ú����Ϊnop 
			memset(&byCall[1], 0x90, PATCH_LENGTH - 1);


			//�洢��ת��ַ Ҫ��ת�ĵ�ַ -  ��ǰ��ַ - 5
			*(DWORD*)&byCall[1] = (DWORD)HookFunc - (DWORD)dwHookAddr - 5;

			// һ�������ǲ���д��,������Ҫ�����Ϊ�ɶ���д.
			VirtualProtect((LPVOID)HOOK_ORIADDR, PATCH_LENGTH, PAGE_EXECUTE_READWRITE, &dwOldProtect);
			//����ԭ���ֽ�
			memcpy(oldCall, (void*)dwHookAddr, PATCH_LENGTH);

			//�滻ԭ���ֽ�
			memcpy((void*)dwHookAddr, byCall, PATCH_LENGTH);
			// �ָ�����
			//UnHook();
	}	


	void SetHook() {

		HookFun();

	}