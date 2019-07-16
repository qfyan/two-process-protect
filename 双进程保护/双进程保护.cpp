// 双进程保护.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include<Windows.h>

#define DEF_MUTEX_NAME L"my_mutex"
#define DEF_KEY 0x17



PROCESS_INFORMATION		pi = { 0, };
int step = 0;

using namespace std;




typedef DWORD(WINAPI *MESSAGEBOXW)(HWND, LPCTSTR, LPCTSTR, DWORD);


void child_process()
{
	
	_asm
	{
		/*call s
		s:
		pop eax
		add eax,9
			mov 变量,eax*/
		//这几句可以求出异常代码地址，但是是在被调试进程中，调试器不知道，进程间数据共享？
		_emit 0x8d //lea eax,eax
		_emit 0x0c0
			_emit 0x7d
			_emit 0x17
			_emit 0x7d
			_emit 0x17
			_emit 0x7d
			_emit 0x17
			_emit 0x9a//加密后的lea eax，eax
			_emit 0x0d7
			call MessageBoxW//call指令解析很麻烦，不解析成机器码加密
		/*push 0
		push 0
		push 0
		push 0
		call MessageBoxW*/
	}
}


int onException(DEBUG_EVENT &de)
{
	PEXCEPTION_RECORD record = &(de.u.Exception.ExceptionRecord);
	if (record->ExceptionCode == EXCEPTION_ILLEGAL_INSTRUCTION)
	{
		if (step == 0)//处理第一次lea eax，eax
		{
			step++;
			CONTEXT ct;
			ct.ContextFlags = CONTEXT_FULL;
			GetThreadContext(pi.hThread, &ct);
			ct.Eip += 2;//eip-1

			//跳过lea eax，eax
			PBYTE pbuf = new BYTE[8];
			ReadProcessMemory(pi.hProcess, (LPVOID)(ct.Eip), pbuf, 8, 0);
			for (int i = 0; i < 8; ++i)
			{
				pbuf[i] ^= 0x17;


			}
			WriteProcessMemory(pi.hProcess, (LPVOID)(ct.Eip), pbuf, 8, 0);
			SetThreadContext(pi.hThread, &ct);
			return 1;
		}
		else if (step == 1)//处理第二次lea eax，eax
		{
			CONTEXT ct;
			ct.ContextFlags = CONTEXT_FULL;
			GetThreadContext(pi.hThread, &ct);
			BYTE p[] = { 0x6a,0 };
			WriteProcessMemory(pi.hProcess, (LPVOID)(ct.Eip), p, 2, 0);
			return 1;
		}
		

	}
	return 0;
}


int DebugLoop()
{
	DEBUG_EVENT de;
	int ret;
	while (WaitForDebugEvent(&de, INFINITE))
	{
		switch (de.dwDebugEventCode)
		{
		case CREATE_PROCESS_DEBUG_EVENT:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
			break;
		case EXCEPTION_DEBUG_EVENT:
			ret = onException(de);
			
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
		
			break;
		case EXIT_PROCESS_DEBUG_EVENT:
			return 1;
			break;
		default:
			ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
			break;
		}
	}

}

void parent_process()
{
	int ret;
	WCHAR sz_path[MAX_PATH] = { 0 };
	GetModuleFileName(GetModuleHandle(NULL), sz_path, MAX_PATH);

	STARTUPINFO				si = { sizeof(STARTUPINFO), };
	ret = CreateProcess(
		NULL,
		sz_path,
		NULL, NULL,
		FALSE,
		DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
		NULL, NULL,
		&si,
		&pi);
	if (ret == 0)
	{
		cout << "CreateProcess fail" << endl;
		return;
	}
	DebugLoop();



}


int main() 
{
	HANDLE hmutex;
	hmutex = CreateMutex(NULL, FALSE, DEF_MUTEX_NAME);
	if (hmutex == 0)
	{
		cout << "CreateMutex fail" << endl;
		return -1;
	}
	int ret = GetLastError();
	if (ret == ERROR_ALREADY_EXISTS)//
	{
		MessageBoxW(0, L"开始子进程", 0, 0);
		child_process();
	}
	else
	{
		MessageBoxW(0, L"开始父进程", 0, 0);
		parent_process();
	}
	return 0;
}


