#pragma once

#include "resource.h"

#define WM_CLIENT_LOST         WM_USER+1
#define WM_REMOTE_CONNECT      WM_USER+2
#define WM_REMOTE_LOST         WM_USER+3
#define WM_SYSTEM_STATE        WM_USER+4
#define WM_LOGIN_STATE         WM_USER+5
#define WM_LOGIN_PRIVILEGE     WM_USER+6
#define WM_LOGIN_FAIL_COUNT    WM_USER+7

#define VIDEO_PORT       5000

extern HWND hWndMain;

extern int PRINT(const TCHAR* fmt, ...);

//-----------------------------------------------------------------
// END of File
//-----------------------------------------------------------------