// InetOps
// Copyright (c) 2012-2025 Henry++

#pragma once

#include "routine.h"

#include "resource.h"
#include "app.h"

// libs
#pragma comment(lib, "msimg32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "sensapi.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winmm.lib")
#pragma comment(lib, "wintrust.lib")

#define PING_TIMEOUT 1000

#define DIVIDER_COPY L", "
#define DIVIDER_TRIM L"\r\n "

#define SZ_UNKNOWN L"<unknown>"
#define SZ_HEX L"0x%08X"

#define EX_STYLE LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_INFOTIP | LVS_EX_LABELTIP
#define G_STYLE LVGS_COLLAPSIBLE

#define LANG_SUBMENU 1
#define LANG_MENU 4

#define IL_FOLDER 0
#define IL_FOLDER_CURRENT 1
#define IL_SUCCESS 2
#define IL_FAULT 3

#define PAGE_COUNT 13
#define CATEGORY_COUNT 3
#define WHOIS_COUNT 17

#define IP_ADDRESS L"https://api.ipify.org/?format=text"

typedef struct _STATIC_DATA
{
	HIMAGELIST himglist;
	HICON hfolder;
	HICON hfolder_current;
	HICON hsuccess;
	HICON hfailed;
} STATIC_DATA, *PSTATIC_DATA;

typedef struct _PAGE_LIST
{
	HTREEITEM hitem;
	HWND hpage;

	ULONG_PTR category;

	INT dlg_id;
	INT listview_id;

	INT title;
	INT description;

	BOOLEAN is_thread;
} PAGE_LIST, *PPAGE_LIST;

typedef struct _CATEGORY_LIST
{
	HTREEITEM hitem;

	INT name;
} CATEGORY_LIST, *PCATEGORY_LIST;

typedef struct _WHOIS_LIST
{
	WCHAR server[128];
} WHOIS_LIST, *PWHOIS_LIST;

// https://www.iana.org/domains/root/db
WHOIS_LIST whois_servers[WHOIS_COUNT] = {0};
