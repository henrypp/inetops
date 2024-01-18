// InetOps
// Copyright (c) 2012-2024 Henry++

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
#define SZ_HEX L"0x%06X"

#define EX_STYLE LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_INFOTIP | LVS_EX_LABELTIP
#define G_STYLE LVGS_COLLAPSIBLE

#define LANG_MENU 3

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
	INT title;
	INT description;

	HWND hpage;
	HTREEITEM hitem;

	ULONG_PTR category;

	INT dlg_id;
	INT listview_id;

	BOOLEAN thread;
} PAGE_LIST, *PPAGE_LIST;

typedef struct _CATEGORY_LIST
{
	INT name;
	HTREEITEM hitem;
} CATEGORY_LIST, *PCATEGORY_LIST;

typedef struct _WHOIS_LIST
{
	WCHAR server[128];
} WHOIS_LIST, *PWHOIS_LIST;

// http://www.iana.org/domains/root/db/
WHOIS_LIST whois_servers[WHOIS_COUNT] = {0};

//typedef struct _sockaddr_in {
//        short   sin_family;
//        u_short sin_port;
//        struct  in_addr sin_addr;
//        char    sin_zero[8];
//} sockaddr_in, *psockaddr_in;
//
//typedef struct  _hostent {
//        char    FAR * h_name;           /* official name of host */
//        char    FAR * FAR * h_aliases;  /* alias list */
//        short   h_addrtype;             /* host address type */
//        short   h_length;               /* length of address */
//        char    FAR * FAR * h_addr_list; /* list of addresses */
//#define h_addr  h_addr_list[0]          /* address, for backward compat */
//} hostent, *phostent;
//
//typedef struct _in_addr {
//        union {
//                struct { u_char s_b1,s_b2,s_b3,s_b4; } S_un_b;
//                struct { u_short s_w1,s_w2; } S_un_w;
//                u_long S_addr;
//        } S_un;
//#define s_addr  S_un.S_addr
//                                /* can be used for most tcp & ip code */
//#define s_host  S_un.S_un_b.s_b2
//                                /* host on imp */
//#define s_net   S_un.S_un_b.s_b1
//                                /* network */
//#define s_imp   S_un.S_un_w.s_w2
//                                /* imp */
//#define s_impno S_un.S_un_b.s_b4
//                                /* imp # */
//#define s_lh    S_un.S_un_b.s_b3
//                                /* logical host */
//} in_addr, *pin_addr;
//
//typedef struct _sockaddr {
//        u_short sa_family;              /* address family */
//        char    sa_data[14];            /* up to 14 bytes of direct address */
//} sockaddr, *psockaddr;
