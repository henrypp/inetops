// InetOps
// Copyright (c) 2012-2024 Henry++

#include "routine.h"

#include <windows.h>
#include <wininet.h>
#include <winsock2.h>
#include <ws2def.h>
#include <lmshare.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <lm.h>
#include <inaddr.h>
#include <shlobj.h>
#include <sensapi.h>
#include <strsafe.h>

#include "app.h"
#include "rapp.h"
#include "main.h"

#include "resource.h"

#define APP_HOST L"www.github.com"

STATIC_DATA config = {0};
PAGE_LIST page_list[PAGE_COUNT] = {0};
CATEGORY_LIST category_list[3] = {0};
WSADATA wsa = {0};

INT_PTR WINAPI PageDlgProc (
	_In_ HWND hwnd,
	_In_ UINT msg,
	_In_ WPARAM wparam,
	_In_ LPARAM lparam
);

VOID _app_imagelist_init (
	_In_opt_ HWND hwnd,
	_In_ LONG dpi_value
)
{
	LONG icon_size;

	SAFE_DELETE_ICON (config.hfolder);
	SAFE_DELETE_ICON (config.hfolder_current);
	SAFE_DELETE_ICON (config.hsuccess);
	SAFE_DELETE_ICON (config.hfailed);

	if (!dpi_value)
		dpi_value = _r_dc_getwindowdpi (hwnd);

	icon_size = _r_dc_getsystemmetrics (SM_CXSMICON, dpi_value);

	_r_sys_loadicon (_r_sys_getimagebase (), MAKEINTRESOURCEW (IDI_FOLDER), icon_size, &config.hfolder);
	_r_sys_loadicon (_r_sys_getimagebase (), MAKEINTRESOURCEW (IDI_FOLDER_CURRENT), icon_size, &config.hfolder_current);
	_r_sys_loadicon (_r_sys_getimagebase (), MAKEINTRESOURCEW (IDI_SUCCESS), icon_size, &config.hsuccess);
	_r_sys_loadicon (_r_sys_getimagebase (), MAKEINTRESOURCEW (IDI_FAULT), icon_size, &config.hfailed);

	if (config.himglist)
	{
		ImageList_SetIconSize (config.himglist, icon_size, icon_size);
	}
	else
	{
		config.himglist = ImageList_Create (icon_size, icon_size, ILC_COLOR32 | ILC_HIGHQUALITYSCALE, 0, 5);

		if (config.himglist)
		{
			ImageList_ReplaceIcon (config.himglist, -1, config.hfolder);
			ImageList_ReplaceIcon (config.himglist, -1, config.hfolder_current);
			ImageList_ReplaceIcon (config.himglist, -1, config.hsuccess);
			ImageList_ReplaceIcon (config.himglist, -1, config.hfailed);
		}
	}

	_r_treeview_setimagelist (hwnd, IDC_ITEMLIST, config.himglist);
}

LONG_PTR _app_treeview_custdraw (
	_In_ HWND hwnd,
	_In_ LPNMTVCUSTOMDRAW lptvcd
)
{
	if (lptvcd->nmcd.hdr.idFrom != IDC_ITEMLIST)
		return CDRF_DODEFAULT;

	switch (lptvcd->nmcd.dwDrawStage)
	{
		case CDDS_PREPAINT:
		{
			return (CDRF_NOTIFYPOSTPAINT | CDRF_NOTIFYITEMDRAW);
		}

		case CDDS_ITEMPREPAINT:
		{
			HFONT hfont;
			COLORREF text_clr;
			ULONG weight = 0;
			ULONG underline = 0;

			text_clr = GetSysColor (COLOR_GRAYTEXT);

			if (!lptvcd->iLevel)
			{
				weight = FW_BOLD;
				text_clr = RGB (0, 0, 0);
			}

			if (lptvcd->nmcd.uItemState & CDIS_HOT)
			{
				text_clr = RGB (0, 78, 152);
				underline = 1;
				lptvcd->clrTextBk = RGB (216, 231, 239);
			}

			if (lptvcd->nmcd.uItemState & CDIS_SELECTED)
			{
				text_clr = RGB (0, 0, 0);
				lptvcd->clrTextBk = RGB (171, 208, 228);
			}

			hfont = CreateFontW (
				-11,
				0,
				0,
				0,
				weight,
				0,
				underline,
				0,
				DEFAULT_CHARSET,
				OUT_CHARACTER_PRECIS,
				CLIP_CHARACTER_PRECIS,
				DEFAULT_QUALITY,
				DEFAULT_PITCH,
				0
			);

			SelectObject (lptvcd->nmcd.hdc, hfont);

			DeleteObject (hfont);

			lptvcd->clrText = text_clr;

			return (CDRF_NOTIFYPOSTPAINT | CDRF_NEWFONT);
		}
	}

	return CDRF_DODEFAULT;
}

VOID _app_setpagepos (
	_In_ HWND hwnd,
	_In_ HWND hchild
)
{
	RECT rect;
	INT pos;

	if (!GetWindowRect (GetDlgItem (hwnd, IDC_ITEMLIST), &rect))
		return;

	MapWindowPoints (HWND_DESKTOP, hwnd, (PPOINT)&rect, 2);

	pos = rect.top;

	SetWindowPos (hchild, NULL, _r_calc_rectwidth (&rect) + rect.left * 2, pos, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED | SWP_NOOWNERZORDER);
}

ULONG_PTR _app_getpageid (
	_In_ INT dlg_id
)
{
	for (ULONG_PTR i = 0; i < PAGE_COUNT; i++)
	{
		if (page_list[i].dlg_id == dlg_id)
			return i;
	}

	return 0;
}

ULONG_PTR _app_getcurrentpage (
	_In_ HWND hwnd
)
{
	HTREEITEM hitem;
	LPARAM lparam;

	hitem = (HTREEITEM)SendDlgItemMessageW (hwnd, IDC_ITEMLIST, TVM_GETNEXTITEM, TVGN_CARET, 0);

	if (!_r_treeview_getnextitem (hwnd, IDC_ITEMLIST, hitem, TVGN_PARENT))
		hitem = _r_treeview_getnextitem (hwnd, IDC_ITEMLIST, hitem, TVGN_CHILD);

	if (!hitem)
		return 0;

	lparam = _r_treeview_getitemlparam (hwnd, IDC_ITEMLIST, hitem);

	if (lparam < 0)
		lparam = 0;

	if (lparam >= PAGE_COUNT)
		lparam = PAGE_COUNT - 1;

	return lparam;
}

VOID _app_setcurrentpage (
	_In_ HWND hwnd,
	_In_ ULONG_PTR item_id
)
{
	if (item_id >= PAGE_COUNT)
		item_id = PAGE_COUNT - 1;

	_r_treeview_selectitem (hwnd, IDC_ITEMLIST, page_list[item_id].hitem);
}

NTSTATUS _app_tool_ping (
	_In_ LPVOID lparam
)
{
	SOCKADDR_IN6_LH icmp6_local_addr = {0};
	SOCKADDR_IN6_LH icmp6_remote_addr = {0};
	IP_OPTION_INFORMATION icmp_options = {0};
	PICMP_ECHO_REPLY reply = NULL;
	IPAddr icmp_local_addr = 0;
	IPAddr icmp_remote_addr = 0;
	ADDRINFOW hints = {0};
	R_STRINGREF sr;
	WCHAR buffer[32];
	WCHAR ipaddr[32];
	PR_STRING string;
	PR_BYTE bytes;
	PR_BYTE icmp_echo;
	PADDRINFOW result;
	LPSOCKADDR sockaddr_ip;
	HWND hwnd;
	HANDLE icmp_handle;
	ULONG_PTR page_id;
	ULONG reply_length;
	ULONG length;
	LONG retries;
	INT item_id = 0;
	NTSTATUS status;

	hwnd = (HWND)lparam;

	page_id = _app_getpageid (IDD_PAGE_PING);

	page_list[page_id].thread = TRUE;

	_r_ctrl_setstring (hwnd, IDC_PING_START, L"Abort");
	_r_ctrl_enable (hwnd, IDC_PING_CLEAR, FALSE);

	_r_listview_deleteallitems (hwnd, IDC_PING_RESULT);

	_r_ctrl_enable (hwnd, IDC_HOSTADDR_START, FALSE);
	_r_ctrl_enable (hwnd, IDC_HOSTADDR_CLEAR, FALSE);

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	string = _r_ctrl_getstring (hwnd, IDC_PING_HOST);

	if (!string)
		goto CleanupExit;

	retries = _r_ctrl_getinteger (hwnd, IDC_PING_RETRIES, NULL);

	_r_str_generaterandom (buffer, RTL_NUMBER_OF (buffer), TRUE);

	_r_obj_initializestringref (&sr, buffer);

	status = _r_str_unicode2multibyte (&sr, &icmp_echo);

	if (!NT_SUCCESS (status))
		goto CleanupExit;

	icmp_options.Ttl = UCHAR_MAX;
	icmp_options.Flags = IP_FLAG_DF;

	reply_length = (ULONG)sizeof (ICMP_ECHO_REPLY) + (ULONG)icmp_echo->length + 8 + (ULONG)sizeof (IO_STATUS_BLOCK) + MAX_OPT_SIZE;
	reply = _r_mem_allocate (reply_length);

	for (LONG i = 0; i < retries; i++)
	{
		if (!page_list[page_id].thread)
			break;

		status = GetAddrInfoW (string->buffer, NULL, &hints, &result);

		if (status == ERROR_SUCCESS)
		{
			for (PADDRINFOW ptr = result; ptr; ptr = ptr->ai_next)
			{
				sockaddr_ip = ptr->ai_addr;

				length = RTL_NUMBER_OF (ipaddr);

				status = WSAAddressToStringW (sockaddr_ip, (ULONG)ptr->ai_addrlen, NULL, ipaddr, &length);

				if (status == ERROR_SUCCESS)
				{
					_r_obj_initializestringref (&sr, ipaddr);

					status = _r_str_unicode2multibyte (&sr, &bytes);

					if (!NT_SUCCESS (status))
						goto CleanupExit;

					if (ptr->ai_family == AF_INET)
					{
						icmp_handle = IcmpCreateFile ();

						if (icmp_handle == INVALID_HANDLE_VALUE)
							goto CleanupExit;

						icmp_local_addr = in4addr_any.s_addr;
						icmp_remote_addr = inet_addr (bytes->buffer);

						status = IcmpSendEcho2Ex (
							icmp_handle,
							NULL,
							NULL,
							NULL,
							icmp_local_addr,
							icmp_remote_addr,
							icmp_echo->buffer,
							(WORD)icmp_echo->length,
							&icmp_options,
							reply,
							reply_length,
							PING_TIMEOUT
						);

						switch (reply->Status)
						{
							case IP_SUCCESS:
							{
								_r_listview_additem_ex (hwnd, IDC_PING_RESULT, item_id, ipaddr, IL_SUCCESS, I_GROUPIDNONE, 0);

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d bytes", reply->DataSize);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 1, buffer);

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d", reply->Options.Tos);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 2, buffer);

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d", reply->Options.Ttl);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 3, buffer);

								break;
							}

							case IP_REQ_TIMED_OUT:
							{
								_r_listview_additem_ex (hwnd, IDC_PING_RESULT, item_id, ipaddr, IL_FAULT, I_GROUPIDNONE, 0);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 1, L"Timeout");

								break;
							}

							default:
							{
								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error: %d", reply->Status);
								_r_listview_additem_ex (hwnd, IDC_PING_RESULT, item_id, buffer, IL_FAULT, I_GROUPIDNONE, 0);

								break;
							}
						}

						IcmpCloseHandle (icmp_handle);

						item_id += 1;
					}
					else if (ptr->ai_family == AF_INET6)
					{
						icmp_handle = Icmp6CreateFile ();

						if (icmp_handle == INVALID_HANDLE_VALUE)
							goto CleanupExit;

						status = inet_pton (AF_INET6, bytes->buffer, &icmp6_remote_addr);

						icmp6_local_addr.sin6_addr = in6addr_any;
						icmp6_local_addr.sin6_family = AF_INET6;

						RtlCopyMemory (&icmp6_remote_addr, &icmp6_remote_addr, sizeof (SOCKADDR_IN6_LH));

						status = Icmp6SendEcho2 (
							icmp_handle,
							NULL,
							NULL,
							NULL,
							&icmp6_local_addr,
							&icmp6_remote_addr,
							icmp_echo->buffer,
							(WORD)icmp_echo->length,
							&icmp_options,
							reply,
							reply_length,
							PING_TIMEOUT
						);

						switch (reply->Status)
						{
							case IP_SUCCESS:
							{
								_r_listview_additem_ex (hwnd, IDC_PING_RESULT, item_id, ipaddr, IL_SUCCESS, I_GROUPIDNONE, 0);

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d bytes", reply->DataSize);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 1, buffer);

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d", reply->RoundTripTime);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 2, buffer);

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d", reply->Options.Ttl);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 3, buffer);

								break;
							}

							case IP_REQ_TIMED_OUT:
							{
								_r_listview_additem_ex (hwnd, IDC_PING_RESULT, item_id, ipaddr, IL_FAULT, I_GROUPIDNONE, 0);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 1, L"Timeout");

								break;
							}

							default:
							{
								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error: %d", reply->Status);
								_r_listview_additem_ex (hwnd, IDC_PING_RESULT, item_id, buffer, IL_FAULT, I_GROUPIDNONE, 0);

								break;
							}
						}

						IcmpCloseHandle (icmp_handle);

						item_id += 1;
					}
				}
			}
		}
	}

CleanupExit:

	page_list[page_id].thread = FALSE;

	if (string)
		_r_obj_dereference (string);

	if (reply)
		_r_mem_free (reply);

	_r_ctrl_setstring (hwnd, IDC_PING_START, L"Start");

	_r_ctrl_enable (hwnd, IDC_PING_START, TRUE);
	_r_ctrl_enable (hwnd, IDC_PING_CLEAR, TRUE);

	return STATUS_SUCCESS;
}

NTSTATUS _app_tool_externalip (
	_In_ LPVOID lparam
)
{
	CHAR buffer2[4096] = {0};
	CHAR buffer[256];
	PR_STRING proxy_string;
	PR_STRING address;
	HINTERNET hsession;
	HINTERNET hconnect;
	HINTERNET hrequest;
	HWND hwnd;
	ULONG readed;
	INT item_id = 0;
	BOOLEAN result = FALSE;
	ULONG status;

	hwnd = (HWND)lparam;

	_r_ctrl_enable (hwnd, IDC_IP_REFRESH, FALSE);

	_r_listview_fillitems (hwnd, IDC_IP_RESULT, -1, -1, 1, L"Loading...", I_IMAGENONE);

	proxy_string = _r_app_getproxyconfiguration ();

	hsession = _r_inet_createsession (_r_app_getuseragent (), proxy_string);

	if (!hsession)
	{
		if (proxy_string)
			_r_obj_dereference (proxy_string);

		return STATUS_NETWORK_BUSY;
	}

	address = _r_obj_createstring (IP_ADDRESS);

	status = _r_inet_openurl (hsession, address, &hconnect, &hrequest, NULL);

	if (status = STATUS_SUCCESS)
	{
		if (_r_inet_querystatuscode (hrequest) == HTTP_STATUS_OK)
		{
			while (TRUE)
			{
				RtlZeroMemory (buffer, sizeof (buffer));

				if (_r_inet_readrequest (hrequest, buffer, RTL_NUMBER_OF (buffer), &readed, NULL))
				{
					buffer[readed] = ANSI_NULL;

					StringCchCatA (buffer2, RTL_NUMBER_OF (buffer2), buffer);
				}
				else
				{
					break;
				}

				if (_r_str_isempty2 (buffer))
					break;
			}

			result = TRUE;
		}
	}

	if (!result)
		_r_listview_fillitems (hwnd, IDC_IP_RESULT, -1, -1, 1, L"Error...", IL_FAULT);

	_r_ctrl_enable (hwnd, IDC_IP_REFRESH, TRUE);

	if (proxy_string)
		_r_obj_dereference (proxy_string);

	_r_obj_dereference (address);

	_r_inet_close (hsession);
	_r_inet_close (hconnect);
	_r_inet_close (hrequest);

	return STATUS_SUCCESS;
}

NTSTATUS _app_tool_downloadspeed (
	_In_ LPVOID lparam
)
{
	HINTERNET hsession = NULL;
	HINTERNET hconnect = NULL;
	HINTERNET hrequest = NULL;
	HWND hwnd;
	PR_STRING proxy_string = NULL;
	PR_STRING url;
	SYSTEMTIME st = {0};
	WCHAR buffer[256] = {0};
	PBYTE buff = NULL;
	ULONG_PTR page_id;
	ULONG length;
	ULONG total_size = 0;
	ULONG recieved = 0;
	ULONG temp = 0;
	ULONG seconds = 0;
	ULONG min_speed = 0;
	ULONG max_speed = 0;
	LARGE_INTEGER p1 = {0};
	LARGE_INTEGER p2 = {0};
	LARGE_INTEGER freq = {0};
	ULONG limit;
	ULONG status;

	hwnd = (HWND)lparam;

	limit = _r_ctrl_getinteger (hwnd, IDC_SPEEDMETER_LIMIT, NULL);
	page_id = _app_getpageid (IDD_PAGE_SPEEDMETER);

	_r_ctrl_setstring (hwnd, IDC_SPEEDMETER_START, L"Прервать");
	_r_ctrl_enable (hwnd, IDC_SPEEDMETER_CLEAR, FALSE);

	page_list[page_id].thread = TRUE;

	url = _r_ctrl_getstring (hwnd, IDC_SPEEDMETER_LINK);

	if (!url)
		goto CleanupExit;

	proxy_string = _r_app_getproxyconfiguration ();

	hsession = _r_inet_createsession (_r_app_getuseragent (), proxy_string);

	if (!hsession)
		goto CleanupExit;

	status = _r_inet_openurl (hsession, url, &hconnect, &hrequest, NULL);

	if (status == STATUS_SUCCESS)
	{
		RtlQueryPerformanceCounter (&p1);
		RtlQueryPerformanceCounter (&freq);

		length = PR_SIZE_BUFFER;
		buff = _r_mem_allocate (length);

		while (TRUE)
		{
			if (!page_list[page_id].thread)
				break;

			if (_r_inet_readrequest (hrequest, buff, length, &recieved, &total_size))
			{
				RtlQueryPerformanceCounter (&p2);

				seconds = (ULONG)(((p2.QuadPart - p1.QuadPart) / (freq.QuadPart / 1000LL)) / 1000LL);

				if (seconds)
				{
					temp = (total_size / seconds) / 1024;

					if (!min_speed || temp < min_speed)
						min_speed = temp;

					if (temp > max_speed)
						max_speed = temp;
				}

				_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d kbps", min_speed);
				_r_listview_setitem (hwnd, IDC_SPEEDMETER_RESULT, 0, 1, buffer);

				_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d kbps", (min_speed + max_speed) / 2);
				_r_listview_setitem (hwnd, IDC_SPEEDMETER_RESULT, 1, 2, buffer);

				_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d kbps", max_speed);
				_r_listview_setitem (hwnd, IDC_SPEEDMETER_RESULT, 2, 3, buffer);

				_r_format_number (buffer, RTL_NUMBER_OF (buffer), total_size);
				_r_str_append (buffer, RTL_NUMBER_OF (buffer), L" bytes");

				_r_listview_setitem (hwnd, IDC_SPEEDMETER_RESULT, 5, 5, buffer);
			}
			else
			{
				break;
			}

			if (limit && limit < seconds)
				break;
		}

		_r_mem_free (buff);

		GetLocalTime (&st);

		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
		_r_listview_setitem (hwnd, IDC_SPEEDMETER_RESULT, 6, 2, buffer);
	}
	else
	{
		_r_show_message (hwnd, MB_OK | MB_ICONSTOP, NULL, L"Can't access url.");
	}

CleanupExit:

	if (hsession)
		_r_inet_close (hsession);

	if (hconnect)
		_r_inet_close (hconnect);

	if (hrequest)
		_r_inet_close (hrequest);

	if (proxy_string)
		_r_obj_dereference (proxy_string);

	if (url)
		_r_obj_dereference (url);

	page_list[page_id].thread = FALSE;

	_r_ctrl_setstring (hwnd, IDC_SPEEDMETER_START, L"Start");

	_r_ctrl_enable (hwnd, IDC_SPEEDMETER_START, TRUE);
	_r_ctrl_enable (hwnd, IDC_SPEEDMETER_CLEAR, TRUE);

	return STATUS_SUCCESS;
}

NTSTATUS _app_tool_whois (
	_In_ LPVOID lparam
)
{
	HWND hwnd;
	SOCKET sock = 0;
	SOCKADDR_IN addr = {0};
	PHOSTENT host;
	WSABUF wsa_buffer = {0};
	WCHAR buffer[256] = {0};
	CHAR domain[256] = {0};
	CHAR server[256] = {0};
	PBYTE bytes;
	R_STRINGBUILDER str;
	R_BYTEREF br;
	PR_STRING string;
	ULONG return_length = 0;
	ULONG buffer_sent = 0;
	ULONG flags = 0;
	NTSTATUS status;

	hwnd = (HWND)lparam;

	_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, L"");

	_r_ctrl_enable (hwnd, IDC_WHOIS_START, FALSE);
	_r_ctrl_enable (hwnd, IDC_WHOIS_CLEAR, FALSE);

	_r_obj_initializestringbuilder (&str, 256);

	if (!GetDlgItemTextA (hwnd, IDC_WHOIS_HOST, domain, RTL_NUMBER_OF (domain)) || !GetDlgItemTextA (hwnd, IDC_WHOIS_SERVER, server, RTL_NUMBER_OF (server)))
	{
		_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, L"Необходимо ввести адрес домена и сервер");

		goto CleanupExit;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons (43);
	addr.sin_addr.s_addr = inet_addr (server);

	if (addr.sin_addr.S_un.S_addr == INADDR_NONE)
	{
		host = gethostbyname (server);

		if (!host)
		{
			_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Calling gethostbyname() error: %d\0", WSAGetLastError ());
			_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, buffer);

			goto CleanupExit;
		}

		addr.sin_addr.S_un.S_addr = ((LPIN_ADDR)host->h_addr)->s_addr;
	}

	sock = WSASocketW (AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);

	if (sock == INVALID_SOCKET)
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Calling socket() error: %d", PebLastError ());
		_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, buffer);

		goto CleanupExit;
	}

	if (WSAConnect (sock, (PSOCKADDR)&addr, sizeof (SOCKADDR_IN), NULL, NULL, NULL, NULL) == SOCKET_ERROR)
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Calling WSAConnect() error: %d", PebLastError ());
		_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, buffer);

		goto CleanupExit;
	}

	StringCchCatA (domain, RTL_NUMBER_OF (domain), "\r\n");

	wsa_buffer.buf = domain;
	wsa_buffer.len = (ULONG)strlen (domain);

	status = WSASend (sock, &wsa_buffer, 1, &buffer_sent, 1, NULL, NULL);

	if (status == SOCKET_ERROR)
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Calling WSASend() error: %d", PebLastError ());
		_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, buffer);

		goto CleanupExit;
	}

	bytes = _r_mem_allocate (0x1000);

	while (TRUE)
	{
		wsa_buffer.buf = bytes;
		wsa_buffer.len = 0x1000;

		status = WSARecv (sock, &wsa_buffer, 1, &return_length, &flags, NULL, NULL);

		if (status != SOCKET_ERROR || return_length == 0)
			break;

		_r_obj_initializebyteref (&br, bytes);

		status = _r_str_multibyte2unicode (&br, &string);

		if (NT_SUCCESS (status))
		{
			_r_obj_appendstringbuilder2 (&str, string);

			_r_obj_dereference (string);
		}
	}

	string = _r_obj_finalstringbuilder (&str);

	_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, string->buffer);

	_r_obj_dereference (string);

	_r_mem_free (bytes);

CleanupExit:

	if (sock)
		closesocket (sock);

	_r_ctrl_enable (hwnd, IDC_WHOIS_START, TRUE);
	_r_ctrl_enable (hwnd, IDC_WHOIS_CLEAR, TRUE);

	return STATUS_SUCCESS;
}

VOID _app_tool_urldecoder (
	_In_ HWND hwnd
)
{
	PR_STRING string;
	WCHAR buffer[256];
	ULONG size;
	HRESULT status;

	_r_ctrl_setstring (hwnd, IDC_URLDECODER_RESULT, L"");

	string = _r_ctrl_getstring (hwnd, IDC_URLDECODER_LINK);

	if (!string)
		goto CleanupExit;

	_r_ctrl_enable (hwnd, IDC_URLDECODER_START, FALSE);
	_r_ctrl_enable (hwnd, IDC_URLDECODER_CLEAR, FALSE);

	size = RTL_NUMBER_OF (buffer);

	status = UrlUnescapeW (string->buffer, buffer, &size, URL_ESCAPE_PERCENT);

	if (FAILED (status))
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Can't escape address (0x%08X)", status);

	_r_ctrl_setstring (hwnd, IDC_URLDECODER_RESULT, buffer);

CleanupExit:

	_r_ctrl_enable (hwnd, IDC_URLDECODER_START, TRUE);
	_r_ctrl_enable (hwnd, IDC_URLDECODER_CLEAR, TRUE);
}

VOID _app_getsharedtype (
	_Out_writes_z_ (buffer_size) LPWSTR buffer,
	_In_ _In_range_ (1, PR_SIZE_MAX_STRING_LENGTH) ULONG_PTR buffer_size,
	_In_ ULONG type
)
{
	buffer[0] = UNICODE_NULL;

	if (type & STYPE_DISKTREE)
		_r_str_copy (buffer, buffer_size, L"Disk drive, ");

	if (type & STYPE_PRINTQ)
		_r_str_copy (buffer, buffer_size, L"Print queue, ");

	if (type & STYPE_DEVICE)
		_r_str_copy (buffer, buffer_size, L"Communication device, ");

	if (type & STYPE_IPC)
		_r_str_append (buffer, buffer_size, L"IPC, ");

	if (type & STYPE_SPECIAL)
		_r_str_append (buffer, buffer_size, L"Special share, ");

	if (type & STYPE_TEMPORARY)
		_r_str_append (buffer, buffer_size, L"Temporary share, ");

	_r_str_trim (buffer, L", ");

	if (!buffer[0])
		_r_str_printf (buffer, buffer_size, SZ_HEX, type);
}

VOID _app_tool_sharedinfo (
	_In_ HWND hwnd
)
{
	WCHAR buffer[256];
	PSHARE_INFO_502 share_info = NULL;
	PSHARE_INFO_502 p;
	ULONG readed;
	ULONG resume_handle = 0;
	ULONG total;
	INT item_id = 0;
	NET_API_STATUS status;

	_r_listview_deleteallitems (hwnd, IDC_SHAREDINFO);

	do
	{
		status = NetShareEnum (
			NULL,
			502,
			(LPBYTE*)&share_info,
			MAX_PREFERRED_LENGTH,
			&readed,
			&total,
			&resume_handle
		);

		if (status == ERROR_SUCCESS || status == ERROR_MORE_DATA)
		{
			p = share_info;

			for (ULONG i = 1; i <= readed; i++)
			{
				_r_listview_additem_ex (hwnd, IDC_SHAREDINFO, item_id, p->shi502_netname, IL_SUCCESS, I_GROUPIDNONE, 0);
				_r_listview_setitem (hwnd, IDC_SHAREDINFO, item_id, 1, p->shi502_path[0] ? p->shi502_path : SZ_UNKNOWN);

				_app_getsharedtype (buffer, RTL_NUMBER_OF (buffer), p->shi502_type);
				_r_listview_setitem (hwnd, IDC_SHAREDINFO, item_id, 2, buffer);

				if (p->shi502_max_uses == -1)
					_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"unlimited");

				_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d/%s", p->shi502_current_uses, buffer);
				_r_listview_setitem (hwnd, IDC_SHAREDINFO, item_id, 3, buffer);

				item_id += 1;

				p++;
			}

			NetApiBufferFree (share_info);
		}
	}
	while (status == ERROR_MORE_DATA);
}

VOID _app_tool_sysinfo (
	_In_ HWND hwnd
)
{
	RTL_OSVERSIONINFOEXW version_info;
	R_STRINGREF sr;
	PFIXED_INFO network_params;
	PR_STRING username;
	WCHAR buffer[128];
	WCHAR type[256] = {0};
	ULONG length;
	ULONG flags = 0;
	SOCKET sock;
	INT item_id = 0;
	NTSTATUS status;

	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d.%d", LOBYTE (wsa.wVersion), HIBYTE (wsa.wVersion));
	_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, buffer);

	status = RtlGetVersion (&version_info);

	if (NT_SUCCESS (status))
	{
		_r_str_printf (
			buffer,
			RTL_NUMBER_OF (buffer),
			L"%d.%d build %d",
			version_info.dwMajorVersion,
			version_info.dwMinorVersion,
			version_info.dwBuildNumber
		);

		_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, buffer);
	}

	if (IsNetworkAlive (&flags))
	{
		if (flags & NETWORK_ALIVE_LAN)
			_r_str_append (type, RTL_NUMBER_OF (type), L"LAN, ");

		if (flags & NETWORK_ALIVE_WAN)
			_r_str_append (type, RTL_NUMBER_OF (type), L"WAN, ");

		_r_str_trim (type, L", ");

		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Enabled (%s)", type);
	}
	else
	{
		_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"No connection");
	}

	_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, buffer);

	length = sizeof (FIXED_INFO) * 2;
	network_params = _r_mem_allocate (length);

	if (GetNetworkParams (network_params, &length) == ERROR_BUFFER_OVERFLOW)
		_r_mem_reallocate (&network_params, length);

	if (GetNetworkParams (network_params, &length) == NO_ERROR)
	{
		switch (network_params->NodeType)
		{
			case BROADCAST_NODETYPE:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Broadcast");
				break;
			}

			case PEER_TO_PEER_NODETYPE:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"P2P");
				break;
			}

			case MIXED_NODETYPE:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Mixed");
				break;
			}

			case HYBRID_NODETYPE:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Hybrid");
				break;
			}

			default:
			{
				_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Unknown (%d)", network_params->NodeType);
				break;
			}
		}

		_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, buffer);

		_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, network_params->EnableRouting ? L"On" : L"Off");
		_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, network_params->EnableProxy ? L"On" : L"Off");
		_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, network_params->EnableDns ? L"On" : L"Off");
	}
	else
	{
		_r_listview_fillitems (hwnd, IDC_SYSINFO, -1, -1, 1, L"n/a", IL_FAULT);
		item_id += 4;
	}

	if (network_params)
		_r_mem_free (network_params);

	sock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP); // IPv4

	_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, (PebLastError () == WSAEAFNOSUPPORT) ? L"Off" : L"On");
	closesocket (sock);

	sock = socket (AF_INET6, SOCK_STREAM, IPPROTO_TCP); // IPv6

	_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, (PebLastError () == WSAEAFNOSUPPORT) ? L"Off" : L"On");
	closesocket (sock);

	_r_obj_initializestringref (&sr, L"%USERNAME%");

	status = _r_str_environmentexpandstring (&sr, &username);

	if (NT_SUCCESS (status))
	{
		_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, username->buffer);

		_r_obj_dereference (username);
	}
	else
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error (0x%08x)", status);

		_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, buffer);
	}

	flags = RTL_NUMBER_OF (buffer);
	GetComputerNameExW (ComputerNameDnsHostname, buffer, &flags);

	_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, buffer);
}

VOID _app_tool_hostaddress (
	_In_ HWND hwnd
)
{
	PR_STRING url;
	WCHAR buffer[256];
	PADDRINFOW result;
	ADDRINFOW hints = {0};
	WCHAR ipaddr[100];
	ULONG length;
	LPSOCKADDR sockaddr_ip;
	INT item_id = 0;

	_r_listview_deleteallitems (hwnd, IDC_HOSTADDR_RESULT);

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	url = _r_ctrl_getstring (hwnd, IDC_HOSTADDR_HOST);

	if (!url)
		return;

	_r_ctrl_enable (hwnd, IDC_HOSTADDR_START, FALSE);
	_r_ctrl_enable (hwnd, IDC_HOSTADDR_CLEAR, FALSE);

	if (GetAddrInfoW (url->buffer, NULL, &hints, &result) == ERROR_SUCCESS)
	{
		for (PADDRINFOW ptr = result; ptr; ptr = ptr->ai_next)
		{
			sockaddr_ip = ptr->ai_addr;

			length = RTL_NUMBER_OF (ipaddr);

			if (WSAAddressToStringW (sockaddr_ip, (ULONG)ptr->ai_addrlen, NULL, ipaddr, &length) == ERROR_SUCCESS)
			{
				if (ptr->ai_family == AF_INET)
				{
					_r_listview_additem_ex (hwnd, IDC_HOSTADDR_RESULT, item_id, ipaddr, IL_SUCCESS, 0, 0);
				}
				else if (ptr->ai_family == AF_INET6)
				{
					_r_listview_additem_ex (hwnd, IDC_HOSTADDR_RESULT, item_id, ipaddr, IL_SUCCESS, 1, 0);
				}
				else
				{
					_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%s (%d)", ipaddr, ptr->ai_family);

					_r_listview_additem_ex (hwnd, IDC_HOSTADDR_RESULT, item_id, buffer, IL_SUCCESS, 2, 0);
				}

				item_id += 1;
			}
		}
	}
	else
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Can't get IP of host (0x%08x)", PebLastError ());
	}

	FreeAddrInfoW (result);

	_r_obj_dereference (url);

	_r_ctrl_enable (hwnd, IDC_HOSTADDR_START, TRUE);
	_r_ctrl_enable (hwnd, IDC_HOSTADDR_CLEAR, TRUE);
}

NTSTATUS _app_tool_urlinfo (
	_In_ LPVOID lparam
)
{
	PR_STRING proxy_string;
	PR_STRING string;
	PR_STRING url;
	SYSTEMTIME st = {0};
	HINTERNET hsession;
	HINTERNET hconnect;
	HINTERNET hrequest;
	HWND hwnd;
	WCHAR buffer[256] = {0};
	LONG64 timestamp;
	ULONG flags = 0;
	ULONG length;
	ULONG status;
	INT item_id = 0;
	BOOL result;

	hwnd = (HWND)lparam;

	_r_ctrl_setstring (hwnd, IDC_URLINFO_HEADER, NULL);

	url = _r_ctrl_getstring (hwnd, IDC_URLINFO_LINK);

	proxy_string = _r_app_getproxyconfiguration ();

	hsession = _r_inet_createsession (_r_app_getuseragent (), proxy_string);

	if (!hsession)
	{
		_r_show_errormessage (hwnd, NULL, PebLastError (), L"Произошла ошибка при создания сессии", FALSE);

		return STATUS_SUCCESS;
	}

	_r_ctrl_enable (hwnd, IDC_URLINFO_START, FALSE);
	_r_ctrl_enable (hwnd, IDC_URLINFO_CLEAR, FALSE);

	status = _r_inet_openurl (hsession, url, &hconnect, &hrequest, NULL);

	if (status != STATUS_SUCCESS)
	{
		_r_show_errormessage (hwnd, NULL, status, L"Произошла ошибка при открытии ссылки", FALSE);
	}
	else
	{
		length = sizeof (buffer);

		if (WinHttpQueryOption (hrequest, WINHTTP_QUERY_RAW_HEADERS_CRLF, &buffer, &length))
			_r_ctrl_setstring (hwnd, IDC_URLINFO_HEADER, buffer);
	}

	length = sizeof (flags);

	if (WinHttpQueryOption (hrequest, WINHTTP_QUERY_FLAG_NUMBER | WINHTTP_QUERY_CONTENT_LENGTH, &flags, &length))
	{
		StrFormatByteSizeW (flags, buffer, RTL_NUMBER_OF (buffer));

		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, buffer);
	}
	else
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, L"no");
	}

	length = sizeof (st);

	timestamp = _r_inet_querylastmodified (hrequest);

	string = _r_format_unixtime (timestamp, 0);

	if (timestamp && string)
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, string->buffer);
	}
	else
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, L"no");
	}

	length = sizeof (buffer);
	result = WinHttpQueryOption (hrequest, WINHTTP_QUERY_ACCEPT_RANGES, &buffer, &length);

	_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, result ? L"Supported" : L"Unsupported");

	length = sizeof (buffer);

	if (WinHttpQueryOption (hrequest, WINHTTP_QUERY_CONTENT_TYPE, &buffer, &length))
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, buffer);
	}
	else
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, L"no");
	}

	length = sizeof (buffer);

	if (WinHttpQueryOption (hrequest, WINHTTP_QUERY_ETAG, &buffer, &length))
	{
		_r_str_trim (buffer, L"\""); // Strip Quotes

		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, buffer);
	}
	else
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, L"no");
	}

	length = sizeof (buffer);

	if (WinHttpQueryOption (hrequest, WINHTTP_QUERY_VERSION, &buffer, &length))
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, buffer);
	}
	else
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, L"no");
	}

	length = sizeof (buffer);

	if (WinHttpQueryOption (hrequest, WINHTTP_QUERY_SERVER, &buffer, &length))
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, buffer);
	}
	else
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, L"no");
	}

	length = sizeof (flags);

	status = _r_inet_querystatuscode (hrequest);

	_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d", status);

	_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, buffer);

	if (proxy_string)
		_r_obj_dereference (proxy_string);

	if (string)
		_r_obj_dereference (string);

	if (url)
		_r_obj_dereference (url);

	_r_inet_close (hsession);

	if (hconnect)
		_r_inet_close (hconnect);

	if (hrequest)
		_r_inet_close (hrequest);

	_r_ctrl_enable (hwnd, IDC_URLINFO_START, TRUE);
	_r_ctrl_enable (hwnd, IDC_URLINFO_CLEAR, TRUE);

	return STATUS_SUCCESS;
}

VOID _app_print_tcpstats (
	_In_ HWND hwnd,
	_Out_ PMIB_TCPSTATS2 stats,
	_In_ ULONG family
)
{
	WCHAR buffer[100];
	ULONG status;
	INT item_id = 0;

	status = GetTcpStatisticsEx2 (stats, AF_INET);

	if (status != NO_ERROR)
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error: " SZ_HEX, status);

		_r_listview_fillitems (hwnd, IDC_IP_STATISTIC, 0, 15, 1, buffer, IL_FAULT);
	}
	else
	{
		switch (stats->RtoAlgorithm)
		{
			case TcpRtoAlgorithmOther:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Other (1)");
				break;
			}

			case TcpRtoAlgorithmConstant:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Constant time-out (2)");
				break;
			}

			case TcpRtoAlgorithmRsre:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"MIL-STD-1778 (3)");
				break;
			}

			case TcpRtoAlgorithmVanj:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Van Jacobson's algorithm (4)");
				break;
			}

			default:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"[unknown]");
				break;
			}
		}

		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwRtoMin);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwRtoMax);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dw64InSegs);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dw64OutSegs);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwRetransSegs);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwOutRsts);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInErrs);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwAttemptFails);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwActiveOpens);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwPassiveOpens);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwCurrEstab);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwEstabResets);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		if (stats->dwMaxConn == -1)
		{
			_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Variable");
		}
		else
		{
			_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwMaxConn);
		}

		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwNumConns);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);
	}

	status = GetTcpStatisticsEx2 (stats, AF_INET6);

	item_id = 15;

	if (status != NO_ERROR)
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error: " SZ_HEX, status);

		_r_listview_fillitems (hwnd, IDC_IP_STATISTIC, 15, 30, 1, buffer, IL_FAULT);
	}
	else
	{
		switch (stats->RtoAlgorithm)
		{
			case MIB_TCP_RTO_OTHER:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Other (1)");
				break;
			}

			case MIB_TCP_RTO_CONSTANT:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Constant time-out (2)");
				break;
			}

			case MIB_TCP_RTO_RSRE:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"MIL-STD-1778 (3)");
				break;
			}

			case MIB_TCP_RTO_VANJ:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Van Jacobson's algorithm (4)");
				break;
			}
		}

		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwRtoMin);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwRtoMax);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dw64InSegs);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dw64OutSegs);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwRetransSegs);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwOutRsts);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInErrs);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwAttemptFails);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwActiveOpens);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwPassiveOpens);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwCurrEstab);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwEstabResets);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		if (stats->dwMaxConn == -1)
		{
			_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Variable");
		}
		else
		{
			_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwMaxConn);
		}

		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwNumConns);
		_r_listview_setitem (hwnd, IDC_TCP_STATISTIC, item_id++, 1, buffer);
	}
}

VOID _app_print_udpstats (
	_In_ HWND hwnd,
	_Out_ PMIB_UDPSTATS2 stats,
	_In_ ULONG family
)
{
	WCHAR buffer[100];
	ULONG status;
	INT item_id = 0;

	status = GetUdpStatisticsEx2 (stats, AF_INET);

	if (status != NO_ERROR)
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error: " SZ_HEX, status);

		_r_listview_fillitems (hwnd, IDC_UDP_STATISTIC, 0, 5, 1, buffer, IL_FAULT);
	}
	else
	{
		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dw64InDatagrams);
		_r_listview_setitem (hwnd, IDC_UDP_STATISTIC, item_id, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInErrors);
		_r_listview_setitem (hwnd, IDC_UDP_STATISTIC, item_id + 1, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwNoPorts);
		_r_listview_setitem (hwnd, IDC_UDP_STATISTIC, item_id + 2, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dw64OutDatagrams);
		_r_listview_setitem (hwnd, IDC_UDP_STATISTIC, item_id + 3, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwNumAddrs);
		_r_listview_setitem (hwnd, IDC_UDP_STATISTIC, item_id + 4, 1, buffer);
	}

	status = GetUdpStatisticsEx2 (stats, AF_INET6);

	item_id = 5;

	if (status != NO_ERROR)
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error: " SZ_HEX, status);
		_r_listview_fillitems (hwnd, IDC_UDP_STATISTIC, 5, 10, 1, buffer, IL_FAULT);
	}
	else
	{
		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dw64InDatagrams);
		_r_listview_setitem (hwnd, IDC_UDP_STATISTIC, item_id, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInErrors);
		_r_listview_setitem (hwnd, IDC_UDP_STATISTIC, item_id + 1, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwNoPorts);
		_r_listview_setitem (hwnd, IDC_UDP_STATISTIC, item_id + 2, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dw64OutDatagrams);
		_r_listview_setitem (hwnd, IDC_UDP_STATISTIC, item_id + 3, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwNumAddrs);
		_r_listview_setitem (hwnd, IDC_UDP_STATISTIC, item_id + 4, 1, buffer);
	}
}

VOID _app_print_icmpstats (
	_In_ HWND hwnd,
	_Out_ PMIB_ICMP_EX_XPSP1 stats,
	_In_ ULONG family
)
{
	WCHAR buffer[128];
	ULONG status;
	INT item_id = 0;

	status = GetIcmpStatisticsEx (stats, AF_INET);

	if (status != NO_ERROR)
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error: " SZ_HEX, status);

		_r_listview_fillitems (hwnd, IDC_ICMP_STATISTIC, 0, 4, 1, buffer, IL_FAULT);
	}
	else
	{
		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->icmpInStats.dwMsgs);
		_r_listview_setitem (hwnd, IDC_ICMP_STATISTIC, item_id, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->icmpOutStats.dwErrors);
		_r_listview_setitem (hwnd, IDC_ICMP_STATISTIC, item_id + 1, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->icmpOutStats.dwMsgs);
		_r_listview_setitem (hwnd, IDC_ICMP_STATISTIC, item_id + 2, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->icmpOutStats.dwErrors);
		_r_listview_setitem (hwnd, IDC_ICMP_STATISTIC, item_id + 3, 1, buffer);
	}

	status = GetIcmpStatisticsEx (stats, AF_INET6);

	item_id = 4;

	if (status != NO_ERROR)
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error: " SZ_HEX, status);
		_r_listview_fillitems (hwnd, IDC_ICMP_STATISTIC, 4, 8, 1, buffer, IL_FAULT);
	}
	else
	{
		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->icmpInStats.dwMsgs);
		_r_listview_setitem (hwnd, IDC_ICMP_STATISTIC, item_id, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->icmpOutStats.dwErrors);
		_r_listview_setitem (hwnd, IDC_ICMP_STATISTIC, item_id + 1, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->icmpOutStats.dwMsgs);
		_r_listview_setitem (hwnd, IDC_ICMP_STATISTIC, item_id + 2, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->icmpOutStats.dwErrors);
		_r_listview_setitem (hwnd, IDC_ICMP_STATISTIC, item_id + 3, 1, buffer);
	}
}

VOID _app_print_ipstats (
	_In_ HWND hwnd,
	_Out_ PMIB_IPSTATS_LH stats,
	_In_ ULONG family
)
{
	WCHAR buffer[100];
	ULONG status;
	INT item_id = 0;

	status = GetIpStatisticsEx (stats, AF_INET);

	if (status != NO_ERROR)
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error: " SZ_HEX, status);

		_r_listview_fillitems (hwnd, IDC_IP_STATISTIC, 0, 23, 1, buffer, IL_FAULT);
	}
	else
	{
		switch (stats->dwForwarding)
		{
			case MIB_IP_FORWARDING:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"On");
				break;
			}

			case MIB_IP_NOT_FORWARDING:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Off");
				break;
			}

			case MIB_USE_CURRENT_FORWARDING:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Use the current IP forwarding");
				break;
			}

			default:
			{
				_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"n/a (0x%08x)", stats->dwForwarding);
				break;
			}
		}

		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwForwDatagrams);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInReceives);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInHdrErrors);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInAddrErrors);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInUnknownProtos);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInDiscards);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwRoutingDiscards);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwOutDiscards);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwOutNoRoutes);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwReasmOks);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwReasmFails);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwReasmReqds);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwFragOks);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwFragFails);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwFragCreates);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwReasmTimeout);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInDelivers);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwOutRequests);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwDefaultTTL);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwNumIf);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwNumAddr);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwNumRoutes);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);
	}

	status = GetIpStatisticsEx (stats, AF_INET6);

	item_id = 23;

	if (status != NO_ERROR)
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error: " SZ_HEX, status);

		_r_listview_fillitems (hwnd, IDC_IP_STATISTIC, 23, 66, 1, buffer, IL_FAULT);
	}
	else
	{
		switch (stats->dwForwarding)
		{
			case MIB_IP_FORWARDING:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"On");
				break;
			}

			case MIB_IP_NOT_FORWARDING:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Off");
				break;
			}

			case MIB_USE_CURRENT_FORWARDING:
			{
				_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Use the current IP forwarding");
				break;
			}

			default:
			{
				_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"n/a (0x%08x)", stats->dwForwarding);
				break;
			}
		}

		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwForwDatagrams);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInReceives);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInHdrErrors);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInAddrErrors);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInUnknownProtos);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInDiscards);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwRoutingDiscards);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwOutDiscards);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwOutNoRoutes);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwReasmOks);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwReasmFails);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwReasmReqds);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwFragOks);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwFragFails);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwFragCreates);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwReasmTimeout);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwInDelivers);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwOutRequests);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwDefaultTTL);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwNumIf);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwNumAddr);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);

		_r_format_number (buffer, RTL_NUMBER_OF (buffer), stats->dwNumRoutes);
		_r_listview_setitem (hwnd, IDC_IP_STATISTIC, item_id++, 1, buffer);
	}
}

VOID CALLBACK TimerProc (
	_In_ HWND hwnd,
	_In_ UINT msg,
	_In_ UINT_PTR id_event,
	_In_ ULONG time
)
{
	MIB_TCPSTATS2 tcp_stat;
	MIB_UDPSTATS2 udp_stat;
	MIB_ICMP_EX icmp_stat;
	MIB_IPSTATS ip_stat;
	ULONG_PTR dlg_id;

	if (id_event != 1337)
		return;

	dlg_id = _app_getcurrentpage (hwnd);

	hwnd = page_list[dlg_id].hpage;

	switch (page_list[dlg_id].dlg_id)
	{
		case IDD_PAGE_TCP_STATISTIC:
		{
			_app_print_tcpstats (hwnd, &tcp_stat, AF_INET);
			_app_print_tcpstats (hwnd, &tcp_stat, AF_INET6);

			break;
		}

		case IDD_PAGE_UDP_STATISTIC:
		{
			_app_print_udpstats (hwnd, &udp_stat, AF_INET);
			_app_print_udpstats (hwnd, &udp_stat, AF_INET6);

			break;
		}

		case IDD_PAGE_ICMP_STATISTIC:
		{
			_app_print_icmpstats (hwnd, &icmp_stat, AF_INET);
			_app_print_icmpstats (hwnd, &icmp_stat, AF_INET6);

			break;
		}

		case IDD_PAGE_IP_STATISTIC:
		{
			_app_print_ipstats (hwnd, &ip_stat, AF_INET);
			_app_print_ipstats (hwnd, &ip_stat, AF_INET6);

			break;
		}
	}
}

VOID _app_initializepages (
	_In_ HWND hwnd
)
{
	ULONG_PTR idx = 0;

	// whois servers
	_r_str_copy (whois_servers[idx++].server, RTL_NUMBER_OF (whois_servers[idx].server), L"whois.verisign-grs.com");
	_r_str_copy (whois_servers[idx++].server, RTL_NUMBER_OF (whois_servers[idx].server), L"whois.dotgov.gov");
	_r_str_copy (whois_servers[idx++].server, RTL_NUMBER_OF (whois_servers[idx].server), L"whois.afilias.net");
	_r_str_copy (whois_servers[idx++].server, RTL_NUMBER_OF (whois_servers[idx].server), L"whois.nic.kz");
	_r_str_copy (whois_servers[idx++].server, RTL_NUMBER_OF (whois_servers[idx].server), L"whois.nic.name");
	_r_str_copy (whois_servers[idx++].server, RTL_NUMBER_OF (whois_servers[idx].server), L"whois.pir.org");
	_r_str_copy (whois_servers[idx++].server, RTL_NUMBER_OF (whois_servers[idx].server), L"whois.pir.org");
	_r_str_copy (whois_servers[idx++].server, RTL_NUMBER_OF (whois_servers[idx].server), L"whois.tcinet.ru");
	_r_str_copy (whois_servers[idx++].server, RTL_NUMBER_OF (whois_servers[idx].server), L"whois.ua");
	_r_str_copy (whois_servers[idx++].server, RTL_NUMBER_OF (whois_servers[idx].server), L"whois.website.ws");

	// categories
	idx = 0;

	category_list[idx++].name = IDS_CATEGORY_TOOLS;
	category_list[idx++].name = IDS_CATEGORY_INFORMATION;
	category_list[idx++].name = IDS_CATEGORY_STATISTICS;

	// pages
	idx = 0;

	page_list[idx].dlg_id = IDD_PAGE_PING;
	page_list[idx].listview_id = IDC_PING_RESULT;

	page_list[idx].title = IDS_TOOL_PING;
	page_list[idx].description = IDS_TOOL_PING_INFO;

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_SPEEDMETER;
	page_list[idx].listview_id = IDC_SPEEDMETER_RESULT;

	page_list[idx].title = IDS_TOOL_SPEED;
	page_list[idx].description = IDS_TOOL_SPEED_INFO;

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_URLDECODER;

	page_list[idx].title = IDS_TOOL_DECODER;
	page_list[idx].description = IDS_TOOL_DECODER_INFO;

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_URLINFO;

	page_list[idx].title = IDS_TOOL_INFORMATION;
	page_list[idx].description = IDS_TOOL_INFORMATION_INFO;

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_HOSTADDR;
	page_list[idx].listview_id = IDC_HOSTADDR_RESULT;

	page_list[idx].title = IDS_TOOL_HOSTADDRESS;
	page_list[idx].description = IDS_TOOL_HOSTADDRESS_INFO;

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_WHOIS;

	page_list[idx].title = IDS_TOOL_WHOIS;
	page_list[idx].description = IDS_TOOL_WHOIS_INFO;

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_IP;
	page_list[idx].category = 1;

	page_list[idx].title = IDS_TOOL_IP;
	page_list[idx].description = IDS_TOOL_IP_INFO;

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_SHAREDINFO;
	page_list[idx].listview_id = IDC_SHAREDINFO;
	page_list[idx].category = 1;

	page_list[idx].title = IDS_TOOL_SHARED;
	page_list[idx].description = IDS_TOOL_SHARED_INFO;

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_SYSINFO;
	page_list[idx].listview_id = IDC_SYSINFO;
	page_list[idx].category = 1;

	page_list[idx].title = IDS_TOOL_SYSTEM;
	page_list[idx].description = IDS_TOOL_SYSTEM_INFO;

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_TCP_STATISTIC;
	page_list[idx].listview_id = IDC_TCP_STATISTIC;
	page_list[idx].category = 2;

	page_list[idx].title = IDS_TOOL_TCP;
	page_list[idx].description = IDS_TOOL_TCP_INFO;

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_UDP_STATISTIC;
	page_list[idx].listview_id = IDC_UDP_STATISTIC;
	page_list[idx].category = 2;

	page_list[idx].title = IDS_TOOL_UDP;
	page_list[idx].description = IDS_TOOL_UDP_INFO;

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_ICMP_STATISTIC;
	page_list[idx].listview_id = IDC_ICMP_STATISTIC;
	page_list[idx].category = 2;

	page_list[idx].title = IDS_TOOL_ICMP;
	page_list[idx].description = IDS_TOOL_ICMP_INFO;

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_IP_STATISTIC;
	page_list[idx].listview_id = IDC_IP_STATISTIC;
	page_list[idx].category = 2;

	page_list[idx].title = IDS_TOOL_IPSTATS;
	page_list[idx].description = IDS_TOOL_IPSTATS_INFO;

	for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (category_list); i++)
	{
		category_list[i].hitem = _r_treeview_additem (hwnd, IDC_ITEMLIST, _r_locale_getstring (category_list[i].name), IL_FOLDER, TVIS_EXPANDED, NULL, NULL, -1);
	}

	for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (page_list); i++)
	{
		page_list[i].hitem = _r_treeview_additem (
			hwnd,
			IDC_ITEMLIST,
			_r_locale_getstring (page_list[i].title),
			IL_FOLDER,
			0,
			category_list[page_list[i].category].hitem,
			NULL,
			(LPARAM)i
		);

		page_list[i].hpage = _r_wnd_createwindow (_r_sys_getimagebase (), MAKEINTRESOURCEW (page_list[i].dlg_id), hwnd, &PageDlgProc, NULL);

		if (page_list[i].hpage)
			_app_setpagepos (hwnd, page_list[i].hpage);
	}
}

VOID _app_initializepage (
	_In_ HWND hwnd,
	_In_ INT page_id
)
{
	INT width;
	INT item_id;

	//if (!IsWindowVisible (GetDlgItem (hwnd, page_id)))
	//	return;

	switch (page_id)
	{
		case IDD_PAGE_PING:
		{
			SendDlgItemMessageW (hwnd, IDC_PING_UPDOWN, UDM_SETRANGE32, 1, 1000);

			_r_ctrl_setstring (hwnd, IDC_PING_HOST, _r_obj_getstring (_r_config_getstring (L"PingAddress", APP_HOST)));

			SetDlgItemInt (hwnd, IDC_PING_RETRIES, _r_config_getlong (L"PingRetries", 5), TRUE);

			_r_listview_setstyle (hwnd, IDC_PING_RESULT, EX_STYLE, FALSE);

			_r_listview_setimagelist (hwnd, IDC_PING_RESULT, config.himglist);

			_r_listview_addcolumn (hwnd, IDC_PING_RESULT, 0, L"Address", 190, 0);
			_r_listview_addcolumn (hwnd, IDC_PING_RESULT, 1, L"Size", 100, 0);
			_r_listview_addcolumn (hwnd, IDC_PING_RESULT, 2, L"Delay", 80, 0);
			_r_listview_addcolumn (hwnd, IDC_PING_RESULT, 3, L"TTL", 80, 0);

			break;
		}

		case IDD_PAGE_SPEEDMETER:
		{
			_r_listview_setstyle (hwnd, IDC_SPEEDMETER_RESULT, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_SPEEDMETER_RESULT, config.himglist);

			width = _r_ctrl_getwidth (hwnd, IDC_SPEEDMETER_RESULT);

			_r_listview_addcolumn (hwnd, IDC_SPEEDMETER_RESULT, 0, L"Parameter", width / 2, 0);
			_r_listview_addcolumn (hwnd, IDC_SPEEDMETER_RESULT, 1, L"Value", width / 2, 0);

			_r_listview_addgroup (hwnd, IDC_SPEEDMETER_RESULT, 0, L"Speed", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_SPEEDMETER_RESULT, 1, L"Time", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_SPEEDMETER_RESULT, 2, L"Other", 0, G_STYLE, G_STYLE);

			item_id = 0;

			_r_listview_additem_ex (hwnd, IDC_SPEEDMETER_RESULT, item_id++, L"Minimum", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_SPEEDMETER_RESULT, item_id++, L"Average", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_SPEEDMETER_RESULT, item_id++, L"Maximum", IL_SUCCESS, 0, 0);

			_r_listview_additem_ex (hwnd, IDC_SPEEDMETER_RESULT, item_id++, L"Test started", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_SPEEDMETER_RESULT, item_id++, L"Test finished", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_SPEEDMETER_RESULT, item_id++, L"Execution time", IL_SUCCESS, 1, 0);

			_r_listview_additem_ex (hwnd, IDC_SPEEDMETER_RESULT, item_id++, L"Recieved data length", IL_SUCCESS, 2, 0);

			_r_ctrl_setstring (hwnd, IDC_SPEEDMETER_LINK, _r_obj_getstring (_r_config_getstring (L"SpeedmeterLink", APP_HOST)));

			SendDlgItemMessageW (hwnd, IDC_SPEEDMETER_UPDOWN, UDM_SETRANGE32, 0, 1000);

			SetDlgItemInt (hwnd, IDC_SPEEDMETER_LIMIT, _r_config_getlong (L"SpeedMeterLimit", 10), TRUE);

			break;
		}

		case IDD_PAGE_URLDECODER:
		{
			_r_ctrl_setstring (
				hwnd,
				IDC_URLDECODER_LINK,
				_r_obj_getstring (_r_config_getstring (L"UrlDecoderLink", L"%22%23%24%25%26%27%28%29%2A%2C%3B%3F%5B%5D%5E%60%7B%7D"))
			);

			break;
		}

		case IDD_PAGE_HOSTADDR:
		{
			_r_ctrl_setstring (hwnd, IDC_HOSTADDR_HOST, _r_obj_getstring (_r_config_getstring (L"HostAddrAddress", APP_HOST)));

			_r_listview_setstyle (hwnd, IDC_HOSTADDR_RESULT, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_HOSTADDR_RESULT, config.himglist);

			width = _r_ctrl_getwidth (hwnd, IDC_HOSTADDR_RESULT);

			_r_listview_addcolumn (hwnd, IDC_HOSTADDR_RESULT, 0, L"Parameter", width, 0);

			_r_listview_addgroup (hwnd, IDC_HOSTADDR_RESULT, 0, L"IPv4", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_HOSTADDR_RESULT, 1, L"IPv6 ", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_HOSTADDR_RESULT, 2, L"Other ", 0, G_STYLE, G_STYLE);

			break;
		}

		case IDD_PAGE_WHOIS:
		{
			_r_ctrl_setstring (hwnd, IDC_WHOIS_HOST, _r_obj_getstring (_r_config_getstring (L"WhoisAddress", APP_HOST)));

			for (ULONG_PTR i = 0; i < WHOIS_COUNT; i++)
				SendDlgItemMessageW (hwnd, IDC_WHOIS_SERVER, CB_ADDSTRING, 0, (LPARAM)whois_servers[i].server);

			item_id = _r_config_getlong (L"WhoisServer", 0);

			if (item_id == CB_ERR)
			{
				_r_ctrl_setstring (hwnd, IDC_WHOIS_SERVER, _r_obj_getstring (_r_config_getstring (L"WhoisServerCustom", whois_servers[0].server)));
			}
			else
			{
				SendDlgItemMessageW (hwnd, IDC_WHOIS_SERVER, CB_SETCURSEL, item_id, 0);
			}

			break;
		}

		case IDD_PAGE_URLINFO:
		{
			_r_listview_setstyle (hwnd, IDC_URLINFO_RESULT, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_URLINFO_RESULT, config.himglist);

			width = _r_ctrl_getwidth (hwnd, IDC_URLINFO_RESULT);

			_r_listview_addcolumn (hwnd, IDC_URLINFO_RESULT, 0, L"Parameter", width / 2, 0);
			_r_listview_addcolumn (hwnd, IDC_URLINFO_RESULT, 1, L"Value", width / 2, 0);

			_r_listview_addgroup (hwnd, IDC_URLINFO_RESULT, 0, L"File information", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_URLINFO_RESULT, 1, L"Server information ", 0, G_STYLE, G_STYLE);

			item_id = 0;

			_r_listview_additem_ex (hwnd, IDC_URLINFO_RESULT, item_id++, L"Size", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_URLINFO_RESULT, item_id++, L"Last-modified", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_URLINFO_RESULT, item_id++, L"Resume downloading", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_URLINFO_RESULT, item_id++, L"Content type", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_URLINFO_RESULT, item_id++, L"Etag", IL_SUCCESS, 0, 0);

			_r_listview_additem_ex (hwnd, IDC_URLINFO_RESULT, item_id++, L"Protocol", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_URLINFO_RESULT, item_id++, L"Server", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_URLINFO_RESULT, item_id++, L"Status", IL_SUCCESS, 1, 0);

			_r_ctrl_setstring (hwnd, IDC_URLINFO_LINK, _r_obj_getstring (_r_config_getstring (L"UrlInfoLink", APP_HOST)));
			_r_ctrl_checkbutton (hwnd, IDC_URLINFO_HEADER_CHK, _r_config_getboolean (L"UrlInfoShowHeader", FALSE));

			PostMessageW (hwnd, WM_COMMAND, MAKELPARAM (IDC_URLINFO_HEADER_CHK, 0), 0);

			break;
		}

		case IDD_PAGE_IP:
		{
			_r_listview_setstyle (hwnd, IDC_IP_RESULT, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_IP_RESULT, config.himglist);

			width = _r_ctrl_getwidth (hwnd, IDC_IP_RESULT);

			_r_listview_addcolumn (hwnd, IDC_IP_RESULT, 0, L"Parameter", width / 2, 0);
			_r_listview_addcolumn (hwnd, IDC_IP_RESULT, 1, L"Value", width / 2, 0);

			_r_listview_addgroup (hwnd, IDC_IP_RESULT, 0, L"External address", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_IP_RESULT, 1, L"Local address", 0, G_STYLE, G_STYLE);

			item_id = 0;

			_r_listview_additem_ex (hwnd, IDC_IP_RESULT, item_id++, L"Адрес", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_RESULT, item_id++, L"Прокси", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_RESULT, item_id++, L"Провайдер", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_RESULT, item_id++, L"Организация", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_RESULT, item_id++, L"Город", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_RESULT, item_id++, L"Координаты", IL_SUCCESS, 0, 0);

			_r_ctrl_checkbutton (hwnd, IDC_IP_EXTERNAL_CHK, _r_config_getboolean (L"RetrieveExternalIp", FALSE));

			PostMessageW (hwnd, WM_COMMAND, MAKELPARAM (IDC_IP_REFRESH, 0), 0);

			break;
		}

		case IDD_PAGE_SHAREDINFO:
		{
			_r_listview_setstyle (hwnd, IDC_SHAREDINFO, EX_STYLE, FALSE);

			_r_listview_setimagelist (hwnd, IDC_SHAREDINFO, config.himglist);

			_r_listview_addcolumn (hwnd, IDC_SHAREDINFO, 0, L"Name", 190, 0);
			_r_listview_addcolumn (hwnd, IDC_SHAREDINFO, 1, L"Path", 190, 0);
			_r_listview_addcolumn (hwnd, IDC_SHAREDINFO, 2, L"Type", 190, 0);
			_r_listview_addcolumn (hwnd, IDC_SHAREDINFO, 3, L"Connected", 190, 0);

			PostMessageW (hwnd, WM_COMMAND, MAKELPARAM (IDC_SHAREDINFO_START, 0), 0);

			break;
		}

		case IDD_PAGE_SYSINFO:
		{
			_r_listview_setstyle (hwnd, IDC_SYSINFO, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_SYSINFO, config.himglist);

			width = _r_ctrl_getwidth (hwnd, IDC_SYSINFO);

			_r_listview_addcolumn (hwnd, IDC_SYSINFO, 0, L"Parameter", width / 2, 0);
			_r_listview_addcolumn (hwnd, IDC_SYSINFO, 1, L"Value", width / 2, 0);

			_r_listview_addgroup (hwnd, IDC_SYSINFO, 0, L"General", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_SYSINFO, 1, L"Network configuration", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_SYSINFO, 2, L"Version of protocols", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_SYSINFO, 3, L"System", 0, G_STYLE, G_STYLE);

			item_id = 0;

			_r_listview_additem_ex (hwnd, IDC_SYSINFO, item_id++, L"Winsock version", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_SYSINFO, item_id++, L"Windows version", IL_SUCCESS, 0, 0);

			_r_listview_additem_ex (hwnd, IDC_SYSINFO, item_id++, L"Состояние сети", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_SYSINFO, item_id++, L"Тип узла", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_SYSINFO, item_id++, L"Переадресация", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_SYSINFO, item_id++, L"Proxy", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_SYSINFO, item_id++, L"DNS", IL_SUCCESS, 1, 0);

			_r_listview_additem_ex (hwnd, IDC_SYSINFO, item_id++, L"IPv4", IL_SUCCESS, 2, 0);
			_r_listview_additem_ex (hwnd, IDC_SYSINFO, item_id++, L"IPv6", IL_SUCCESS, 2, 0);

			_r_listview_additem_ex (hwnd, IDC_SYSINFO, item_id++, L"User name", IL_SUCCESS, 3, 0);
			_r_listview_additem_ex (hwnd, IDC_SYSINFO, item_id++, L"Host name", IL_SUCCESS, 3, 0);
			_r_listview_additem_ex (hwnd, IDC_SYSINFO, item_id++, L"Computer name", IL_SUCCESS, 3, 0);

			_app_tool_sysinfo (hwnd);

			break;
		}

		case IDD_PAGE_TCP_STATISTIC:
		{
			_r_listview_setstyle (hwnd, IDC_TCP_STATISTIC, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_TCP_STATISTIC, config.himglist);

			width = _r_ctrl_getwidth (hwnd, IDC_TCP_STATISTIC);

			_r_listview_addcolumn (hwnd, IDC_TCP_STATISTIC, 0, L"Parameter", width / 2, 0);
			_r_listview_addcolumn (hwnd, IDC_TCP_STATISTIC, 1, L"Value", width / 2, 0);

			_r_listview_addgroup (hwnd, IDC_TCP_STATISTIC, 0, L"IPv4", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_TCP_STATISTIC, 1, L"IPv6", 0, G_STYLE, G_STYLE);

			item_id = 0;

			// ipv4
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"RTO algorithm", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"The minimum RTO value (ms)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"The maximum RTO value (ms)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Received", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Sent", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Sent (Again)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Sent with the reset flag", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Received errors", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Failed connections", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Open (active)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Open (passive)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Established connections", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Discarded connections", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Max. number of connections", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Number of connections", IL_SUCCESS, 0, 0);

			// ipv6
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"RTO algorithm", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"The minimum RTO value (ms)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"The maximum RTO value (ms)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Received", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Sent", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Sent (Again)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Sent with the reset flag", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Received errors", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Failed connections", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Open (active)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Open (passive)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Established connections", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Discarded connections", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Max. number of connections", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_TCP_STATISTIC, item_id++, L"Number of connections", IL_SUCCESS, 1, 0);

			break;
		}

		case IDD_PAGE_UDP_STATISTIC:
		{
			_r_listview_setstyle (hwnd, IDC_UDP_STATISTIC, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_UDP_STATISTIC, config.himglist);

			width = _r_ctrl_getwidth (hwnd, IDC_UDP_STATISTIC);

			_r_listview_addcolumn (hwnd, IDC_UDP_STATISTIC, 0, L"Parameter", width / 2, 0);
			_r_listview_addcolumn (hwnd, IDC_UDP_STATISTIC, 1, L"Value", width / 2, 0);

			_r_listview_addgroup (hwnd, IDC_UDP_STATISTIC, 0, L"IPv4", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_UDP_STATISTIC, 1, L"IPv6", 0, G_STYLE, G_STYLE);

			item_id = 0;

			// ipv4
			_r_listview_additem_ex (hwnd, IDC_UDP_STATISTIC, item_id++, L"Received", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_UDP_STATISTIC, item_id++, L"Received (errors)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_UDP_STATISTIC, item_id++, L"Received (invalid port)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_UDP_STATISTIC, item_id++, L"Sent", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_UDP_STATISTIC, item_id++, L"Number of addresses", IL_SUCCESS, 0, 0);

			// ipv6
			_r_listview_additem_ex (hwnd, IDC_UDP_STATISTIC, item_id++, L"Received", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_UDP_STATISTIC, item_id++, L"Received (errors)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_UDP_STATISTIC, item_id++, L"Received (invalid port)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_UDP_STATISTIC, item_id++, L"Sent", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_UDP_STATISTIC, item_id++, L"Number of addresses", IL_SUCCESS, 1, 0);

			break;
		}

		case IDD_PAGE_ICMP_STATISTIC:
		{
			_r_listview_setstyle (hwnd, IDC_ICMP_STATISTIC, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_ICMP_STATISTIC, config.himglist);

			width = _r_ctrl_getwidth (hwnd, IDC_ICMP_STATISTIC);

			_r_listview_addcolumn (hwnd, IDC_ICMP_STATISTIC, 1, L"Parameter", width / 2, 0);
			_r_listview_addcolumn (hwnd, IDC_ICMP_STATISTIC, 1, L"Value", width / 2, 0);

			_r_listview_addgroup (hwnd, IDC_ICMP_STATISTIC, 0, L"IPv4", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_ICMP_STATISTIC, 1, L"IPv6", 0, G_STYLE, G_STYLE);

			item_id = 0;

			// ipv4
			_r_listview_additem_ex (hwnd, IDC_ICMP_STATISTIC, item_id++, L"Incoming", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_ICMP_STATISTIC, item_id++, L"Incoming (errors)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_ICMP_STATISTIC, item_id++, L"Outgoing", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_ICMP_STATISTIC, item_id++, L"Outgoing (errors)", IL_SUCCESS, 0, 0);

			// ipv6
			_r_listview_additem_ex (hwnd, IDC_ICMP_STATISTIC, item_id++, L"Incoming", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_ICMP_STATISTIC, item_id++, L"Incoming (errors)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_ICMP_STATISTIC, item_id++, L"Outgoing", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_ICMP_STATISTIC, item_id++, L"Outgoing (errors)", IL_SUCCESS, 1, 0);

			break;
		}

		case IDD_PAGE_IP_STATISTIC:
		{
			_r_listview_setstyle (hwnd, IDC_IP_STATISTIC, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_IP_STATISTIC, config.himglist);

			width = _r_ctrl_getwidth (hwnd, IDC_IP_STATISTIC);

			_r_listview_addcolumn (hwnd, IDC_IP_STATISTIC, 0, L"Parameter", width / 2, 0);
			_r_listview_addcolumn (hwnd, IDC_IP_STATISTIC, 1, L"Value", width / 2, 0);

			_r_listview_addgroup (hwnd, IDC_IP_STATISTIC, 0, L"IPv4", 0, G_STYLE, G_STYLE);
			_r_listview_addgroup (hwnd, IDC_IP_STATISTIC, 1, L"IPv6", 0, G_STYLE, G_STYLE);

			item_id = 0;

			// ipv4
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Redirection", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Redirected packets", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Recieved", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Recieved (errors in header)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Recieved (errors in address)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Recieved (errors in protocol)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Discarded incoming packets", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Discarded outgoing routes", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Discarded outgoing packets", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Packets without a route", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Packets collected", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Packets collected (error)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Packets requiring assembly", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Fragmented packets", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Fragmented packets (error)", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Fragments created", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Fragmented packet assembly time", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Delivered packets", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Packets sent", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"TTL value", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Number of interfaces", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Number of IP addresses", IL_SUCCESS, 0, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Number of routes", IL_SUCCESS, 0, 0);

			item_id = 24;

			// ipv6
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Redirection", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Redirected packets", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Recieved", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Recieved (errors in header)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Recieved (errors in address)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Recieved (errors in protocol)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Discarded incoming packets", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Discarded outgoing routes", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Discarded outgoing packets", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Packets without a route", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Packets collected", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Packets collected (error)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Packets requiring assembly", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Fragmented packets", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Fragmented packets (error)", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Fragments created", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Fragmented packet assembly time", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Delivered packets", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Packets sent", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"TTL value", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Number of interfaces", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Number of IP addresses", IL_SUCCESS, 1, 0);
			_r_listview_additem_ex (hwnd, IDC_IP_STATISTIC, item_id++, L"Number of routes", IL_SUCCESS, 1, 0);

			break;
		}
	}
}

INT_PTR WINAPI PageDlgProc (
	_In_ HWND hwnd,
	_In_ UINT msg,
	_In_ WPARAM wparam,
	_In_ LPARAM lparam
)
{
	switch (msg)
	{
		case WM_INITDIALOG:
		{
			_app_initializepage (hwnd, IDD_PAGE_PING);
			_app_initializepage (hwnd, IDD_PAGE_SPEEDMETER);
			_app_initializepage (hwnd, IDD_PAGE_URLDECODER);
			_app_initializepage (hwnd, IDD_PAGE_HOSTADDR);
			_app_initializepage (hwnd, IDD_PAGE_URLINFO);
			_app_initializepage (hwnd, IDD_PAGE_IP);
			_app_initializepage (hwnd, IDD_PAGE_WHOIS);
			_app_initializepage (hwnd, IDD_PAGE_SHAREDINFO);
			_app_initializepage (hwnd, IDD_PAGE_SYSINFO);
			_app_initializepage (hwnd, IDD_PAGE_TCP_STATISTIC);
			_app_initializepage (hwnd, IDD_PAGE_UDP_STATISTIC);
			_app_initializepage (hwnd, IDD_PAGE_ICMP_STATISTIC);
			_app_initializepage (hwnd, IDD_PAGE_IP_STATISTIC);

			break;
		}

		case WM_DESTROY:
		{
			WCHAR buffer[256] = {0};
			LONG item_id;
			BOOL is_translated;

			if (GetDlgItem (hwnd, IDC_PING_HOST))
			{
				GetDlgItemTextW (hwnd, IDC_PING_HOST, buffer, RTL_NUMBER_OF (buffer));

				_r_config_setstring (L"PingAddress", buffer);
			}

			if (GetDlgItem (hwnd, IDC_PING_RETRIES))
			{
				item_id = GetDlgItemInt (hwnd, IDC_PING_RETRIES, &is_translated, TRUE);

				if (is_translated)
					_r_config_setlong (L"PingRetries", item_id);
			}

			if (GetDlgItem (hwnd, IDC_SPEEDMETER_LINK))
			{
				item_id = GetDlgItemInt (hwnd, IDC_SPEEDMETER_LIMIT, &is_translated, TRUE);

				if (is_translated)
					_r_config_setlong (L"SpeedMeterLimit", item_id);

				GetDlgItemTextW (hwnd, IDC_SPEEDMETER_LINK, buffer, RTL_NUMBER_OF (buffer));

				_r_config_setstring (L"SpeedmeterLink", buffer);
			}

			if (GetDlgItem (hwnd, IDC_URLDECODER_LINK))
			{
				GetDlgItemTextW (hwnd, IDC_URLDECODER_LINK, buffer, RTL_NUMBER_OF (buffer));

				_r_config_setstring (L"UrlDecoderLink", buffer);
			}

			if (GetDlgItem (hwnd, IDC_HOSTADDR_HOST))
			{
				GetDlgItemTextW (hwnd, IDC_HOSTADDR_HOST, buffer, RTL_NUMBER_OF (buffer));

				_r_config_setstring (L"HostAddrAddress", buffer);
			}

			if (GetDlgItem (hwnd, IDC_URLINFO_LINK))
			{
				GetDlgItemTextW (hwnd, IDC_URLINFO_LINK, buffer, RTL_NUMBER_OF (buffer));

				_r_config_setstring (L"UrlInfoLink", buffer);
			}

			if (GetDlgItem (hwnd, IDC_URLINFO_HEADER_CHK))
				_r_config_setboolean (L"UrlInfoShowHeader", _r_ctrl_isbuttonchecked (hwnd, IDC_URLINFO_HEADER_CHK));

			if (GetDlgItem (hwnd, IDC_IP_EXTERNAL_CHK))
				_r_config_setboolean (L"RetrieveExternalIp", _r_ctrl_isbuttonchecked (hwnd, IDC_IP_EXTERNAL_CHK));

			if (GetDlgItem (hwnd, IDC_WHOIS_HOST))
			{
				GetDlgItemTextW (hwnd, IDC_WHOIS_HOST, buffer, RTL_NUMBER_OF (buffer));

				_r_config_setstring (L"WhoisAddress", buffer);
			}

			if (GetDlgItem (hwnd, IDC_WHOIS_SERVER))
			{
				item_id = _r_combobox_getcurrentitem (hwnd, IDC_WHOIS_SERVER);

				if (item_id == CB_ERR)
				{
					GetDlgItemTextW (hwnd, IDC_WHOIS_SERVER, buffer, RTL_NUMBER_OF (buffer));

					_r_config_setstring (L"WhoisServerCustom", buffer);
				}

				_r_config_setlong (L"WhoisServer", item_id);
			}

			break;
		}

		case WM_CONTEXTMENU:
		{
			HMENU hmenu;
			HMENU hsubmenu;
			ULONG_PTR page_id;

			page_id = _app_getcurrentpage (hwnd);

			if (!page_list[page_id].listview_id)
				break;

			hmenu = LoadMenuW (NULL, MAKEINTRESOURCEW (IDM_LISTVIEW));
			hsubmenu = GetSubMenu (hmenu, 0);

			//if (!_r_listview_getitemcount (page_list[page_id].hpage, page_list[page_id].listview_id))
			//{
			//	_r_menu_enableitem (hsubmenu, IDC_LISTVIEW_COPY, 0, FALSE);
			//	_r_menu_enableitem (hsubmenu, IDC_LISTVIEW_COPY_VALUE, 0, FALSE);
			//	_r_menu_enableitem (hsubmenu, IDC_LISTVIEW_SAVE_AS, 0, FALSE);
			//}

			//if (!_r_listview_getselectedcount (page_list[page_id].hpage, page_list[page_id].listview_id))
			//{
			//	_r_menu_enableitem (hsubmenu, IDC_LISTVIEW_COPY, 0, FALSE);
			//	_r_menu_enableitem (hsubmenu, IDC_LISTVIEW_COPY_VALUE, 0, FALSE);
			//}

			//if (PostMessageW ((HWND)PostMessageW ((HWND)wparam, LVM_GETHEADER, 0, 0), HDM_GETITEMCOUNT, 0, 0) != 2)
			//	_r_menu_enableitem (hsubmenu, IDC_LISTVIEW_COPY_VALUE, 0, FALSE);

			_r_menu_popup (hsubmenu, hwnd, NULL, TRUE);

			DestroyMenu (hmenu);

			break;
		}

		case WM_COMMAND:
		{
			switch (LOWORD (wparam))
			{
				/*
				case IDM_COPY:
				{
					static R_STRINGREF divider_sr = PR_STRINGREF_INIT (DIVIDER_COPY);

					R_STRINGBUILDER buffer;
					PR_STRING string;
					ULONG_PTR page_id;
					INT item_id = -1;
					INT column_count;

					page_id = _app_getcurrentpage (hwnd);

					if (!page_list[page_id].listview_id)
						break;

					if (GetFocus () != GetDlgItem (page_list[page_id].hpage, page_list[page_id].listview_id))
						break;

					column_count = _r_listview_getcolumncount (page_list[page_id].hpage, page_list[page_id].listview_id);

					_r_obj_initializestringbuilder (&buffer);

					while ((item_id = _r_listview_getnextselected (page_list[page_id].hpage, page_list[page_id].listview_id, item_id)) != -1)
					{
						for (INT i = 0; i < column_count; i++)
						{
							string = _r_listview_getitemtext (page_list[page_id].hpage, page_list[page_id].listview_id, item_id, i);

							if (string)
							{
								_r_obj_appendstringbuilder2 (&buffer, string);
								_r_obj_appendstringbuilder3 (&buffer, &divider_sr);

								_r_obj_dereference (string);
							}
						}

						string = _r_obj_finalstringbuilder (&buffer);

						_r_str_trimstring (string, &divider_sr, 0);

						_r_obj_appendstringbuilder (&buffer, DIVIDER_TRIM);
					}

					string = _r_obj_finalstringbuilder (&buffer);

					_r_str_trimstring2 (string, DIVIDER_COPY, 0);

					_r_clipboard_set (hwnd, &string->sr);

					_r_obj_deletestringbuilder (&buffer);

					break;
				}

				case IDM_SELECT_ALL:
				{
					ULONG_PTR page_id;

					page_id = _app_getcurrentpage (hwnd);

					if (!page_list[page_id].listview_id)
						break;

					if (GetFocus () != GetDlgItem (page_list[page_id].hpage, page_list[page_id].listview_id))
						break;

					_r_listview_setitemstate (page_list[page_id].hpage, page_list[page_id].listview_id, -1, LVIS_SELECTED, LVIS_SELECTED);

					break;
				}

				case IDC_LISTVIEW_COPY:
				{
					PR_STRING string;

					if (GetListViewText (GetDlgItem (hwnd, page_list.listview_id[page_id]), buff, 4096, 1))
						_r_clipboard_set (hwnd, &string->sr);

					break;
				}

				case IDC_COPY_VALUE:
				{
					WCHAR buff[4096] = {0};
					ULONG_PTR page_id;

					page_id = _app_getcurrentpage (hwnd);

					if (GetListViewText (GetDlgItem (hwnd, page_list[page_id].listview_id), buff, 4096, 1, 1))
						SetClipboardText (buff, 4096);

					break;
				}

				case IDC_SAVE_AS:
				{
					OPENFILENAME of = {0};
					WCHAR buff[4096] = {0};
					HANDLE hfile;
					CHAR header[2] = {0xFF, 0xFE};
					ULONG dwWriten = 0;

					_r_str_copy (buffer, RTL_NUMBER_OF(buffer), L"report.txt");

					of.lStructSize = sizeof (of);
					of.hwndOwner = hwnd;
					of.lpstrFilter = L"Все файлы (*.*)\0*.*";
					of.lpstrFile = buffer;
					of.nMaxFile = RTL_NUMBER_OF(buffer);
					of.Flags = OFN_EXPLORER | OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;

					if (GetSaveFileName (&of))
					{
						if (GetListViewText (GetDlgItem (hwnd, page_list[page_id].listview_id), buff, 4096))
						{
							hfile = CreateFile (buffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

							if (!hfile)
								break;

							WriteFile (hfile, header, 2, &dwWriten, NULL); // Write Header
							WriteFile (hfile, buff, (lstrlen (buff) * 2) + dwWriten - 1, &dwWriten, NULL); // Write Text

							CloseHandle (hfile);
						}
					}

					break;
				}
				*/
				case IDC_PING_START:
				{
					ULONG_PTR page_id;

					page_id = _app_getpageid (IDD_PAGE_PING);

					if (page_list[page_id].thread)
					{
						if (_r_show_message (hwnd, MB_YESNO | MB_ICONEXCLAMATION, NULL, L"Do you want to clear data?") == IDYES)
							page_list[page_id].thread = FALSE;
					}
					else
					{
						_r_sys_createthread (&_app_tool_ping, hwnd, NULL, NULL, L"Ping");
					}

					break;
				}

				case IDC_SPEEDMETER_START:
				{
					ULONG_PTR page_id;

					page_id = _app_getpageid (IDD_PAGE_SPEEDMETER);

					if (page_list[page_id].thread)
					{
						if (_r_show_message (hwnd, MB_YESNO | MB_ICONEXCLAMATION, NULL, L"Do you want to clear data?") == IDYES)
							page_list[page_id].thread = FALSE;
					}
					else
					{
						_r_sys_createthread (&_app_tool_downloadspeed, hwnd, NULL, NULL, L"DownloadSpeed");
					}

					break;
				}

				case IDC_URLDECODER_START:
				{
					_app_tool_urldecoder (hwnd);
					break;
				}

				case IDC_HOSTADDR_START:
				{
					_app_tool_hostaddress (hwnd);
					break;
				}

				case IDC_URLINFO_START:
				{
					_r_sys_createthread (&_app_tool_urlinfo, hwnd, NULL, NULL, L"UrlInfo");
					break;
				}

				case IDC_URLINFO_HEADER_CHK:
				{
					BOOLEAN is_checked;

					is_checked = _r_ctrl_isbuttonchecked (hwnd, IDC_URLINFO_HEADER_CHK);

					ShowWindow (GetDlgItem (hwnd, IDC_URLINFO_HEADER), is_checked ? SW_SHOW : SW_HIDE);
					ShowWindow (GetDlgItem (hwnd, IDC_URLINFO_RESULT), is_checked ? SW_HIDE : SW_SHOW);

					break;
				}

				case IDC_IP_REFRESH:
				{
					if (_r_ctrl_isbuttonchecked (hwnd, IDC_IP_EXTERNAL_CHK))
					{
						_r_sys_createthread (&_app_tool_externalip, hwnd, NULL, NULL, L"ExternalIp");
					}
					else
					{
						_r_listview_fillitems (hwnd, IDC_IP_RESULT, -1, -1, 1, L"n/a", IL_FAULT);
					}

					break;
				}

				case IDC_WHOIS_START:
				{
					_r_sys_createthread (&_app_tool_whois, hwnd, NULL, NULL, L"Whois");
					break;
				}

				case IDC_SHAREDINFO_START:
				{
					_app_tool_sharedinfo (hwnd);
					break;
				}

				case IDC_PING_CLEAR:
				case IDC_SPEEDMETER_CLEAR:
				case IDC_URLDECODER_CLEAR:
				case IDC_HOSTADDR_CLEAR:
				case IDC_URLINFO_CLEAR:
				case IDC_WHOIS_CLEAR:
				case IDC_SHAREDINFO_CLEAR:
				{
					ULONG_PTR page_id;

					page_id = _app_getcurrentpage (hwnd);

					if (!_r_listview_getitemcount (hwnd, page_list[page_id].listview_id))
						break;

					if (_r_show_confirmmessage (hwnd, NULL, L"Do you want to clear data?", L"ClearConfirm"))
						_r_listview_deleteallitems (hwnd, page_list[page_id].listview_id);

					break;
				}

				break;
			}
		}
	}

	return 0;
}

LRESULT CALLBACK DlgProc (
	_In_ HWND hwnd,
	_In_ UINT msg,
	_In_ WPARAM wparam,
	_In_ LPARAM lparam
)
{
	static R_LAYOUT_MANAGER layout_manager = {0};

	switch (msg)
	{
		case WM_INITDIALOG:
		{
			HMENU hsubmenu;
			HMENU hmenu;
			ULONG_PTR page_id;
			LONG status;
			INT parts[2] = {0};

			status = WSAStartup (WINSOCK_VERSION, &wsa);

			if (status != ERROR_SUCCESS)
			{
				_r_show_errormessage (hwnd, NULL, status, NULL, FALSE);

				RtlExitUserProcess (status);
			}

			_r_treeview_setstyle (hwnd, IDC_ITEMLIST, TVS_EX_DOUBLEBUFFER | TVS_EX_FADEINOUTEXPANDOS, 0, 0);

			_app_imagelist_init (hwnd, 0);

			hmenu = GetMenu (hwnd);

			if (hmenu)
			{
				_r_menu_checkitem (hmenu, IDM_ALWAYSONTOP_CHK, 0, MF_BYCOMMAND, _r_config_getboolean (L"AlwaysOnTop", FALSE));
				_r_menu_checkitem (hmenu, IDM_CHECKUPDATES_CHK, 0, MF_BYCOMMAND, _r_update_isenabled (FALSE));

				hsubmenu = GetSubMenu (hmenu, 1);

				if (hsubmenu)
					_r_locale_enum (hsubmenu, LANG_MENU, IDX_LANGUAGE); // enum localizations
			}

			parts[0] = 200;
			parts[1] = -1;

			_r_status_setparts (hwnd, IDC_STATUSBAR, parts, RTL_NUMBER_OF (parts));

			_app_initializepages (hwnd);

			page_id = _app_getcurrentpage (hwnd);

			_app_setcurrentpage (hwnd, _r_config_getlong (L"LastItem", (LONG)_app_getpageid (IDD_PAGE_SYSINFO)));

			SetTimer (hwnd, 1337, 1000, &TimerProc);

			_r_layout_initializemanager (&layout_manager, hwnd);

			break;
		}

		case RM_LOCALIZE:
		{
			HMENU hmenu;
			HMENU hsubmenu;
			LONG dpi_value;

			dpi_value = _r_dc_getwindowdpi (hwnd);

			for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (category_list); i++)
			{
				_r_treeview_setitem (hwnd, IDC_ITEMLIST, category_list[i].hitem, _r_locale_getstring (category_list[i].name), IL_FOLDER, 0);
			}

			for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (page_list); i++)
			{
				_r_treeview_setitem (hwnd, IDC_ITEMLIST, page_list[i].hitem, _r_locale_getstring (page_list[i].title), IL_FOLDER, (LPARAM)i);
			}

			hmenu = GetMenu (hwnd);

			if (!hmenu)
				break;

			_r_menu_setitemtext (hmenu, 0, TRUE, _r_locale_getstring (IDS_FILE));
			_r_menu_setitemtext (hmenu, 1, TRUE, _r_locale_getstring (IDS_SETTINGS));
			_r_menu_setitemtext (hmenu, 2, TRUE, _r_locale_getstring (IDS_HELP));

			_r_menu_setitemtextformat (hmenu, IDM_EXIT, FALSE, L"%s\tEsc", _r_locale_getstring (IDS_EXIT));
			_r_menu_setitemtext (hmenu, IDM_ALWAYSONTOP_CHK, FALSE, _r_locale_getstring (IDS_ALWAYSONTOP_CHK));
			_r_menu_setitemtext (hmenu, IDM_CHECKUPDATES_CHK, FALSE, _r_locale_getstring (IDS_CHECKUPDATES_CHK));
			_r_menu_setitemtext (hmenu, IDM_WEBSITE, FALSE, _r_locale_getstring (IDS_WEBSITE));
			_r_menu_setitemtext (hmenu, IDM_CHECKUPDATES, FALSE, _r_locale_getstring (IDS_CHECKUPDATES));
			_r_menu_setitemtextformat (hmenu, IDM_ABOUT, FALSE, L"%s\tF1", _r_locale_getstring (IDS_ABOUT));

			hsubmenu = GetSubMenu (hmenu, 1);

			if (hsubmenu)
			{
				_r_menu_setitemtextformat (hsubmenu, LANG_MENU, TRUE, L"%s (Language)", _r_locale_getstring (IDS_LANGUAGE));

				_r_locale_enum (hsubmenu, LANG_MENU, IDX_LANGUAGE); // enum localizations
			}

			break;
		}

		case WM_CLOSE:
		{
			DestroyWindow (hwnd);
			break;
		}

		case WM_DESTROY:
		{
			KillTimer (hwnd, 1337);

			for (INT i = 0; i < PAGE_COUNT; i++)
				page_list[i].thread = FALSE;

			_r_config_setlong (L"LastItem", (LONG)_app_getcurrentpage (hwnd));

			ImageList_Destroy (config.himglist);

			WSACleanup ();

			PostQuitMessage (0);

			break;
		}

		case WM_SIZE:
		{
			_r_layout_resize (&layout_manager, wparam);
			break;
		}

		case WM_DPICHANGED:
		{
			_r_wnd_message_dpichanged (hwnd, wparam, lparam);

			_app_imagelist_init (hwnd, LOWORD (wparam));

			SendMessageW (hwnd, WM_SIZE, 0, 0);

			break;
		}

		case WM_THEMECHANGED:
		{
			SendMessageW (hwnd, WM_SIZE, 0, 0);
			break;
		}

		case WM_NOTIFY:
		{
			LPNMHDR lphdr = (LPNMHDR)lparam;

			switch (lphdr->code)
			{
				case TVN_SELCHANGED:
				{
					ULONG_PTR page_id_old;
					ULONG_PTR page_id_new;
					LPNMTREEVIEWW lpnmtv;

					if (wparam != IDC_ITEMLIST)
						break;

					lpnmtv = (LPNMTREEVIEWW)lparam;

					page_id_old = lpnmtv->itemOld.lParam;
					page_id_new = lpnmtv->itemNew.lParam;

					if (page_list[page_id_old].hpage)
						ShowWindow (page_list[page_id_old].hpage, SW_HIDE);

					if (page_id_new == -1)
					{
						_r_treeview_selectfirstchild (hwnd, IDC_ITEMLIST, lpnmtv->itemNew.hItem);

						return 0;
					}

					if (page_list[page_id_new].hpage)
					{
						_app_setpagepos (hwnd, page_list[page_id_new].hpage);

						ShowWindow (page_list[page_id_new].hpage, SW_SHOW);
					}

					_r_status_settext (hwnd, IDC_STATUSBAR, 0, _r_locale_getstring (page_list[page_id_new].title));
					_r_status_settext (hwnd, IDC_STATUSBAR, 1, _r_locale_getstring (page_list[page_id_new].description));

					break;
				}

				case NM_CUSTOMDRAW:
				{
					LONG_PTR result;

					result = _app_treeview_custdraw (hwnd, (LPNMTVCUSTOMDRAW)lparam);

					SetWindowLongPtrW (hwnd, DWLP_MSGRESULT, result);

					return result;
				}
			}

			break;
		}

		case WM_COMMAND:
		{
			INT ctrl_id = LOWORD (wparam);
			INT notify_code = HIWORD (wparam);

			if (notify_code == 0)
			{
				if (ctrl_id >= IDX_LANGUAGE && ctrl_id <= IDX_LANGUAGE + (INT)(INT_PTR)_r_locale_getcount () + 1)
				{
					HMENU hmenu;
					HMENU hsubmenu;

					hmenu = GetMenu (hwnd);

					if (hmenu)
					{
						hsubmenu = GetSubMenu (GetSubMenu (hmenu, 1), LANG_MENU);

						if (hsubmenu)
							_r_locale_apply (hsubmenu, ctrl_id, IDX_LANGUAGE);
					}

					return FALSE;
				}
			}

			switch (ctrl_id)
			{
				case IDCANCEL: // process Esc key
				case IDM_EXIT:
				{
					DestroyWindow (hwnd);
					break;
				}

				case IDM_ALWAYSONTOP_CHK:
				{
					BOOLEAN new_val;

					new_val = !_r_config_getboolean (L"AlwaysOnTop", FALSE);

					_r_menu_checkitem (GetMenu (hwnd), ctrl_id, 0, MF_BYCOMMAND, new_val);
					_r_config_setboolean (L"AlwaysOnTop", new_val);

					_r_wnd_top (hwnd, new_val);

					break;
				}

				case IDM_CHECKUPDATES_CHK:
				{
					BOOLEAN new_val;

					new_val = !_r_update_isenabled (FALSE);

					_r_menu_checkitem (GetMenu (hwnd), ctrl_id, 0, MF_BYCOMMAND, new_val);
					_r_update_enable (new_val);

					break;
				}

				case IDM_WEBSITE:
				{
					_r_shell_opendefault (_r_app_getwebsite_url ());
					break;
				}

				case IDM_CHECKUPDATES:
				{
					_r_update_check (hwnd);
					break;
				}

				case IDM_ABOUT:
				{
					_r_show_aboutmessage (hwnd);
					break;
				}

				case IDM_ZOOM:
				{
					ShowWindow (hwnd, IsZoomed (hwnd) ? SW_RESTORE : SW_MAXIMIZE);
					break;
				}
			}

			break;
		}
	}

	return 0;
}

INT APIENTRY wWinMain (
	_In_ HINSTANCE hinst,
	_In_opt_ HINSTANCE prev_hinst,
	_In_ LPWSTR cmdline,
	_In_ INT show_cmd
)
{
	HWND hwnd;

	if (!_r_app_initialize (NULL))
		return ERROR_APP_INIT_FAILURE;

	hwnd = _r_app_createwindow (hinst, MAKEINTRESOURCEW (IDD_MAIN), MAKEINTRESOURCEW (IDI_MAIN), &DlgProc);

	if (!hwnd)
		return ERROR_APP_INIT_FAILURE;

	return _r_wnd_message_callback (hwnd, MAKEINTRESOURCEW (IDA_MAIN));
}