// InetOps
// Copyright (c) 2012-2023 Henry++

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
#include <winioctl.h>
#include <strsafe.h>

#include "app.h"
#include "rapp.h"
#include "main.h"

#include "resource.h"

#define APP_HOST L"www.github.com"

WSADATA wsa = {0};
PAGE_LIST page_list[PAGE_COUNT] = {0};
CATEGORY_LIST category_list[3] = {0};
HIMAGELIST himglist = NULL;

LONG_PTR TreeView_CustDraw (
	_In_ HWND hwnd,
	_In_ LPNMTVCUSTOMDRAW lptvcd
)
{
	if (lptvcd->nmcd.hdr.idFrom != IDC_ITEMLIST)
		return 0;

	switch (lptvcd->nmcd.dwDrawStage)
	{
		case CDDS_PREPAINT:
		{
			return (CDRF_NOTIFYPOSTPAINT | CDRF_NOTIFYITEMDRAW);
		}

		case CDDS_ITEMPREPAINT:
		{
			HFONT hFont;
			COLORREF clTextClr;
			ULONG dwWeight = 0;
			ULONG dwUnderline = 0;

			clTextClr = GetSysColor (COLOR_GRAYTEXT);

			if (!lptvcd->iLevel)
			{
				dwWeight = FW_BOLD;
				clTextClr = RGB (0, 0, 0);
			}

			if (lptvcd->nmcd.uItemState & CDIS_HOT)
			{
				clTextClr = RGB (0, 78, 152);
				dwUnderline = 1;
				lptvcd->clrTextBk = RGB (216, 231, 239);
			}

			if (lptvcd->nmcd.uItemState & CDIS_SELECTED)
			{
				clTextClr = RGB (0, 0, 0);
				lptvcd->clrTextBk = RGB (171, 208, 228);
			}

			hFont = CreateFont (
				-11,
				0,
				0,
				0,
				dwWeight,
				0,
				dwUnderline,
				0,
				DEFAULT_CHARSET,
				OUT_CHARACTER_PRECIS,
				CLIP_CHARACTER_PRECIS,
				DEFAULT_QUALITY,
				DEFAULT_PITCH,
				0
			);

			SelectObject (lptvcd->nmcd.hdc, hFont);
			DeleteObject (hFont);

			lptvcd->clrText = clTextClr;

			return (CDRF_NOTIFYPOSTPAINT | CDRF_NEWFONT);
		}
	}

	return 0;
}

VOID SetPagePos (
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

VOID Lv_InsertItemA (
	_In_ HWND hwnd,
	_In_ INT ctrl_id,
	_In_ LPSTR text,
	_In_ INT item_id,
	_In_ INT subitem_id
)
{
	PR_STRING string;
	R_BYTEREF st;
	NTSTATUS status;

	_r_obj_initializebyteref (&st, text);

	st.buffer = (LPSTR)text;
	st.length = strlen (text);

	status = _r_str_multibyte2unicode (&st, &string);

	if (NT_SUCCESS (status))
	{
		_r_listview_setitem (hwnd, ctrl_id, item_id, subitem_id, string->buffer);

		_r_obj_dereference (string);
	}
}

ULONG_PTR GetPageId (
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

ULONG_PTR GetCurrentPage (
	_In_ HWND hwnd
)
{
	HTREEITEM hitem;
	LPARAM lparam;

	hitem = (HTREEITEM)SendDlgItemMessage (hwnd, IDC_ITEMLIST, TVM_GETNEXTITEM, TVGN_CARET, 0);

	if (!SendDlgItemMessage (hwnd, IDC_ITEMLIST, TVM_GETNEXTITEM, TVGN_PARENT, (LPARAM)hitem))
		hitem = (HTREEITEM)SendDlgItemMessage (hwnd, IDC_ITEMLIST, TVM_GETNEXTITEM, TVGN_CHILD, (LPARAM)hitem);

	if (!hitem)
		return 0;

	lparam = _r_treeview_getlparam (hwnd, IDC_ITEMLIST, hitem);

	if (lparam < 0)
		lparam = 0;

	if (lparam >= PAGE_COUNT)
		lparam = PAGE_COUNT - 1;

	return lparam;
}

VOID SetCurrentPage (
	_In_ HWND hwnd,
	_In_ ULONG_PTR item_id
)
{
	if (item_id >= PAGE_COUNT)
		item_id = PAGE_COUNT - 1;

	SendDlgItemMessage (hwnd, IDC_ITEMLIST, TVM_SELECTITEM, TVGN_CARET, (LPARAM)page_list[item_id].hitem);
}

NTSTATUS GetPing (
	_In_ LPVOID lparam
)
{
	WCHAR buffer[256];
	WCHAR ipaddr[32];
	CHAR send_buff[256];
	R_STRINGREF sr;
	PR_STRING string;
	PR_BYTE bytes;
	PADDRINFOW result;
	ADDRINFOW hints;
	LPSOCKADDR sockaddr_ip;
	SOCKADDR_IN6_LH v6addr;
	PICMP_ECHO_REPLY icmp_reply;
	HWND hwnd;
	HANDLE icmp_handle = NULL;
	HANDLE icmp6_handle = NULL;
	ULONG_PTR page_id;
	PVOID reply;
	ULONG byte_length;
	ULONG length;
	ULONG ip;
	ULONG status;
	LONG retries;
	INT item_id = 0;

	hwnd = (HWND)lparam;

	page_id = GetPageId (IDD_PAGE_PING);

	page_list[page_id].thread = TRUE;

	_r_ctrl_setstring (hwnd, IDC_PING_START, L"Abort");
	_r_ctrl_enable (hwnd, IDC_PING_CLEAR, FALSE);

	_r_listview_deleteallitems (hwnd, IDC_PING_RESULT);

	RtlZeroMemory (&hints, sizeof (hints));

	_r_ctrl_enable (hwnd, IDC_HOSTADDR_START, FALSE);
	_r_ctrl_enable (hwnd, IDC_HOSTADDR_CLEAR, FALSE);

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	string = _r_ctrl_getstring (hwnd, IDC_PING_HOST);

	if (!string)
		goto CleanupExit;

	icmp_handle = IcmpCreateFile ();
	icmp6_handle = Icmp6CreateFile ();

	if (icmp_handle == INVALID_HANDLE_VALUE || icmp6_handle == INVALID_HANDLE_VALUE)
		goto CleanupExit;

	retries = _r_ctrl_getinteger (hwnd, IDC_PING_RETRIES, NULL);

	RtlZeroMemory (send_buff, sizeof (send_buff));

	byte_length = sizeof (ICMP_ECHO_REPLY) + sizeof (send_buff);
	reply = _r_mem_allocate (byte_length);

	for (ULONG_PTR i = 0; i < sizeof (send_buff); i++)
		send_buff[i] = 'A' + (_r_math_getrandom () % 26);

	for (LONG i = 0; i < retries; i++)
	{
		if (!page_list[page_id].thread)
			break;

		if (GetAddrInfoW (string->buffer, NULL, &hints, &result) == ERROR_SUCCESS)
		{
			for (PADDRINFOW ptr = result; ptr; ptr = ptr->ai_next)
			{
				sockaddr_ip = ptr->ai_addr;

				length = RTL_NUMBER_OF (ipaddr);

				status = WSAAddressToString (sockaddr_ip, (ULONG)ptr->ai_addrlen, NULL, ipaddr, &length);

				if (status == ERROR_SUCCESS)
				{
					_r_obj_initializestringref (&sr, ipaddr);

					_r_str_unicode2multibyte (&sr, &bytes);

					if (ptr->ai_family == AF_INET)
					{
						ip = inet_addr (bytes->buffer);

						status = IcmpSendEcho (
							icmp_handle,
							ip,
							send_buff,
							sizeof (send_buff),
							NULL,
							reply,
							byte_length,
							PING_TIMEOUT
						);

						icmp_reply = reply;

						switch (icmp_reply->Status)
						{
							case IP_SUCCESS:
							{
								_r_listview_additem_ex (hwnd, IDC_PING_RESULT, item_id, ipaddr, IL_SUCCESS, I_GROUPIDNONE, 0);

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d bytes", icmp_reply->DataSize);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 1, buffer);

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d", icmp_reply->Options.Tos);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 2, buffer);

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d", icmp_reply->Options.Ttl);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 3, buffer);

								break;
							}

							case IP_REQ_TIMED_OUT:
							{
								_r_listview_additem_ex (hwnd, IDC_PING_RESULT, item_id, L"Timeout", IL_FAULT, I_GROUPIDNONE, 0);
								break;
							}

							default:
							{

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error: %d", icmp_reply->Status);
								_r_listview_additem_ex (hwnd, IDC_PING_RESULT, item_id, buffer, IL_FAULT, I_GROUPIDNONE, 0);

								break;
							}
						}

						item_id += 1;
					}
					else if (ptr->ai_family == AF_INET6)
					{
						RtlZeroMemory (&v6addr, sizeof (v6addr));

						status = inet_pton (AF_INET6, bytes->buffer, &v6addr);

						RDBG2 (L"err: %d", status);

						status = Icmp6SendEcho2 (
							icmp6_handle,
							NULL,
							NULL,
							NULL,
							&v6addr,
							&v6addr,
							send_buff,
							sizeof (send_buff),
							NULL,
							reply,
							byte_length,
							PING_TIMEOUT
						);

						icmp_reply = reply;

						switch (icmp_reply->Status)
						{
							case IP_SUCCESS:
							{
								//_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d bytes", icmp_reply->DataSize);
								_r_listview_additem_ex (hwnd, IDC_PING_RESULT, item_id, ipaddr, IL_SUCCESS, I_GROUPIDNONE, 0);

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d bytes", icmp_reply->DataSize);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 1, buffer);

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d", icmp_reply->RoundTripTime);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 2, buffer);

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%d", icmp_reply->Options.Ttl);
								_r_listview_setitem (hwnd, IDC_PING_RESULT, item_id, 3, buffer);

								break;
							}

							case IP_REQ_TIMED_OUT:
							{
								_r_listview_additem_ex (hwnd, IDC_PING_RESULT, item_id, L"Timeout", IL_FAULT, I_GROUPIDNONE, 0);
								break;
							}

							default:
							{

								_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Error: %d", icmp_reply->Status);
								_r_listview_additem_ex (hwnd, IDC_PING_RESULT, item_id, buffer, IL_FAULT, I_GROUPIDNONE, 0);

								break;
							}
						}

						item_id += 1;
					}
				}
			}
		}
	}

	_r_mem_free (reply);

CleanupExit:

	page_list[page_id].thread = FALSE;

	if (_r_fs_isvalidhandle (icmp_handle))
		IcmpCloseHandle (icmp_handle);

	if (_r_fs_isvalidhandle (icmp6_handle))
		IcmpCloseHandle (icmp6_handle);

	if (string)
		_r_obj_dereference (string);

	_r_ctrl_setstring (hwnd, IDC_PING_START, L"Start");

	_r_ctrl_enable (hwnd, IDC_PING_START, TRUE);
	_r_ctrl_enable (hwnd, IDC_PING_CLEAR, TRUE);

	return STATUS_SUCCESS;
}

NTSTATUS GetExternalIp (
	_In_ LPVOID lparam
)
{
	HWND hwnd;
	HINTERNET hsession;
	HINTERNET hconnect;
	HINTERNET hrequest;
	CHAR buffer2[4096] = {0};
	CHAR buffer[256];
	PR_STRING address;
	ULONG readed;
	ULONG status;
	INT item_id = 0;
	BOOLEAN result = FALSE;

	hwnd = (HWND)lparam;

	_r_ctrl_enable (hwnd, IDC_IP_REFRESH, FALSE);

	_r_listview_fillitems (hwnd, IDC_IP_RESULT, -1, -1, 1, L"Loading...", I_IMAGENONE);

	hsession = _r_inet_createsession (NULL);

	if (!hsession)
		return STATUS_NETWORK_BUSY;

	address = _r_obj_createstring (IP_ADDRESS);

	status = _r_inet_openurl (hsession, address, &hconnect, &hrequest, NULL);

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

			if (!readed)
				break;
		}

		result = TRUE;
	}

	if (!result)
		_r_listview_fillitems (hwnd, IDC_IP_RESULT, -1, -1, 1, L"Error...", IL_FAULT);

	_r_ctrl_enable (hwnd, IDC_IP_REFRESH, TRUE);

	_r_inet_close (hsession);
	_r_inet_close (hconnect);
	_r_inet_close (hrequest);

	_r_obj_dereference (address);

	return STATUS_SUCCESS;
}

NTSTATUS GetDownloadSpeed (
	_In_ LPVOID lparam
)
{
	HWND hwnd;
	HINTERNET hsession = NULL;
	HINTERNET hconnect = NULL;
	HINTERNET hrequest = NULL;
	PR_STRING url;
	SYSTEMTIME st = {0};
	WCHAR buffer[256] = {0};
	BYTE buff[0x8000] = {0};
	ULONG_PTR page_id;
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
	INT item_id;
	ULONG status;

	hwnd = (HWND)lparam;
	limit = _r_ctrl_getinteger (hwnd, IDC_SPEEDMETER_LIMIT, NULL);
	page_id = GetPageId (IDD_PAGE_SPEEDMETER);

	_r_ctrl_setstring (hwnd, IDC_SPEEDMETER_START, L"Прервать");
	_r_ctrl_enable (hwnd, IDC_SPEEDMETER_CLEAR, FALSE);

	page_list[page_id].thread = TRUE;

	url = _r_ctrl_getstring (hwnd, IDC_SPEEDMETER_LINK);

	if (!url)
		goto END;

	hsession = _r_inet_createsession (NULL);

	if (!hsession)
		goto END;

	status = _r_inet_openurl (hsession, url, &hconnect, &hrequest, NULL);

	if (status == ERROR_SUCCESS)
	{
		RtlQueryPerformanceCounter (&p1);
		RtlQueryPerformanceCounter (&freq);

		while (TRUE)
		{
			if (!page_list[page_id].thread)
				break;

			if (_r_inet_readrequest (hrequest, buff, sizeof (buff), &recieved, &total_size))
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

				item_id = 0;

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

		GetLocalTime (&st);

		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
		_r_listview_setitem (hwnd, IDC_SPEEDMETER_RESULT, item_id++, 6, buffer);
	}
	else
	{
		_r_show_message (hwnd, MB_OK | MB_ICONSTOP, NULL, L"Can't access url.");
	}

END:

	if (hsession)
		_r_inet_close (hsession);

	if (hconnect)
		_r_inet_close (hconnect);

	if (hrequest)
		_r_inet_close (hrequest);

	if (url)
		_r_obj_dereference (url);

	page_list[page_id].thread = FALSE;

	_r_ctrl_setstring (hwnd, IDC_SPEEDMETER_START, L"Start");

	_r_ctrl_enable (hwnd, IDC_SPEEDMETER_START, TRUE);
	_r_ctrl_enable (hwnd, IDC_SPEEDMETER_CLEAR, TRUE);

	return STATUS_SUCCESS;
}

NTSTATUS GetWhois (
	_In_ LPVOID lparam
)
{
	HWND hwnd;
	SOCKET sock = 0;
	WCHAR buffer[256] = {0};
	CHAR buffer2[256] = {0};
	CHAR domain[256] = {0};
	CHAR server[256] = {0};
	R_STRINGBUILDER str;
	R_STRINGREF substring;

	hwnd = (HWND)lparam;

	_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, L"");

	_r_ctrl_enable (hwnd, IDC_WHOIS_START, FALSE);
	_r_ctrl_enable (hwnd, IDC_WHOIS_CLEAR, FALSE);

	_r_obj_initializestringbuilder (&str, 256);

	if (!GetDlgItemTextA (hwnd, IDC_WHOIS_HOST, domain, RTL_NUMBER_OF (domain)) || !GetDlgItemTextA (hwnd, IDC_WHOIS_SERVER, server, RTL_NUMBER_OF (server)))
	{
		_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, L"Необходимо ввести адрес домена и сервер");
		goto WHOIS_RETN;
	}

	//ddr.sin_family = AF_INET;
	//ddr.sin_port = htons (43);
	//ddr.sin_addr.s_addr = inet_addr (server);
	//
	//f (addr.sin_addr.S_un.S_addr == INADDR_NONE)
	//
	//	host = gethostbyname (server);
	//
	//	if (!host)
	//	{
	//		_r_str_printf (buffer, RTL_NUMBER_OF(buffer),, L"Ошибка выполнения gethostbyname() (код ошибки %d)", PebLastError ());
	//		_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, buffer);
	//
	//		goto WHOIS_RETN;
	//	}
	//
	//	addr.sin_addr.S_un.S_addr = ((LPIN_ADDR)host->h_addr)->s_addr;
	//

	sock = socket (AF_INET, SOCK_STREAM, 0);

	if (sock == INVALID_SOCKET)
	{
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Ошибка выполнения socket() (код ошибки %d)", PebLastError ());
		_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, buffer);

		goto WHOIS_RETN;
	}

	//if (connect (sock, &addr, sizeof (sockaddr)) == SOCKET_ERROR)
	//{
	//	_r_str_printf (buffer, RTL_NUMBER_OF(buffer), L"Ошибка выполнения connect() (код ошибки %i)", PebLastError ());
	//	_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, buffer);
	//
	//	goto WHOIS_RETN;
	//}

	StringCchCatA (domain, RTL_NUMBER_OF (domain), "\r\n");
	//WSASend (sock, domain, (INT)strlen (domain), 0);

	while (TRUE)
	{
		memset (&buffer2, 0, sizeof (buffer2));

		if (!recv (sock, buffer2, sizeof (buffer2), 0))
			break;

		_r_obj_appendstringbuilder (&str, buffer); // buffer2 
	}

	_r_obj_initializestringref (&substring, (LPWSTR)L"\n");

WHOIS_RETN:

	if (sock)
		closesocket (sock);

	_r_ctrl_enable (hwnd, IDC_WHOIS_START, TRUE);
	_r_ctrl_enable (hwnd, IDC_WHOIS_CLEAR, TRUE);

	return STATUS_SUCCESS;
}

VOID UrlDecoder (
	_In_ HWND hwnd
)
{
	PR_STRING string;
	WCHAR buffer[256];
	ULONG size;

	_r_ctrl_setstring (hwnd, IDC_URLDECODER_RESULT, L"");

	_r_ctrl_enable (hwnd, IDC_URLDECODER_START, FALSE);
	_r_ctrl_enable (hwnd, IDC_URLDECODER_CLEAR, FALSE);

	string = _r_ctrl_getstring (hwnd, IDC_URLDECODER_LINK);

	if (!string)
		return;

	size = RTL_NUMBER_OF (buffer);

	if (UrlUnescape (string->buffer, buffer, &size, URL_ESCAPE_PERCENT) != S_OK)
		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Can't escape address (0x%08X)", PebLastError ());

	_r_ctrl_setstring (hwnd, IDC_URLDECODER_RESULT, buffer);

	_r_ctrl_enable (hwnd, IDC_URLDECODER_START, TRUE);
	_r_ctrl_enable (hwnd, IDC_URLDECODER_CLEAR, TRUE);
}

VOID GetIpAddress (
	_In_ HWND hwnd
)
{
	if (_r_ctrl_isbuttonchecked (hwnd, IDC_IP_EXTERNAL_CHK))
	{
		_r_sys_createthread (&GetExternalIp, hwnd, NULL, NULL, L"ExternalIp");
	}
	else
	{
		_r_listview_fillitems (hwnd, IDC_IP_RESULT, -1, -1, 1, L"n/a", IL_FAULT);
	}
}

VOID GetSharedType (
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

VOID GetSharedInfo (
	_In_ HWND hwnd
)
{
	NET_API_STATUS status;
	WCHAR buffer[256];
	PSHARE_INFO_502 share_info = NULL;
	PSHARE_INFO_502 p;
	ULONG readed;
	ULONG resume_handle = 0;
	ULONG total;
	INT item_id = 0;

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

				GetSharedType (buffer, RTL_NUMBER_OF (buffer), p->shi502_type);
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

VOID GetSysInfo (
	_In_ HWND hwnd
)
{
	RTL_OSVERSIONINFOEXW version_info;
	PFIXED_INFO network_params;
	WCHAR buffer[128];
	WCHAR buffer2[256];
	CHAR szBufferA[16];
	NTSTATUS status;
	ULONG out_length;
	ULONG flags;
	SOCKET sock;
	INT item_id = 0;

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

	flags = 0;

	if (IsNetworkAlive (&flags))
	{
		ZeroMemory (buffer2, sizeof (buffer2));

		if (flags & NETWORK_ALIVE_LAN)
			_r_str_append (buffer2, RTL_NUMBER_OF (buffer2), L"LAN");

		if (flags & NETWORK_ALIVE_WAN)
		{
			if (flags & NETWORK_ALIVE_LAN)
				_r_str_append (buffer2, RTL_NUMBER_OF (buffer2), L" + ");

			_r_str_append (buffer2, RTL_NUMBER_OF (buffer2), L"WAN");
		}

		_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Enabled (%s)", buffer2);
	}
	else
	{
		_r_str_copy (buffer, RTL_NUMBER_OF (buffer), L"Disabled");
	}

	_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, buffer);

	out_length = sizeof (FIXED_INFO);
	network_params = _r_mem_allocate (out_length);

	if (GetNetworkParams (network_params, &out_length) == ERROR_BUFFER_OVERFLOW)
	{
		_r_mem_free (network_params);
		network_params = _r_mem_allocate (out_length);
	}

	if (GetNetworkParams (network_params, &out_length) == NO_ERROR && network_params)
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
				_r_str_printf (buffer, RTL_NUMBER_OF (buffer), L"Unknown (0x%08x)", network_params->NodeType);
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

	flags = RTL_NUMBER_OF (buffer);
	GetUserName (buffer, &flags);
	_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, buffer);

	Lv_InsertItemA (hwnd, IDC_SYSINFO, gethostname (szBufferA, RTL_NUMBER_OF (szBufferA)) ? "n/a" : szBufferA, item_id++, 1);

	flags = RTL_NUMBER_OF (buffer);
	GetComputerNameEx (ComputerNameDnsHostname, buffer, &flags);
	_r_listview_setitem (hwnd, IDC_SYSINFO, item_id++, 1, buffer);
}

VOID GetHostAddress (
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

	_r_ctrl_enable (hwnd, IDC_HOSTADDR_START, FALSE);
	_r_ctrl_enable (hwnd, IDC_HOSTADDR_CLEAR, FALSE);

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	url = _r_ctrl_getstring (hwnd, IDC_HOSTADDR_HOST);

	if (!url)
		return;

	if (GetAddrInfoW (url->buffer, NULL, &hints, &result) == ERROR_SUCCESS)
	{
		for (PADDRINFOW ptr = result; ptr; ptr = ptr->ai_next)
		{
			sockaddr_ip = ptr->ai_addr;

			length = RTL_NUMBER_OF (ipaddr);

			if (WSAAddressToString (sockaddr_ip, (ULONG)ptr->ai_addrlen, NULL, ipaddr, &length) == ERROR_SUCCESS)
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

NTSTATUS GetUrlInfo (
	_In_ LPVOID lparam
)
{
	HWND hwnd;
	HINTERNET hsession;
	HINTERNET hconnect;
	HINTERNET hrequest;
	PR_STRING url;
	PR_STRING string;
	SYSTEMTIME st = {0};
	WCHAR buffer[256] = {0};
	LONG64 timestamp;
	ULONG flags = 0;
	ULONG length;
	ULONG status;
	INT item_id = 0;

	hwnd = (HWND)lparam;

	_r_ctrl_setstring (hwnd, IDC_URLINFO_HEADER, NULL);

	_r_ctrl_enable (hwnd, IDC_URLINFO_START, FALSE);

	url = _r_ctrl_getstring (hwnd, IDC_URLINFO_LINK);

	hsession = _r_inet_createsession (NULL);

	if (!hsession)
		return 0;

	status = _r_inet_openurl (hsession, url, &hconnect, &hrequest, NULL);

	if (status != ERROR_SUCCESS)
	{
		_r_show_errormessage (hwnd, NULL, PebLastError (), L"Произошла ошибка при открытии ссылки", NULL, NULL);
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

	string = _r_format_unixtime (timestamp);

	if (timestamp && string)
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, string->buffer);
	}
	else
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, L"no");
	}

	length = sizeof (buffer);
	BOOL wu = WinHttpQueryOption (hrequest, WINHTTP_QUERY_ACCEPT_RANGES, &buffer, &length);

	_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, wu ? L"Supported" : L"Unsupported");

	length = sizeof (buffer);

	if (WinHttpQueryOption (hrequest, WINHTTP_QUERY_CONTENT_TYPE, &buffer, &length))
	{
		_r_listview_setitem (hwnd, IDC_URLINFO_RESULT, item_id++, 1, buffer);
	}

	length = sizeof (buffer);

	if (WinHttpQueryOption (hrequest, WINHTTP_QUERY_ETAG, &buffer, &length))
	{
		StrTrim (buffer, L"\""); // Strip Quotes
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

	if (url)
		_r_obj_dereference (url);

	if (string)
		_r_obj_dereference (string);

	_r_inet_close (hsession);

	if (hconnect)
		_r_inet_close (hconnect);

	if (hrequest)
		_r_inet_close (hrequest);

	_r_ctrl_enable (hwnd, IDC_URLINFO_START, TRUE);

	return STATUS_SUCCESS;
}

VOID PrintTcpStats (
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

VOID PrintUdpStats (
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

VOID PrintIcmpStats (
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

VOID PrintIpStats (
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

	dlg_id = GetCurrentPage (hwnd);

	hwnd = page_list[dlg_id].hpage;


	switch (page_list[dlg_id].dlg_id)
	{
		case IDD_PAGE_TCP_STATISTIC:
		{
			PrintTcpStats (hwnd, &tcp_stat, AF_INET);
			PrintTcpStats (hwnd, &tcp_stat, AF_INET6);

			break;
		}

		case IDD_PAGE_UDP_STATISTIC:
		{
			PrintUdpStats (hwnd, &udp_stat, AF_INET);
			PrintUdpStats (hwnd, &udp_stat, AF_INET6);

			break;
		}

		case IDD_PAGE_ICMP_STATISTIC:
		{
			PrintIcmpStats (hwnd, &icmp_stat, AF_INET);
			PrintIcmpStats (hwnd, &icmp_stat, AF_INET6);

			break;
		}

		case IDD_PAGE_IP_STATISTIC:
		{
			PrintIpStats (hwnd, &ip_stat, AF_INET);
			PrintIpStats (hwnd, &ip_stat, AF_INET6);

			break;
		}
	}
}

VOID InitializePages ()
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

	_r_str_copy (category_list[idx++].name, RTL_NUMBER_OF (category_list[idx].name), L"Tools");
	_r_str_copy (category_list[idx++].name, RTL_NUMBER_OF (category_list[idx].name), L"Information");
	_r_str_copy (category_list[idx++].name, RTL_NUMBER_OF (category_list[idx].name), L"Statistics");

	// pages
	idx = 0;

	page_list[idx].dlg_id = IDD_PAGE_PING;
	page_list[idx].listview_id = IDC_PING_RESULT;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"Ping");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Диагностика доступности удаленных ресурсов");

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_SPEEDMETER;
	page_list[idx].listview_id = IDC_SPEEDMETER_RESULT;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"Download speed");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Тестирование скорости загрузки данных из сети");

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_URLDECODER;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"Url decoder");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Приведение ссылок из \"percent-encoding\" в нормальный вид");

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_URLINFO;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"Link information");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Получение списка IP адресов сайта");

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_HOSTADDR;
	page_list[idx].listview_id = IDC_HOSTADDR_RESULT;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"Host address");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Вывод списка IP адресов в системе");

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_WHOIS;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"Whois");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Получение регистрационных данных о владельцах доменных имен");

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_IP;
	page_list[idx].category = 1;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"IP");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Вывод информации о общих ресурсах в системе");

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_SHAREDINFO;
	page_list[idx].listview_id = IDC_SHAREDINFO;
	page_list[idx].category = 1;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"Shared resources");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Вывод информации о общих ресурсах в системе");

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_SYSINFO;
	page_list[idx].listview_id = IDC_SYSINFO;
	page_list[idx].category = 1;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"System");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Показ краткой информации о системе");

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_TCP_STATISTIC;
	page_list[idx].listview_id = IDC_TCP_STATISTIC;
	page_list[idx].category = 2;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"TCP");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Статистика использования TCP протокола");

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_UDP_STATISTIC;
	page_list[idx].listview_id = IDC_UDP_STATISTIC;
	page_list[idx].category = 2;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"UDP");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Статистика использования UDP протокола");

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_ICMP_STATISTIC;
	page_list[idx].listview_id = IDC_ICMP_STATISTIC;
	page_list[idx].category = 2;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"ICMP");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Статистика использования ICMP протокола");

	idx += 1;

	page_list[idx].dlg_id = IDD_PAGE_IP_STATISTIC;
	page_list[idx].listview_id = IDC_IP_STATISTIC;
	page_list[idx].category = 2;

	_r_str_copy (page_list[idx].title, RTL_NUMBER_OF (page_list[idx].title), L"IP");
	_r_str_copy (page_list[idx].description, RTL_NUMBER_OF (page_list[idx].description), L"Статистика использования IP");
}

VOID InitializePage (
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
			SendDlgItemMessage (hwnd, IDC_PING_UPDOWN, UDM_SETRANGE32, 1, 1000);

			_r_ctrl_setstring (hwnd, IDC_PING_HOST, _r_obj_getstring (_r_config_getstring (L"PingAddress", APP_HOST)));

			SetDlgItemInt (hwnd, IDC_PING_RETRIES, _r_config_getlong (L"PingRetries", 5), TRUE);

			_r_listview_setstyle (hwnd, IDC_PING_RESULT, EX_STYLE, FALSE);

			_r_listview_setimagelist (hwnd, IDC_PING_RESULT, himglist);

			_r_listview_addcolumn (hwnd, IDC_PING_RESULT, 0, L"Address", 190, 0);
			_r_listview_addcolumn (hwnd, IDC_PING_RESULT, 1, L"Size", 100, 0);
			_r_listview_addcolumn (hwnd, IDC_PING_RESULT, 2, L"Delay", 80, 0);
			_r_listview_addcolumn (hwnd, IDC_PING_RESULT, 3, L"TTL", 80, 0);

			break;
		}

		case IDD_PAGE_SPEEDMETER:
		{
			_r_listview_setstyle (hwnd, IDC_SPEEDMETER_RESULT, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_SPEEDMETER_RESULT, himglist);

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

			SendDlgItemMessage (hwnd, IDC_SPEEDMETER_UPDOWN, UDM_SETRANGE32, 0, 1000);

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

			_r_listview_setimagelist (hwnd, IDC_HOSTADDR_RESULT, himglist);

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
				SendDlgItemMessage (hwnd, IDC_WHOIS_SERVER, CB_ADDSTRING, 0, (LPARAM)whois_servers[i].server);

			item_id = _r_config_getlong (L"WhoisServer", 0);

			if (item_id == CB_ERR)
			{
				_r_ctrl_setstring (hwnd, IDC_WHOIS_SERVER, _r_obj_getstring (_r_config_getstring (L"WhoisServerCustom", whois_servers[0].server)));
			}
			else
			{
				SendDlgItemMessage (hwnd, IDC_WHOIS_SERVER, CB_SETCURSEL, item_id, 0);
			}

			break;
		}

		case IDD_PAGE_URLINFO:
		{
			_r_listview_setstyle (hwnd, IDC_URLINFO_RESULT, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_URLINFO_RESULT, himglist);

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

			PostMessage (hwnd, WM_COMMAND, MAKELPARAM (IDC_URLINFO_HEADER_CHK, 0), 0);

			break;
		}

		case IDD_PAGE_IP:
		{
			_r_listview_setstyle (hwnd, IDC_IP_RESULT, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_IP_RESULT, himglist);

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

			PostMessage (hwnd, WM_COMMAND, MAKELPARAM (IDC_IP_REFRESH, 0), 0);

			break;
		}

		case IDD_PAGE_SHAREDINFO:
		{
			_r_listview_setstyle (hwnd, IDC_SHAREDINFO, EX_STYLE, FALSE);

			_r_listview_setimagelist (hwnd, IDC_SHAREDINFO, himglist);

			_r_listview_addcolumn (hwnd, IDC_SHAREDINFO, 0, L"Name", 190, 0);
			_r_listview_addcolumn (hwnd, IDC_SHAREDINFO, 1, L"Path", 190, 0);
			_r_listview_addcolumn (hwnd, IDC_SHAREDINFO, 2, L"Type", 190, 0);
			_r_listview_addcolumn (hwnd, IDC_SHAREDINFO, 3, L"Connected", 190, 0);

			PostMessage (hwnd, WM_COMMAND, MAKELPARAM (IDC_SHAREDINFO_START, 0), 0);

			break;
		}

		case IDD_PAGE_SYSINFO:
		{
			_r_listview_setstyle (hwnd, IDC_SYSINFO, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_SYSINFO, himglist);

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

			GetSysInfo (hwnd);

			break;
		}

		case IDD_PAGE_TCP_STATISTIC:
		{
			_r_listview_setstyle (hwnd, IDC_TCP_STATISTIC, EX_STYLE, TRUE);

			_r_listview_setimagelist (hwnd, IDC_TCP_STATISTIC, himglist);

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

			_r_listview_setimagelist (hwnd, IDC_UDP_STATISTIC, himglist);

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

			_r_listview_setimagelist (hwnd, IDC_ICMP_STATISTIC, himglist);

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

			_r_listview_setimagelist (hwnd, IDC_IP_STATISTIC, himglist);

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
	//static R_LAYOUT_MANAGER layout = {0};

	switch (msg)
	{
		case WM_INITDIALOG:
		{
			//_r_layout_initializemanager (&layout, hwnd);

			InitializePage (hwnd, IDD_PAGE_PING);
			InitializePage (hwnd, IDD_PAGE_SPEEDMETER);
			InitializePage (hwnd, IDD_PAGE_URLDECODER);
			InitializePage (hwnd, IDD_PAGE_HOSTADDR);
			InitializePage (hwnd, IDD_PAGE_URLINFO);
			InitializePage (hwnd, IDD_PAGE_IP);
			InitializePage (hwnd, IDD_PAGE_WHOIS);
			InitializePage (hwnd, IDD_PAGE_SHAREDINFO);
			InitializePage (hwnd, IDD_PAGE_SYSINFO);
			InitializePage (hwnd, IDD_PAGE_TCP_STATISTIC);
			InitializePage (hwnd, IDD_PAGE_UDP_STATISTIC);
			InitializePage (hwnd, IDD_PAGE_ICMP_STATISTIC);
			InitializePage (hwnd, IDD_PAGE_IP_STATISTIC);

			break;
		}

		case WM_SIZE:
		{
			//_r_layout_resize (&layout, wparam);
			break;
		}

		case WM_DESTROY:
		{
			WCHAR buffer[256] = {0};
			LONG item_id;
			BOOL status = FALSE;

			if (GetDlgItem (hwnd, IDC_PING_HOST))
			{
				GetDlgItemText (hwnd, IDC_PING_HOST, buffer, RTL_NUMBER_OF (buffer));
				_r_config_setstring (L"PingAddress", buffer);
			}

			if (GetDlgItem (hwnd, IDC_PING_RETRIES))
			{
				item_id = GetDlgItemInt (hwnd, IDC_PING_RETRIES, &status, TRUE);

				if (status)
					_r_config_setlong (L"PingRetries", item_id);
			}

			if (GetDlgItem (hwnd, IDC_SPEEDMETER_LINK))
			{
				item_id = GetDlgItemInt (hwnd, IDC_SPEEDMETER_LIMIT, &status, TRUE);

				if (status)
					_r_config_setlong (L"SpeedMeterLimit", item_id);

				GetDlgItemText (hwnd, IDC_SPEEDMETER_LINK, buffer, RTL_NUMBER_OF (buffer));
				_r_config_setstring (L"SpeedmeterLink", buffer);
			}

			if (GetDlgItem (hwnd, IDC_URLDECODER_LINK))
			{
				GetDlgItemText (hwnd, IDC_URLDECODER_LINK, buffer, RTL_NUMBER_OF (buffer));
				_r_config_setstring (L"UrlDecoderLink", buffer);
			}

			if (GetDlgItem (hwnd, IDC_HOSTADDR_HOST))
			{
				GetDlgItemText (hwnd, IDC_HOSTADDR_HOST, buffer, RTL_NUMBER_OF (buffer));
				_r_config_setstring (L"HostAddrAddress", buffer);
			}

			if (GetDlgItem (hwnd, IDC_URLINFO_LINK))
			{
				GetDlgItemText (hwnd, IDC_URLINFO_LINK, buffer, RTL_NUMBER_OF (buffer));
				_r_config_setstring (L"UrlInfoLink", buffer);
			}

			if (GetDlgItem (hwnd, IDC_URLINFO_HEADER_CHK))
				_r_config_setboolean (L"UrlInfoShowHeader", _r_ctrl_isbuttonchecked (hwnd, IDC_URLINFO_HEADER_CHK));

			if (GetDlgItem (hwnd, IDC_IP_EXTERNAL_CHK))
				_r_config_setboolean (L"RetrieveExternalIp", _r_ctrl_isbuttonchecked (hwnd, IDC_IP_EXTERNAL_CHK));

			if (GetDlgItem (hwnd, IDC_WHOIS_HOST))
			{
				GetDlgItemText (hwnd, IDC_WHOIS_HOST, buffer, RTL_NUMBER_OF (buffer));
				_r_config_setstring (L"WhoisAddress", buffer);
			}

			if (GetDlgItem (hwnd, IDC_WHOIS_SERVER))
			{
				item_id = (LONG)SendDlgItemMessage (hwnd, IDC_WHOIS_SERVER, CB_GETCURSEL, 0, 0);

				if (item_id == CB_ERR)
				{
					GetDlgItemText (hwnd, IDC_WHOIS_SERVER, buffer, RTL_NUMBER_OF (buffer));
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

			page_id = GetCurrentPage (hwnd);

			if (!page_list[page_id].listview_id)
				break;

			hmenu = LoadMenu (NULL, MAKEINTRESOURCE (IDM_LISTVIEW));
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

			//if (PostMessage ((HWND)PostMessage ((HWND)wparam, LVM_GETHEADER, 0, 0), HDM_GETITEMCOUNT, 0, 0) != 2)
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
					INT item_id;
					INT column_count;

					page_id = GetCurrentPage (hwnd);

					if (!page_list[page_id].listview_id)
						break;

					if (GetFocus () != GetDlgItem (page_list[page_id].hpage, page_list[page_id].listview_id))
						break;

					item_id = -1;

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

					page_id = GetCurrentPage (hwnd);

					if (!page_list[page_id].listview_id)
						break;

					if (GetFocus () != GetDlgItem (page_list[page_id].hpage, page_list[page_id].listview_id))
						break;

					_r_listview_setitemstate (page_list[page_id].hpage, page_list[page_id].listview_id, -1, LVIS_SELECTED, LVIS_SELECTED);

					break;
				}
				*/
				/*
				case IDC_LISTVIEW_COPY:
				{
					//PR_STRING string;
					//
					//if (GetListViewText (GetDlgItem (hwnd, page_list.listview_id[page_id]), buff, 4096, 1))
					//	_r_clipboard_set (hwnd, &string->sr);

					break;
				}

				case IDC_COPY_VALUE:
				{
					//WCHAR buff[4096] = {0};
					//ULONG_PTR page_id;
					//
					//page_id = GetCurrentPage (hwnd);
					//
					//if (GetListViewText (GetDlgItem (hwnd, page_list[page_id].listview_id), buff, 4096, 1, 1))
					//	SetClipboardText (buff, 4096);

					break;
				}

				case IDC_SAVE_AS:
				{
					//OPENFILENAME of = {0};
					//WCHAR buff[4096] = {0};
					//HANDLE hfile;
					//CHAR header[2] = {0xFF, 0xFE};
					//ULONG dwWriten = 0;
					//
					//_r_str_copy (buffer, RTL_NUMBER_OF(buffer), L"report.txt");
					//
					//of.lStructSize = sizeof (of);
					//of.hwndOwner = hwnd;
					//of.lpstrFilter = L"Все файлы (*.*)\0*.*";
					//of.lpstrFile = buffer;
					//of.nMaxFile = RTL_NUMBER_OF(buffer);
					//of.Flags = OFN_EXPLORER | OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
					//
					//if (GetSaveFileName (&of))
					//{
					//	if (GetListViewText (GetDlgItem (hwnd, page_list[page_id].listview_id), buff, 4096))
					//	{
					//		hfile = CreateFile (buffer, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
					//
					//		if (!hfile)
					//			break;
					//
					//		WriteFile (hfile, header, 2, &dwWriten, NULL); // Write Header
					//		WriteFile (hfile, buff, (lstrlen (buff) * 2) + dwWriten - 1, &dwWriten, NULL); // Write Text
					//
					//		CloseHandle (hfile);
					//	}
					//}

					break;
				}
				*/
				case IDC_PING_START:
				{
					ULONG_PTR page_id;

					page_id = GetPageId (IDD_PAGE_PING);

					if (page_list[page_id].thread)
					{
						if (_r_show_message (hwnd, MB_YESNO | MB_ICONEXCLAMATION, NULL, L"Do you want to clear data?") == IDYES)
							page_list[page_id].thread = FALSE;
					}
					else
					{
						_r_sys_createthread (&GetPing, hwnd, NULL, NULL, L"Ping");
					}

					break;
				}

				case IDC_PING_CLEAR:
				{
					if (_r_listview_getitemcount (hwnd, IDC_PING_RESULT))
					{
						if (_r_show_message (hwnd, MB_YESNO | MB_ICONEXCLAMATION, NULL, L"Do you want to clear data?") == IDYES)
							_r_listview_deleteallitems (hwnd, IDC_PING_RESULT);
					}

					break;
				}

				case IDC_SPEEDMETER_START:
				{
					ULONG_PTR page_id;

					page_id = GetPageId (IDD_PAGE_SPEEDMETER);

					if (page_list[page_id].thread)
					{
						if (_r_show_message (hwnd, MB_YESNO | MB_ICONEXCLAMATION, NULL, L"Do you want to clear data?") == IDYES)
							page_list[page_id].thread = FALSE;
					}
					else
					{
						_r_sys_createthread (&GetDownloadSpeed, hwnd, NULL, NULL, L"DownloadSpeed");
					}

					break;
				}

				case IDC_SPEEDMETER_CLEAR:
				{
					if (!_r_listview_getitemcount (hwnd, IDC_SPEEDMETER_RESULT))
						break;

					if (_r_show_message (hwnd, MB_YESNO | MB_ICONEXCLAMATION, NULL, L"Do you want to clear data?") == IDYES)
						_r_listview_deleteallitems (hwnd, IDC_SPEEDMETER_RESULT);

					break;
				}

				case IDC_URLDECODER_START:
				{
					UrlDecoder (hwnd);
					break;
				}

				case IDC_URLDECODER_CLEAR:
				{
					if (_r_ctrl_getstringlength (hwnd, IDC_URLDECODER_RESULT))
					{
						if (_r_show_message (hwnd, MB_YESNO | MB_ICONEXCLAMATION, NULL, L"Do you want to clear data?") == IDYES)
							_r_ctrl_setstring (hwnd, IDC_URLDECODER_RESULT, NULL);
					}

					break;
				}

				case IDC_HOSTADDR_START:
				{
					GetHostAddress (hwnd);
					break;
				}

				case IDC_HOSTADDR_CLEAR:
				{
					if (_r_listview_getitemcount (hwnd, IDC_HOSTADDR_RESULT))
					{
						if (_r_show_message (hwnd, MB_YESNO | MB_ICONEXCLAMATION, NULL, L"Do you want to clear data?") == IDYES)
							_r_listview_deleteallitems (hwnd, IDC_HOSTADDR_RESULT);
					}

					break;
				}

				case IDC_URLINFO_START:
				{
					_r_sys_createthread (&GetUrlInfo, hwnd, NULL, NULL, L"UrlInfo");
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
					GetIpAddress (hwnd);
					break;
				}

				case IDC_WHOIS_START:
				{
					_r_sys_createthread (&GetWhois, hwnd, NULL, NULL, L"Whois");
					break;
				}

				case IDC_WHOIS_CLEAR:
				{
					if (_r_ctrl_getstringlength (hwnd, IDC_WHOIS_RESULT))
					{
						if (_r_show_message (hwnd, MB_YESNO | MB_ICONEXCLAMATION, NULL, L"Do you want to clear data?") == IDYES)
							_r_ctrl_setstring (hwnd, IDC_WHOIS_RESULT, NULL);
					}

					break;
				}

				case IDC_SHAREDINFO_START:
				{
					GetSharedInfo (hwnd);
					break;
				}

				case IDC_SHAREDINFO_CLEAR:
				{
					if (_r_listview_getitemcount (hwnd, IDC_SHAREDINFO))
					{
						if (_r_show_message (hwnd, MB_YESNO | MB_ICONEXCLAMATION, NULL, L"Do you want to clear data?") == IDYES)
							_r_listview_deleteallitems (hwnd, IDC_SHAREDINFO);
					}

					break;
				}
			}

			break;
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
			HMENU hmenu;
			HICON hicon;
			ULONG_PTR page_id;
			LONG status;
			INT parts[2] = {0};

			InitializePages ();

			status = WSAStartup (WINSOCK_VERSION, &wsa);

			if (status != ERROR_SUCCESS)
			{
				_r_show_errormessage (hwnd, APP_NAME, status, NULL, NULL, NULL);

				RtlExitUserProcess (status);
			}

			_r_treeview_setstyle (hwnd, IDC_ITEMLIST, TVS_EX_DOUBLEBUFFER | TVS_EX_FADEINOUTEXPANDOS, 0, 0);

			himglist = ImageList_Create (16, 16, ILC_COLOR32 | ILC_MASK, 0, 5);

			_r_sys_loadicon (_r_sys_getimagebase (), MAKEINTRESOURCE (IDI_FOLDER), 16, &hicon);
			ImageList_ReplaceIcon (himglist, -1, hicon);

			_r_sys_loadicon (_r_sys_getimagebase (), MAKEINTRESOURCE (IDI_FOLDER_CURRENT), 16, &hicon);
			ImageList_ReplaceIcon (himglist, -1, hicon);

			_r_sys_loadicon (_r_sys_getimagebase (), MAKEINTRESOURCE (IDI_SUCCESS), 16, &hicon);
			ImageList_ReplaceIcon (himglist, -1, hicon);

			_r_sys_loadicon (_r_sys_getimagebase (), MAKEINTRESOURCE (IDI_FAULT), 16, &hicon);
			ImageList_ReplaceIcon (himglist, -1, hicon);

			SendDlgItemMessage (hwnd, IDC_ITEMLIST, TVM_SETIMAGELIST, TVSIL_NORMAL, (LPARAM)himglist);

			hmenu = GetMenu (hwnd);

			if (hmenu)
			{
				_r_menu_checkitem (hmenu, IDM_ALWAYSONTOP_CHK, 0, MF_BYCOMMAND, _r_config_getboolean (L"AlwaysOnTop", FALSE));
				_r_menu_checkitem (hmenu, IDM_CHECKUPDATES_CHK, 0, MF_BYCOMMAND, _r_update_isenabled (FALSE));
			}

			parts[0] = 200;
			parts[1] = -1;

			_r_status_setparts (hwnd, IDC_STATUSBAR, parts, RTL_NUMBER_OF (parts));

			for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (category_list); i++)
			{
				category_list[i].hitem = _r_treeview_additem (hwnd, IDC_ITEMLIST, category_list[i].name, IL_FOLDER, NULL, NULL, 0);
			}

			for (ULONG_PTR i = 0; i < RTL_NUMBER_OF (page_list); i++)
			{
				page_list[i].hitem = _r_treeview_additem (hwnd, IDC_ITEMLIST, page_list[i].title, IL_FOLDER, category_list[page_list[i].category].hitem, NULL, (LPARAM)i);

				page_list[i].hpage = _r_wnd_createwindow (_r_sys_getimagebase (), MAKEINTRESOURCE (page_list[i].dlg_id), hwnd, &PageDlgProc, NULL);

				if (page_list[i].hpage)
					SetPagePos (hwnd, page_list[i].hpage);
			}

			page_id = GetCurrentPage (hwnd);

			SetCurrentPage (hwnd, _r_config_getlong (L"LastItem", (LONG)GetPageId (IDD_PAGE_SYSINFO)));

			SetTimer (hwnd, 1337, 1000, &TimerProc);

			_r_layout_initializemanager (&layout_manager, hwnd);

			break;
		}

		case WM_CLOSE:
		{
			KillTimer (hwnd, 1337);

			for (INT i = 0; i < PAGE_COUNT; i++)
				page_list[i].thread = FALSE;

			_r_config_setlong (L"LastItem", (LONG)GetCurrentPage (hwnd));

			WSACleanup ();

			DestroyWindow (hwnd);
			PostQuitMessage (0);

			break;
		}

		//case WM_DESTROY:
		//{
		//	KillTimer (hwnd, 1337);
		//
		//	for (INT i = 0; i < PAGE_COUNT; i++)
		//		page_list[i].thread = FALSE;
		//
		//	_r_config_setlong (L"LastItem", (LONG)GetCurrentPage (hwnd));
		//
		//	WSACleanup ();
		//
		//	DestroyWindow (hwnd);
		//	PostQuitMessage (0);
		//
		//	break;
		//}

		case WM_SIZE:
		{
			_r_layout_resize (&layout_manager, wparam);
			break;
		}

		case WM_NOTIFY:
		{
			LPNMHDR lphdr = (LPNMHDR)lparam;

			switch (lphdr->code)
			{
				case TVN_SELCHANGING:
				{
					LPNMTREEVIEW pnmtv;
					TVITEMEX tvi = {0};
					LONG_PTR page_id;

					if (wparam != IDC_ITEMLIST)
						break;

					pnmtv = (LPNMTREEVIEW)lparam;

					page_id = pnmtv->itemOld.lParam;

					if (page_id == -1)
					{
						tvi.hItem = (HTREEITEM)SendMessage (pnmtv->hdr.hwndFrom, TVM_GETNEXTITEM, TVGN_CHILD, (LPARAM)pnmtv->itemNew.hItem);
						tvi.mask = TVIF_HANDLE;

						SendMessage (pnmtv->hdr.hwndFrom, TVM_GETITEM, 0, (LPARAM)&tvi);
						SendMessage (pnmtv->hdr.hwndFrom, TVM_SELECTITEM, TVGN_CARET, (LPARAM)tvi.hItem);

						break;
					}

					if (page_list[page_id].hpage)
						ShowWindow (page_list[page_id].hpage, SW_HIDE);

					break;
				}

				case TVN_SELCHANGED:
				{
					LPNMTREEVIEW pnmtv = (LPNMTREEVIEW)lparam;
					ULONG_PTR page_id;

					if (wparam != IDC_ITEMLIST)
						break;

					page_id = pnmtv->itemNew.lParam;

					if (page_list[page_id].hpage)
						ShowWindow (page_list[page_id].hpage, SW_SHOW);

					if (!page_list[page_id].hpage)
						break;

					SetPagePos (hwnd, page_list[page_id].hpage);

					_r_status_settext (hwnd, IDC_STATUSBAR, 0, page_list[page_id].title);
					_r_status_settext (hwnd, IDC_STATUSBAR, 1, page_list[page_id].description);

					break;
				}

				case NM_CUSTOMDRAW:
				{
					LONG_PTR result;

					result = TreeView_CustDraw (hwnd, (LPNMTVCUSTOMDRAW)lparam);

					SetWindowLongPtr (hwnd, DWLP_MSGRESULT, result);
					return result;
				}
			}

			break;
		}

		case WM_COMMAND:
		{
			INT ctrl_id = LOWORD (wparam);

			switch (ctrl_id)
			{
				case IDCANCEL: // process Esc key
				case IDM_EXIT:
				{
					PostMessage (hwnd, WM_CLOSE, 0, 0);
					break;
				}

				case IDM_ZOOM:
				{
					ShowWindow (hwnd, IsZoomed (hwnd) ? SW_RESTORE : SW_MAXIMIZE);
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

				case IDM_CHECK_UPDATES:
				{
					_r_update_check (hwnd);
					break;
				}

				case IDM_ABOUT:
				{
					_r_show_aboutmessage (hwnd);
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

	hwnd = _r_app_createwindow (
		hinst,
		MAKEINTRESOURCE (IDD_MAIN),
		MAKEINTRESOURCE (IDI_MAIN),
		&DlgProc
	);

	if (!hwnd)
		return ERROR_APP_INIT_FAILURE;

	return _r_wnd_message_callback (hwnd, MAKEINTRESOURCE (IDA_MAIN));
}