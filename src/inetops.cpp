/************************************
*  	InetOps
*	Copyright © 2012 Henry++
*
*	GNU General Public License v2
*	http://www.gnu.org/licenses/
*
*	http://www.henrypp.org/
*************************************/

// Include
#include <windows.h>
#include <commdlg.h>
#include <commctrl.h>
#include <uxtheme.h>
#include <wininet.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <shellapi.h>
#include <sensapi.h>
#include <shlwapi.h>
#include <iostream>
#include <strsafe.h>
#include <lm.h>
#include <process.h>

#include "cjson.h"
#include "inetops.h"
#include "resource.h"
#include "ini.h"
#include "about.h"

using namespace std;

INI cfg;

PAGE_LIST page_list =
{
	{
		L"Пинг",
		L"Скорость загрузки",
		L"Декодер ссылок",
		L"Адрес сайта",
		L"Информация о ссылке",
		L"IP",
		L"Whois",
		L"Общие ресурсы",
		L"Система",
		L"TCP",
		L"UDP",
		L"ICMP",
		L"IP"
	},
	{
		L"Диагностика доступности удаленных ресурсов",
		L"Тестирование скорости загрузки данных из сети",
		L"Приведение ссылок из \"percent-encoding\" в нормальный вид",
		L"Получение списка IP адресов сайта",
		L"Получение информации о ссылке (размер, дата изменения и т.д.)",
		L"Вывод списка IP адресов в системе",
		L"Получение регистрационных данных о владельцах доменных имен",
		L"Вывод информации о общих ресурсах в системе",
		L"Показ краткой информации о системе",
		L"Статистика использования TCP протокола",
		L"Статистика использования UDP протокола",
		L"Статистика использования ICMP протокола",
		L"Статистика использования IP"
	},
	{0},
	0,
	0,
	{0},
	{0},
	{
		IDD_PAGE_PING,
		IDD_PAGE_SPEEDMETER,
		IDD_PAGE_URLDECODER,
		IDD_PAGE_HOSTADDR,
		IDD_PAGE_URLINFO,
		IDD_PAGE_IP,
		IDD_PAGE_WHOIS,
		IDD_PAGE_SHAREDINFO,
		IDD_PAGE_SYSINFO,
		IDD_PAGE_TCP_STATISTIC,
		IDD_PAGE_UDP_STATISTIC,
		IDD_PAGE_ICMP_STATISTIC,
		IDD_PAGE_IP_STATISTIC
	},
	{
		IDC_PING_RESULT,
		IDC_SPEEDMETER_RESULT,
		0,
		0,
		IDC_URLINFO_RESULT,
		IDC_IP_RESULT,
		0,
		IDC_SHAREDINFO,
		IDC_SYSINFO,
		IDC_TCP_STATISTIC,
		IDC_UDP_STATISTIC,
		IDC_ICMP_STATISTIC,
		IDC_IP_STATISTIC
	},
	{0, 0, 0, 0, 0, 1, 0, 1, 1, 2, 2, 2, 2},
};

CATEGORY_LIST category_list =
{
	{L"Инструменты", L"Информация", L"Статистика"},
	{0},
};

// Check Updates
void CheckUpdates(LPVOID lpParam)
{
	unsigned long ulReaded = 0;
	char szBufferA[50] = {0};
    wchar_t szBufferW[50] = {0};

	DWORD dwStatus = 0, dwStatusSize = sizeof(dwStatus);

	// Disable Menu
	EnableMenuItem(GetMenu(hMainDlg), IDM_CHECK_UPDATES, MF_BYCOMMAND | MF_DISABLED);

	// Connect
	HINTERNET hInternet = InternetOpen(APP_NAME L" " APP_VERSION, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	HINTERNET hConnect = InternetOpenUrl(hInternet, APP_WEBSITE L"/update.php?product=" APP_NAME_SHORT, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);

	// Get Status
	HttpQueryInfo(hConnect, HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &dwStatus, &dwStatusSize, NULL);

	// Reading
	InternetReadFile(hConnect, szBufferA, 50, &ulReaded);

	// Check Errors
	if(!hInternet || !hConnect || dwStatus != HTTP_STATUS_OK)
	{
		if(!lpParam)
			MessageBox(hMainDlg, L"Ошибка подключения к серверу обновления", APP_NAME, MB_OK | MB_ICONSTOP);
	}
	else
	{
		// Convert to Unicode
		MultiByteToWideChar(CP_UTF8, 0, szBufferA, 50, szBufferW, 50);

		// If NEWVER == CURVER
		if(lstrcmpi(szBufferW, APP_VERSION) == 0)
		{
			if(!lpParam)
				MessageBox(hMainDlg, L"Вы используете последнюю версию программы", APP_NAME, MB_OK | MB_ICONINFORMATION);
		}
		else
		{
			wchar_t szBuffer[MAX_PATH] = {0};
			StringCchPrintf(szBuffer, MAX_PATH, L"Доступна новая версия программы: %s\r\nВы хотите открыть страницу загрузки новой версии?\0", szBufferW);

			if(MessageBox(hMainDlg, szBuffer, APP_NAME, MB_YESNO | MB_ICONQUESTION) == IDYES)
				ShellExecute(hMainDlg, L"open", APP_WEBSITE, NULL, NULL, SW_SHOW);
		}
	}

	// Enable Menu
	EnableMenuItem(GetMenu(hMainDlg), IDM_CHECK_UPDATES, MF_BYCOMMAND | MF_ENABLED);

	// Clear Memory
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hInternet);
}

// Ping (Miltithread)
void Ping(LPVOID lParam)
{
	HWND hwndDlg = (HWND)lParam;

	char buffa[MAX_PATH] = {0};
	wchar_t buffw[MAX_PATH] = {0};

	// Disable Buttons
	SetDlgItemText(hwndDlg, IDC_PING_START, L"Прервать");
	EnableWindow(GetDlgItem(hwndDlg, IDC_PING_CLEAR), 0);

	// Clear Previous Result
	SendDlgItemMessage(hwndDlg, IDC_PING_RESULT, LVM_DELETEALLITEMS, 0, 0);

	// Init State
	page_list.thread[GetPageId(IDD_PAGE_PING)] = 1;

	if(!GetDlgItemTextA(hwndDlg, IDC_PING_HOST, buffa, MAX_PATH))
	{
		MessageBox(hwndDlg, L"Необходимо ввести адрес хоста или IP адрес", APP_NAME, MB_OK | MB_ICONSTOP);
	}
	else
	{
		unsigned long ip = INADDR_NONE;

		if(StringIsIp(buffa))
		{
			ip = inet_addr(buffa);
		}
		else
		{
			hostent* hostip = gethostbyname(buffa);

			if(!hostip)
			{
				MessageBox(hwndDlg, L"Неудалось получить адрес хоста, либо вы ввели неверный адрес", APP_NAME, MB_OK | MB_ICONSTOP);
				goto PING_RETN;
			}

			in_addr addr = {0};

			addr.s_addr = *(u_long*)hostip->h_addr_list[0];
			ip = inet_addr(inet_ntoa(addr));
		}

		char send_buff[32] = {0};
		in_addr from_ip = {0};

		if(ip == INADDR_NONE)
		{
			MessageBox(hwndDlg, L"Неудалось получить адрес хоста, либо вы ввели неверный адрес", APP_NAME, MB_OK | MB_ICONSTOP);
			goto PING_RETN;
		}

		int iRetries = GetDlgItemInt(hwndDlg, IDC_PING_RETRIES, 0, 1);

		if(!iRetries)
		{
			MessageBox(hwndDlg, L"Не указано количество повторов", APP_NAME, MB_OK | MB_ICONSTOP);
			goto PING_RETN;
		}

		// Clean Previous Result
		SendDlgItemMessage(hwndDlg, IDC_PING_RESULT, LVM_DELETEALLITEMS, 0, 0);

		// Filling ICMP buffer
		char ch = 0;
		for(int i = 0, ch = '0' - 1; i < sizeof(send_buff); ++i)
			send_buff[i] = (ch++ == 126) ? ch = '0': ch;

		HANDLE hIcmpFile = IcmpCreateFile();

		if(hIcmpFile)
		{
			for(int i = 0; i < iRetries; i++)
			{
				if(!page_list.thread[GetPageId(IDD_PAGE_PING)])
					break;

				void* reply = (void*)malloc(sizeof(ICMP_ECHO_REPLY) + sizeof(send_buff));
				IcmpSendEcho(hIcmpFile, ip, send_buff, sizeof(send_buff), NULL, (void*)reply, sizeof(ICMP_ECHO_REPLY) + sizeof(send_buff), 1000);
				ICMP_ECHO_REPLY* icmp_reply = (ICMP_ECHO_REPLY*)reply;

				switch(icmp_reply->Status)
				{
					case IP_SUCCESS:
						// Address
						from_ip.s_addr = icmp_reply->Address;
						Lv_InsertItemA(hwndDlg, IDC_PING_RESULT, inet_ntoa(from_ip), i, 0, IL_SUCCESS);

						// Size
						StringCchPrintf(buffw, MAX_PATH, L"%u bytes\0", icmp_reply->DataSize);
						Lv_InsertItem(hwndDlg, IDC_PING_RESULT, buffw, i, 1, -1);

						// Time
						StringCchPrintf(buffw, MAX_PATH, L"%ld ms\0", icmp_reply->RoundTripTime);
						Lv_InsertItem(hwndDlg, IDC_PING_RESULT, buffw, i, 2, -1);

						// Ttl
						StringCchPrintf(buffw, MAX_PATH, L"%d\0", icmp_reply->Options.Ttl);
						Lv_InsertItem(hwndDlg, IDC_PING_RESULT, buffw, i, 3, -1);

						break;

					case IP_REQ_TIMED_OUT:
						Lv_InsertItem(hwndDlg, IDC_PING_RESULT, L"Timeout\0", i, 0, IL_FAULT);
						break;

					default:
						StringCchPrintf(buffw, MAX_PATH, L"Error: %u\0", icmp_reply->Status);
						Lv_InsertItem(hwndDlg, IDC_PING_RESULT, buffw, i, 0, IL_FAULT);
						break;
				}

				free(reply);
			}

			// Close Handle
			IcmpCloseHandle(hIcmpFile);
		}
	}

	PING_RETN:

	page_list.thread[GetPageId(IDD_PAGE_PING)] = 0;

	// Enable Buttons
	SetDlgItemText(hwndDlg, IDC_PING_START, L"Начать");
	EnableWindow(GetDlgItem(hwndDlg, IDC_PING_START), 1);
	EnableWindow(GetDlgItem(hwndDlg, IDC_PING_CLEAR), 1);
}

// Get External Ip (Miltithread)
void GetExternalIp(LPVOID lParam)
{
	HWND hwndDlg = (HWND)lParam;

	bool bResult = 0;
	unsigned long ulReaded = 0;
	int iItem = 0;

	char szBuffer[MAX_PATH] = {0}, szBuffer2[4096] = {0};

	DWORD dwStatus = 0, dwStatusSize = sizeof(dwStatus);

	// Disable Button
	EnableWindow(GetDlgItem(hwndDlg, IDC_IP_REFRESH), 0);

	// Start Indication
	Lv_Fill(hwndDlg, IDC_IP_RESULT, L"получение...", 1, 0, 6, IL_SUCCESS);

	// Connect
	HINTERNET hInternet = InternetOpen(APP_NAME L" " APP_VERSION, INTERNET_OPEN_TYPE_DIRECT, 0, NULL, 0);
	HINTERNET hUrl = InternetOpenUrl(hInternet, L"http://api.myiptest.com/", 0, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0);

	// Get Status Code
	HttpQueryInfo(hUrl, HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &dwStatus, &dwStatusSize, NULL);

	if(dwStatus == HTTP_STATUS_OK)
	{
		while(1)
		{
			memset(&szBuffer, 0, sizeof(szBuffer));

			if(InternetReadFile(hUrl, szBuffer, MAX_PATH, &ulReaded))
				StringCchCatA(szBuffer2, 4096, szBuffer);

			if(!ulReaded)
				break;
		}

		// Parse JSON
		cJSON* json = cJSON_Parse(szBuffer2);

		if(json)
		{
			bResult = 1;

			Lv_InsertItemA(hwndDlg, IDC_IP_RESULT, cJSON_GetObjectItem(json, "ip")->valuestring, iItem++, 1);
			Lv_InsertItemA(hwndDlg, IDC_IP_RESULT, cJSON_GetObjectItem(json, "proxy")->valuestring, iItem++, 1);
			Lv_InsertItemA(hwndDlg, IDC_IP_RESULT, cJSON_GetObjectItem(json, "isp")->valuestring, iItem++, 1);
			Lv_InsertItemA(hwndDlg, IDC_IP_RESULT, cJSON_GetObjectItem(json, "org")->valuestring, iItem++, 1);

			StringCchPrintfA(szBuffer, 1024, "%s (%s) [%s]\0", cJSON_GetObjectItem(json, "city")->valuestring, cJSON_GetObjectItem(json, "country")->valuestring, _strupr(cJSON_GetObjectItem(json, "ccode")->valuestring));
			Lv_InsertItemA(hwndDlg, IDC_IP_RESULT, szBuffer, iItem++, 1);

			StringCchPrintfA(szBuffer, 1024, "широта (%s), долгота (%s)\0", cJSON_GetObjectItem(json, "long")->valuestring, cJSON_GetObjectItem(json, "lat")->valuestring);
			Lv_InsertItemA(hwndDlg, IDC_IP_RESULT, szBuffer, iItem++, 1);

			cJSON_Delete(json);
		}
	}

	// Error Indication
	if(!bResult)
		Lv_Fill(hwndDlg, IDC_IP_RESULT, L"ошибка", 1, 0, 6, IL_FAULT);

	// Clear Memory
	InternetCloseHandle(hUrl);
	InternetCloseHandle(hInternet);

	// Enable Button
	EnableWindow(GetDlgItem(hwndDlg, IDC_IP_REFRESH), 1);
}

// Get Download Speed (Miltithread)
void GetDownloadSpeed(LPVOID lParam)
{
	HWND hwndDlg = (HWND)lParam;
	HINTERNET hInternet = 0, hFile = 0;
	SYSTEMTIME st = {0};
	UINT uLimit = GetDlgItemInt(hwndDlg, IDC_SPEEDMETER_LIMIT, 0, 0);

	wchar_t szBuffer[MAX_PATH] = {0};

	// Clear Previous Result
	Lv_Fill(hwndDlg, IDC_SPEEDMETER_RESULT, 0, 1, 0, -1);

	// Disable Buttons
	SetDlgItemText(hwndDlg, IDC_SPEEDMETER_START, L"Прервать");
	EnableWindow(GetDlgItem(hwndDlg, IDC_SPEEDMETER_CLEAR), 0);

	// Init State
	page_list.thread[GetPageId(IDD_PAGE_SPEEDMETER)] = 1;

	if(!GetDlgItemText(hwndDlg, IDC_SPEEDMETER_LINK, szBuffer, MAX_PATH))
	{
		MessageBox(hwndDlg, L"Необходимо ввести ссылку на файл в сети", APP_NAME, MB_OK | MB_ICONSTOP);
	}
	else
	{
		// Validate
		if(ValidateUrl(szBuffer, MAX_PATH))
			SetDlgItemText(hwndDlg, IDC_SPEEDMETER_LINK, szBuffer);

		// Open Url
		hInternet = InternetOpen(APP_NAME L" " APP_VERSION, INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
		hFile = InternetOpenUrl(hInternet, szBuffer, 0, 0, INTERNET_FLAG_NO_CACHE_WRITE, 0);

		if(hInternet && hFile)
		{
			char buff[4096] = {0};
			DWORD dwTotal = 0, dwRecieved = 0, dwTemp = 0, dwSeconds = 0, dwMinSpeed = 0, dwMaxSpeed = 0;
			LARGE_INTEGER p1 = {0}, p2 = {0}, freq = {0};
		
			// Init Time
			GetLocalTime(&st);
			StringCchPrintf(szBuffer, MAX_PATH, L"%02d:%02d:%02d\0", st.wHour, st.wMinute, st.wSecond);
			Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, szBuffer, 3, 1);
			Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, L"00:00:00", 4, 1);

			QueryPerformanceCounter(&p1);
			QueryPerformanceFrequency(&freq);

			while(1)
			{
				// Thread Break
				if(!page_list.thread[GetPageId(IDD_PAGE_SPEEDMETER)])
					break;

				// Time Limit
				if(uLimit && uLimit <= dwSeconds)
					break;

				if(InternetReadFile(hFile, buff, 4096, &dwRecieved))
				{
					if(!dwRecieved)
						break;

					dwTotal += dwRecieved;

					QueryPerformanceCounter(&p2);
					dwSeconds = ((p2.QuadPart - p1.QuadPart) / (freq.QuadPart / 1000)) / 1000;
				
					if(dwSeconds)
					{
						dwTemp = (dwTotal / dwSeconds) / 1024;

						if(!dwMinSpeed || dwTemp < dwMinSpeed)
							dwMinSpeed = dwTemp;
					
						if(dwTemp > dwMaxSpeed)
							dwMaxSpeed = dwTemp;
					}

					StringCchPrintf(szBuffer, MAX_PATH, L"%d kbps\0", dwMinSpeed);
					Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, szBuffer, 0, 1);

					StringCchPrintf(szBuffer, MAX_PATH, L"%d kbps\0", (dwMinSpeed + dwMaxSpeed) / 2);
					Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, szBuffer, 1, 1);

					StringCchPrintf(szBuffer, MAX_PATH, L"%d kbps\0", dwMaxSpeed);
					Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, szBuffer, 2, 1);

					time_format(dwSeconds, szBuffer);
					Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, szBuffer, 5, 1);

					number_format(dwTotal, szBuffer);
					StringCchCat(szBuffer, MAX_PATH, L" bytes\0");
					Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, szBuffer, 6, 1);
				}
			}

			// End Time
			GetLocalTime(&st);
			StringCchPrintf(szBuffer, MAX_PATH, L"%02d:%02d:%02d\0", st.wHour, st.wMinute, st.wSecond);
			Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, szBuffer, 4, 1);
		}
		else
		{
			MessageBox(hwndDlg, L"Неудалось открыть ссылку", APP_NAME, MB_OK | MB_ICONSTOP);
		}
	}

	// Clear Memory
	InternetCloseHandle(hInternet);
	InternetCloseHandle(hFile);

	// Reset State
	page_list.thread[GetPageId(IDD_PAGE_SPEEDMETER)] = 0;

	// Enable Button
	SetDlgItemText(hwndDlg, IDC_SPEEDMETER_START, L"Начать");
	EnableWindow(GetDlgItem(hwndDlg, IDC_SPEEDMETER_START), 1);
	EnableWindow(GetDlgItem(hwndDlg, IDC_SPEEDMETER_CLEAR), 1);
}

// Get WHOIS Information (Miltithread)
void GetWhois(LPVOID lParam)
{
	HWND hwndDlg = (HWND)lParam;

	wchar_t szBuffer[MAX_PATH] = {0};
	char domain[MAX_PATH] = {0}, server[MAX_PATH] = {0}, buffer[1024] = {0};
	string str;

	SOCKET sock = 0;
	sockaddr_in addr = {0};

	// Clear Previous Result
	SetDlgItemText(hwndDlg, IDC_WHOIS_RESULT, 0);

	// Disable Buttons
	EnableWindow(GetDlgItem(hwndDlg, IDC_WHOIS_START), 0);
	EnableWindow(GetDlgItem(hwndDlg, IDC_WHOIS_CLEAR), 0);			

	if(!GetDlgItemTextA(hwndDlg, IDC_WHOIS_HOST, domain, MAX_PATH) || !GetDlgItemTextA(hwndDlg, IDC_WHOIS_SERVER, server, MAX_PATH))
	{
		SetDlgItemText(hwndDlg, IDC_WHOIS_RESULT, L"Необходимо ввести адрес домена и сервер");
		goto WHOIS_RETN;
	}

	addr.sin_family = AF_INET;
	addr.sin_port = htons(43);
	addr.sin_addr.s_addr = inet_addr(server);

	// Get Host Address
	if(addr.sin_addr.S_un.S_addr == INADDR_NONE)
	{
		hostent* host = gethostbyname(server);

		if(!host)
		{
			StringCchPrintf(szBuffer, MAX_PATH, L"Ошибка выполнения gethostbyname() (код ошибки %i)\0", WSAGetLastError());
			SetDlgItemText(hwndDlg, IDC_WHOIS_RESULT, szBuffer);

			goto WHOIS_RETN;
		}

		addr.sin_addr.S_un.S_addr = ((LPIN_ADDR)host->h_addr)->s_addr;
	}

	// Create Socket
	if((sock = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET)
	{
		StringCchPrintf(szBuffer, MAX_PATH, L"Ошибка выполнения socket() (код ошибки %i)\0", WSAGetLastError());
		SetDlgItemText(hwndDlg, IDC_WHOIS_RESULT, szBuffer);

		goto WHOIS_RETN;
	}

	// Socket Connect
	if(connect(sock, (sockaddr*)&addr, sizeof(sockaddr)) == SOCKET_ERROR)
	{
		StringCchPrintf(szBuffer, MAX_PATH, L"Ошибка выполнения connect() (код ошибки %i)\0", WSAGetLastError());
		SetDlgItemText(hwndDlg, IDC_WHOIS_RESULT, szBuffer);

		goto WHOIS_RETN;
	}

	// Sending Domain Name
	StringCchCatA(domain, MAX_PATH, "\r\n\0");
	send(sock, domain, strlen(domain), 0);

	while(1)
	{
		memset(&buffer, 0, sizeof(buffer));

		if(!recv(sock, buffer, 1024, 0))
			break;

		str.append(buffer);
	}
	
	// Trim Unnecessary LF
	string::size_type pos = str.find_first_not_of("\n");

	if(pos != string::npos)
		str.erase(0, pos);

	pos = str.find_last_not_of("\n");

	if(pos != string::npos)
		str.erase(pos + 1);

	// Repcale LF with CRLF
	for(unsigned int i = 0; i = str.find("\n", i), i != string::npos;)
	{
		str.replace(i, 1, "\r\n");
		i += 2;
	}

	// Show Result
	SetDlgItemTextA(hwndDlg, IDC_WHOIS_RESULT, str.c_str());
	
	WHOIS_RETN:

	// Close Socket
	if(sock)
		closesocket(sock);

	// Enable Button
	EnableWindow(GetDlgItem(hwndDlg, IDC_WHOIS_START), 1);
	EnableWindow(GetDlgItem(hwndDlg, IDC_WHOIS_CLEAR), 1);
}

// Get Url Information (Miltithread)
void GetUrlInfo(LPVOID lParam)
{
	HWND hwndDlg = (HWND)lParam;
	wchar_t szBufferW[MAX_PATH] = {0};

	// Clear Previous Result
	Lv_Fill(hwndDlg, IDC_URLINFO_RESULT, 0, 1, 0, -1, IL_SUCCESS);
	SetDlgItemText(hwndDlg, IDC_URLINFO_HEADER, 0);

	// Disable Buttons
	EnableWindow(GetDlgItem(hwndDlg, IDC_URLINFO_START), 0);
	EnableWindow(GetDlgItem(hwndDlg, IDC_URLINFO_CLEAR), 0);

	if(!GetDlgItemText(hwndDlg, IDC_URLINFO_LINK, szBufferW, MAX_PATH))
	{
		MessageBox(hwndDlg, L"Необходимо ввести ссылку", APP_NAME, MB_OK | MB_ICONSTOP);
	}
	else
	{
		// Validate
		if(ValidateUrl(szBufferW, MAX_PATH))
			SetDlgItemText(hwndDlg, IDC_URLINFO_LINK, szBufferW);

		// Connect
		HINTERNET hInternet = InternetOpen(APP_NAME L" " APP_VERSION, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
		HINTERNET hFile = InternetOpenUrl(hInternet, szBufferW, NULL, 0, INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE, 0);

		if(!hInternet || !hFile)
		{
			StringCchPrintf(szBufferW, MAX_PATH, L"Произошла ошибка при открытии ссылки (код ошибки: %d)\0", GetLastError());
			MessageBox(hwndDlg, szBufferW, APP_NAME, MB_OK | MB_ICONSTOP);
		}
		else
		{
			SYSTEMTIME st = {0};
			wchar_t szBuffer[4096] = {0};
			DWORD dwBuffer = 0, dwLength = 0;
			int iItem = 0;

			// Headers
			dwLength = 4096;
			if(HttpQueryInfo(hFile, HTTP_QUERY_RAW_HEADERS_CRLF, &szBuffer, &dwLength, NULL))
			{
				SetDlgItemText(hwndDlg, IDC_URLINFO_HEADER, szBuffer);
			}
			else
			{
				StringCchPrintf(szBufferW, MAX_PATH, L"Неудалось получить заголовки (код ошибки: %d)\0", GetLastError());
				SetDlgItemText(hwndDlg, IDC_URLINFO_HEADER, szBufferW);
			}

			// Length
			dwLength = sizeof(dwBuffer);
			if(HttpQueryInfo(hFile, HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_CONTENT_LENGTH, &dwBuffer, &dwLength, NULL))
			{
				StrFormatByteSizeW(dwBuffer, szBufferW, MAX_PATH);
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, szBufferW, iItem++, 1, IL_SUCCESS);
			}
			else
			{
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"нет", iItem++, 1, IL_FAULT);
			}

			// Last Modified
			dwLength = sizeof(st);
			if(HttpQueryInfo(hFile, HTTP_QUERY_FLAG_SYSTEMTIME | HTTP_QUERY_LAST_MODIFIED, &st, &dwLength, NULL))
			{
				date_format(&st, szBufferW);
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, szBufferW, iItem++, 1, IL_SUCCESS);
			}
			else
			{
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"нет", iItem++, 1, IL_FAULT);
			}

			// Resume Downloading
			dwLength = 4096;
			Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, HttpQueryInfo(hFile, HTTP_QUERY_ACCEPT_RANGES, &szBuffer, &dwLength, NULL) ? L"Поддерживается" : L"Не поддерживается", iItem++, 1, IL_SUCCESS);

			// Content Type
			dwLength = 4096;
			if(HttpQueryInfo(hFile, HTTP_QUERY_CONTENT_TYPE, &szBuffer, &dwLength, NULL))
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, szBuffer, iItem++, 1, IL_SUCCESS);
			else
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"нет", iItem++, 1, IL_FAULT);

			// E-Tag
			dwLength = 4096;
			if(HttpQueryInfo(hFile, HTTP_QUERY_ETAG, &szBuffer, &dwLength, NULL))
			{
				StrTrim(szBuffer, L"\"\0"); // Strip Quotes
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, szBuffer, iItem++, 1, IL_SUCCESS);
			}
			else
			{
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"нет", iItem++, 1, IL_FAULT);
			}

			// Protocol Version
			dwLength = 4096;
			if(HttpQueryInfo(hFile, HTTP_QUERY_VERSION, &szBuffer, &dwLength, NULL))
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, szBuffer, iItem++, 1, IL_SUCCESS);
			else
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"нет", iItem++, 1, IL_FAULT);
						
			// Server
			dwLength = 4096;
			if(HttpQueryInfo(hFile, HTTP_QUERY_SERVER, &szBuffer, &dwLength, NULL))
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, szBuffer, iItem++, 1, IL_SUCCESS);
			else
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"нет", iItem++, 1, IL_FAULT);

			// Status
			dwLength = sizeof(dwBuffer);
			HttpQueryInfo(hFile, HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_STATUS_CODE, &dwBuffer, &dwLength, NULL);

			dwLength = 4096;
			HttpQueryInfo(hFile, HTTP_QUERY_STATUS_TEXT, &szBuffer, &dwLength, NULL);

			StringCchPrintf(szBufferW, MAX_PATH, L"%d [%s]\0", dwBuffer, szBuffer);
			Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, szBufferW, iItem++, 1, IL_SUCCESS);
		}

		// Clear Memory
		InternetCloseHandle(hFile);
		InternetCloseHandle(hInternet);
	}

	// Enable Button
	EnableWindow(GetDlgItem(hwndDlg, IDC_URLINFO_START), 1);
	EnableWindow(GetDlgItem(hwndDlg, IDC_URLINFO_CLEAR), 1);
}

// Insert Text Into Clipboard
bool SetClipboardText(LPWSTR lpszSrc, int iLength)
{
    bool bRet = 0;
 
    if(OpenClipboard(0))
    {
        EmptyClipboard();

        HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, (iLength + 1) * sizeof(LPWSTR));
 
        if(hGlobal)
        {
            LPWSTR lpszData = (LPWSTR)GlobalLock(hGlobal);
 
            if(lpszData)
            {
                memcpy(lpszData, lpszSrc, iLength * sizeof(LPWSTR));
                lpszData[iLength] = L'\0';
 
                GlobalUnlock(hGlobal);
 
                if(SetClipboardData(CF_UNICODETEXT, hGlobal))
                    bRet = 1;
            }
        }
 
        CloseClipboard();
    }
 
    return bRet;
}

// Pages Routine
int GetPageId(int iDlgId)
{
	for(int i = 0; i < PAGE_COUNT; i++)
	{
		if(page_list.dlg_id[i] == iDlgId)
			return i;
	}

	return 0;
}

// Pages Routine
int GetCurrentPage()
{
	HTREEITEM hItem = TreeView_GetSelection(page_list.hWnd);

	if(!TreeView_GetParent(page_list.hWnd, hItem))
		hItem = TreeView_GetNextItem(page_list.hWnd, hItem, TVGN_CHILD);

	TVITEMEX tvi = {0};
	tvi.hItem = hItem;
	tvi.mask = TVIF_PARAM | TVIF_HANDLE;
	
	SendMessage(page_list.hWnd, TVM_GETITEM, 0, (LPARAM)&tvi);

	if(tvi.lParam < 0)
		return 0;
	
	if(tvi.lParam > PAGE_COUNT)
		return (PAGE_COUNT - 1);

	return tvi.lParam;
}

// Pages Routine
void SetCurrentPage(int iItem)
{
	if(iItem < 0)
		iItem = 0;
	
	if(iItem > PAGE_COUNT)
		iItem = PAGE_COUNT - 1;

	SendMessage(page_list.hWnd, TVM_SELECTITEM, TVGN_CARET, (LPARAM)page_list.hItem[iItem]);
}

// ListView Apperance Routine
void ListView_SetTheme(HWND hWnd, int iCtrlId, bool bGroupView)
{
	SetWindowTheme(GetDlgItem(hWnd, iCtrlId), L"Explorer", 0);
	SendDlgItemMessage(hWnd, iCtrlId, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_INFOTIP);
	SendDlgItemMessage(hWnd, iCtrlId, LVM_SETIMAGELIST, LVSIL_SMALL, (LPARAM)hImgList);
	SendDlgItemMessage(hWnd, iCtrlId, LVM_ENABLEGROUPVIEW, bGroupView, 0);
}

// ImageList Routine
void ImageList_Add(HIMAGELIST hImg, int iIco)
{
	HICON hIcon = LoadIcon(GetModuleHandle(0), MAKEINTRESOURCE(iIco));
	ImageList_ReplaceIcon(hImg, -1, hIcon);
	DestroyIcon(hIcon);
}

// Timer Procedure (Global)
void CALLBACK TimerProc(HWND hwndDlg, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
	wchar_t szBuffer[MAX_PATH] = {0};
	char szBufferA[MAX_PATH] = {0};
	int iBuffer = 0;

	HWND hWnd = page_list.hPage[GetCurrentPage()];

	if(idEvent == 1337)
	{
		switch(page_list.dlg_id[GetCurrentPage()])
		{
			case IDD_PAGE_TCP_STATISTIC:
			{
				MIB_TCPSTATS tcp_stat = {0};

				if(GetTcpStatisticsEx(&tcp_stat, (IsDlgButtonChecked(hWnd, IDC_TCP_STATISTIC_CHK) == BST_CHECKED) ? AF_INET6 : AF_INET) == NO_ERROR)
				{
					switch(tcp_stat.dwRtoAlgorithm)
					{
						case MIB_TCP_RTO_CONSTANT:
							wcsncpy(szBuffer, L"Constant Time-out", MAX_PATH);
							break;

						case MIB_TCP_RTO_RSRE:
							wcsncpy(szBuffer, L"MIL-STD-1778 Appendix B", MAX_PATH);
							break;
							
						case MIB_TCP_RTO_VANJ:
							wcsncpy(szBuffer, L"Van Jacobson Algorithm", MAX_PATH);
							break;

						default:
							wcsncpy(szBuffer, L"Other", MAX_PATH);
							break;
					}

					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(tcp_stat.dwRtoMin, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
						
					number_format(tcp_stat.dwRtoMax, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(tcp_stat.dwInSegs, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
					
					number_format(tcp_stat.dwOutSegs, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
					
					number_format(tcp_stat.dwRetransSegs, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(tcp_stat.dwOutRsts, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(tcp_stat.dwInErrs, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(tcp_stat.dwAttemptFails, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(tcp_stat.dwActiveOpens, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(tcp_stat.dwPassiveOpens, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(tcp_stat.dwCurrEstab, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(tcp_stat.dwEstabResets, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					if(tcp_stat.dwMaxConn == -1)
						wcsncpy(szBuffer, L"Переменное", MAX_PATH);
					else
						number_format(tcp_stat.dwMaxConn, szBuffer);

					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(tcp_stat.dwNumConns, szBuffer);
					Lv_InsertItem(hWnd, IDC_TCP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
				}
				else
				{
					Lv_Fill(hWnd, IDC_TCP_STATISTIC, L"n/a", 1, 0, -1, IL_FAULT);
				}

				break;
			}

			case IDD_PAGE_UDP_STATISTIC:
			{
				MIB_UDPSTATS udp_stat = {0};

				if(GetUdpStatisticsEx(&udp_stat, (IsDlgButtonChecked(hWnd, IDC_UDP_STATISTIC_CHK) == BST_CHECKED) ? AF_INET6 : AF_INET) == NO_ERROR)
				{
					number_format(udp_stat.dwInDatagrams, szBuffer);
					Lv_InsertItem(hWnd, IDC_UDP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(udp_stat.dwInErrors, szBuffer);
					Lv_InsertItem(hWnd, IDC_UDP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(udp_stat.dwNoPorts, szBuffer);
					Lv_InsertItem(hWnd, IDC_UDP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(udp_stat.dwOutDatagrams, szBuffer);
					Lv_InsertItem(hWnd, IDC_UDP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(udp_stat.dwNumAddrs, szBuffer);
					Lv_InsertItem(hWnd, IDC_UDP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
				}
				else
				{
					Lv_Fill(hWnd, IDC_UDP_STATISTIC, L"n/a", 1, 0, -1, IL_FAULT);
				}

				break;
			}

			case IDD_PAGE_ICMP_STATISTIC:
			{
				MIB_ICMP_EX icmp_stat = {0};

				if(GetIcmpStatisticsEx(&icmp_stat, (IsDlgButtonChecked(hWnd, IDC_ICMP_STATISTIC_CHK) == BST_CHECKED) ? AF_INET6 : AF_INET) == NO_ERROR)
				{
					number_format(icmp_stat.icmpInStats.dwMsgs, szBuffer);
					Lv_InsertItem(hWnd, IDC_ICMP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(icmp_stat.icmpInStats.dwErrors, szBuffer);
					Lv_InsertItem(hWnd, IDC_ICMP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(icmp_stat.icmpOutStats.dwMsgs, szBuffer);
					Lv_InsertItem(hWnd, IDC_ICMP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(icmp_stat.icmpOutStats.dwErrors, szBuffer);
					Lv_InsertItem(hWnd, IDC_ICMP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
				}
				else
				{
					Lv_Fill(hWnd, IDC_ICMP_STATISTIC, L"n/a", 1, 0, -1, IL_FAULT);
				}

				break;
			}

			case IDD_PAGE_IP_STATISTIC:
			{
				MIB_IPSTATS ip_stat = {0};

				if(GetIpStatisticsEx(&ip_stat, (IsDlgButtonChecked(hWnd, IDC_IP_STATISTIC_CHK) == BST_CHECKED) ? AF_INET6 : AF_INET) == NO_ERROR)
				{
					switch(ip_stat.dwForwarding)
					{
						case MIB_IP_FORWARDING:
							wcsncpy(szBuffer, L"Включено", MAX_PATH);
							break;

						case MIB_IP_NOT_FORWARDING:
							wcsncpy(szBuffer, L"Отключено", MAX_PATH);
							break;
							
						case MIB_USE_CURRENT_FORWARDING:
							wcsncpy(szBuffer, L"Текущая переадресация", MAX_PATH);
							break;

						default:
							wcsncpy(szBuffer, L"n/a", MAX_PATH);
							break;
					}

					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(ip_stat.dwForwDatagrams, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(ip_stat.dwInReceives, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
						
					number_format(ip_stat.dwInHdrErrors, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
						
					number_format(ip_stat.dwInAddrErrors, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
						
					number_format(ip_stat.dwInUnknownProtos, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(ip_stat.dwInDiscards, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(ip_stat.dwRoutingDiscards, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
						
					number_format(ip_stat.dwOutDiscards, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
						
					number_format(ip_stat.dwOutNoRoutes, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(ip_stat.dwReasmOks, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
						
					number_format(ip_stat.dwReasmFails, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
				
					number_format(ip_stat.dwReasmReqds, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
						
					number_format(ip_stat.dwFragOks, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
						
					number_format(ip_stat.dwFragFails, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
						
					number_format(ip_stat.dwFragCreates, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(ip_stat.dwReasmTimeout, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(ip_stat.dwInDelivers, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
						
					number_format(ip_stat.dwOutRequests, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(ip_stat.dwDefaultTTL, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
		
					number_format(ip_stat.dwNumIf, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
						
					number_format(ip_stat.dwNumAddr, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);

					number_format(ip_stat.dwNumRoutes, szBuffer);
					Lv_InsertItem(hWnd, IDC_IP_STATISTIC, szBuffer, iBuffer++, 1, IL_SUCCESS);
				}
				else
				{
					Lv_Fill(hWnd, IDC_IP_STATISTIC, L"n/a", 1, 0, -1, IL_FAULT);
				}

				break;
			}
		}
	}
}

// Pages Dialogs Procedure
INT_PTR WINAPI PageDlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	int iBuffer = 0;
	DWORD dwBuffer = 0;

	wchar_t szBufferW[MAX_PATH] = {0};
	char szBufferA[MAX_PATH] = {0};

	switch(uMsg)
	{
		case WM_INITDIALOG:
		{
			// Set Title
			SetDlgItemText(hwndDlg, IDC_TITLE, page_list.title[GetCurrentPage()]);
			SetDlgItemText(hwndDlg, IDC_DESCRIPTION, page_list.description[GetCurrentPage()]);

			// Use Bold Font For Title
			SendDlgItemMessage(hwndDlg, IDC_TITLE, WM_SETFONT, (WPARAM)hBold, 0);
			
			// Change Position
			SetWindowPos(hwndDlg, HWND_TOP, 211, 13, 0, 0, SWP_NOSIZE);

			// Ping Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_PING)
			{
				SendDlgItemMessage(hwndDlg, IDC_PING_UPDOWN, UDM_SETRANGE32, 1, 1000);
				SetDlgItemText(hwndDlg, IDC_PING_HOST, cfg.read(APP_NAME_SHORT, L"PingAddress", MAX_PATH, APP_HOST));
				SetDlgItemInt(hwndDlg, IDC_PING_RETRIES, cfg.read(APP_NAME_SHORT, L"PingRetries", 5), 1);
				
				ListView_SetTheme(hwndDlg, IDC_PING_RESULT, 0);

				Lv_InsertColumn(hwndDlg, IDC_PING_RESULT, L"Адрес", 125, 0, 0);
				Lv_InsertColumn(hwndDlg, IDC_PING_RESULT, L"Размер", 80, 1, 0);
				Lv_InsertColumn(hwndDlg, IDC_PING_RESULT, L"Задержка", 80, 2, 0);
				Lv_InsertColumn(hwndDlg, IDC_PING_RESULT, L"TTL", 75, 3, 0);
			}
			
			// Speed Meter Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_SPEEDMETER)
			{
				SetDlgItemText(hwndDlg, IDC_SPEEDMETER_LINK, cfg.read(APP_NAME_SHORT, L"SpeedmeterLink", MAX_PATH, APP_HOST));

				SendDlgItemMessage(hwndDlg, IDC_SPEEDMETER_UPDOWN, UDM_SETRANGE32, 0, 1000);
				SetDlgItemInt(hwndDlg, IDC_SPEEDMETER_LIMIT, cfg.read(APP_NAME_SHORT, L"SpeedMeterLimit", 10), 1);

				ListView_SetTheme(hwndDlg, IDC_SPEEDMETER_RESULT, 1);

				Lv_InsertColumn(hwndDlg, IDC_SPEEDMETER_RESULT, L"Параметр", 170, 0, 0);
				Lv_InsertColumn(hwndDlg, IDC_SPEEDMETER_RESULT, L"Значение", 190, 1, 0);

				Lv_InsertGroup(hwndDlg, IDC_SPEEDMETER_RESULT, L"Скорость", 0, 0);
				Lv_InsertGroup(hwndDlg, IDC_SPEEDMETER_RESULT, L"Время", 1, 0);
				Lv_InsertGroup(hwndDlg, IDC_SPEEDMETER_RESULT, L"Прочее", 2, 0);

				iBuffer = 0;
				Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, L"Минимальная", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, L"Средняя", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, L"Максимальная", iBuffer++, 0, IL_SUCCESS, 0);

				Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, L"Тест запущен", iBuffer++, 0, IL_SUCCESS, 1);
				Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, L"Тест окончен", iBuffer++, 0, IL_SUCCESS, 1);
				Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, L"Время выполнения", iBuffer++, 0, IL_SUCCESS, 1);

				Lv_InsertItem(hwndDlg, IDC_SPEEDMETER_RESULT, L"Принято данных", iBuffer++, 0, IL_SUCCESS, 2);
			}

			// Url Decoder Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_URLDECODER)
			{
				SetDlgItemText(hwndDlg, IDC_URLDECODER_LINK, cfg.read(APP_NAME_SHORT, L"UrlDecoderLink", MAX_PATH, L"%22%23%24%25%26%27%28%29%2A%2C%3B%3F%5B%5D%5E%60%7B%7D"));
			}

			// Host Address Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_HOSTADDR)
			{
				SetDlgItemText(hwndDlg, IDC_HOSTADDR_HOST, cfg.read(APP_NAME_SHORT, L"HostAddrAddress", MAX_PATH, APP_HOST));
			}

			// Whois Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_WHOIS)
			{
				SetDlgItemText(hwndDlg, IDC_WHOIS_HOST, cfg.read(APP_NAME_SHORT, L"WhoisAddress", MAX_PATH, APP_HOST));

				for(int i = 0; i < (sizeof(whois_servers) / sizeof(whois_servers[0])); i++)
					SendDlgItemMessage(hwndDlg, IDC_WHOIS_SERVER, CB_ADDSTRING , 0, (LPARAM)whois_servers[i]);

				iBuffer = cfg.read(APP_NAME_SHORT, L"WhoisServer", 0);

				if(iBuffer == CB_ERR)
					SetDlgItemText(hwndDlg, IDC_WHOIS_SERVER, cfg.read(APP_NAME_SHORT, L"WhoisServerCustom", MAX_PATH, whois_servers[0]));
				else
					SendDlgItemMessage(hwndDlg, IDC_WHOIS_SERVER, CB_SETCURSEL, iBuffer, 0);
			}

			// Url Info Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_URLINFO)
			{
				ListView_SetTheme(hwndDlg, IDC_URLINFO_RESULT, 1);

				Lv_InsertColumn(hwndDlg, IDC_URLINFO_RESULT, L"Параметр", 170, 0, 0);
				Lv_InsertColumn(hwndDlg, IDC_URLINFO_RESULT, L"Значение", 190, 1, 0);

				Lv_InsertGroup(hwndDlg, IDC_URLINFO_RESULT, L"Информация о файле", 0, 0);
				Lv_InsertGroup(hwndDlg, IDC_URLINFO_RESULT, L"Информация о сервере", 1, 0);

				iBuffer = 0;
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"Размер", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"Дата изменения", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"Докачка", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"Тип содержимого", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"Метка объекта", iBuffer++, 0, IL_SUCCESS, 0);

				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"Протокол", iBuffer++, 0, IL_SUCCESS, 1);
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"Сервер", iBuffer++, 0, IL_SUCCESS, 1);
				Lv_InsertItem(hwndDlg, IDC_URLINFO_RESULT, L"Статус", iBuffer++, 0, IL_SUCCESS, 1);

				SetDlgItemText(hwndDlg, IDC_URLINFO_LINK, cfg.read(APP_NAME_SHORT, L"UrlInfoLink", MAX_PATH, APP_HOST));
				CheckDlgButton(hwndDlg, IDC_URLINFO_HEADER_CHK, cfg.read(APP_NAME_SHORT, L"UrlInfoShowHeader", 0) ? BST_CHECKED : BST_UNCHECKED);

				SendMessage(hwndDlg, WM_COMMAND, MAKELPARAM(IDC_URLINFO_HEADER_CHK, 0), 0);
			}

			// Ip Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_IP)
			{
				ListView_SetTheme(hwndDlg, IDC_IP_RESULT, 1);

				Lv_InsertColumn(hwndDlg, IDC_IP_RESULT, L"Параметр", 170, 0, 0);
				Lv_InsertColumn(hwndDlg, IDC_IP_RESULT, L"Значение", 190, 1, 0);

				Lv_InsertGroup(hwndDlg, IDC_IP_RESULT, L"Внешний адрес", 0, 0);
				Lv_InsertGroup(hwndDlg, IDC_IP_RESULT, L"Локальный адрес", 1, 0);

				iBuffer = 0;
				Lv_InsertItem(hwndDlg, IDC_IP_RESULT, L"Адрес", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_IP_RESULT, L"Прокси", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_IP_RESULT, L"Провайдер", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_IP_RESULT, L"Организация", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_IP_RESULT, L"Город", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_IP_RESULT, L"Координаты", iBuffer++, 0, IL_SUCCESS, 0);

				CheckDlgButton(hwndDlg, IDC_IP_EXTERNAL_CHK, cfg.read(APP_NAME_SHORT, L"RetrieveExternalIp", 0) ? BST_CHECKED : BST_UNCHECKED);

				SendMessage(hwndDlg, WM_COMMAND, MAKELPARAM(IDC_IP_REFRESH, 0), 0);
			}

			// Shared Info Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_SHAREDINFO)
			{
				ListView_SetTheme(hwndDlg, IDC_SHAREDINFO, 0);

				Lv_InsertColumn(hwndDlg, IDC_SHAREDINFO, L"Ресурс", 140, 0, 0);
				Lv_InsertColumn(hwndDlg, IDC_SHAREDINFO, L"Путь", 140, 1, 0);
				Lv_InsertColumn(hwndDlg, IDC_SHAREDINFO, L"Подключено", 75, 2, 0);

				SendMessage(hwndDlg, WM_COMMAND, MAKELPARAM(IDC_SHAREDINFO_START, 0), 0);
			}

			// System Info Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_SYSINFO)
			{
				ListView_SetTheme(hwndDlg, IDC_SYSINFO, 1);

				Lv_InsertColumn(hwndDlg, IDC_SYSINFO, L"Параметр", 170, 0, 0);
				Lv_InsertColumn(hwndDlg, IDC_SYSINFO, L"Значение", 190, 1, 0);
				
				Lv_InsertGroup(hwndDlg, IDC_SYSINFO, L"Общее", 0, 0);
				Lv_InsertGroup(hwndDlg, IDC_SYSINFO, L"Конфигурация сети", 1, 0);
				Lv_InsertGroup(hwndDlg, IDC_SYSINFO, L"Поддерживаемые версии протоколов", 2, 0);
				Lv_InsertGroup(hwndDlg, IDC_SYSINFO, L"Система", 3, 0);

				iBuffer = 0;

				Lv_InsertItem(hwndDlg, IDC_SYSINFO, L"Версия Winsock", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, L"Версия Windows", iBuffer++, 0, IL_SUCCESS, 0);

				Lv_InsertItem(hwndDlg, IDC_SYSINFO, L"Состояние сети", iBuffer++, 0, IL_SUCCESS, 1);
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, L"Тип узла", iBuffer++, 0, IL_SUCCESS, 1);
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, L"Переадресация", iBuffer++, 0, IL_SUCCESS, 1);
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, L"Прокси", iBuffer++, 0, IL_SUCCESS, 1);
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, L"DNS", iBuffer++, 0, IL_SUCCESS, 1);

				Lv_InsertItem(hwndDlg, IDC_SYSINFO, L"IPv4", iBuffer++, 0, IL_SUCCESS, 2);
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, L"IPv6", iBuffer++, 0, IL_SUCCESS, 2);

				Lv_InsertItem(hwndDlg, IDC_SYSINFO, L"Имя пользователя", iBuffer++, 0, IL_SUCCESS, 3);
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, L"Имя хоста", iBuffer++, 0, IL_SUCCESS, 3);
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, L"Имя компьютера", iBuffer++, 0, IL_SUCCESS, 3);

				iBuffer = 0;

				// Winsock Version
				StringCchPrintf(szBufferW, MAX_PATH, L"%d.%d\0", LOBYTE(wsa.wVersion), HIBYTE(wsa.wVersion));
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, szBufferW, iBuffer++, 1);

				// Windows Version
				OSVERSIONINFO osvi = {0};
				osvi.dwOSVersionInfoSize = sizeof(osvi);
				GetVersionEx(&osvi);

				StringCchPrintf(szBufferW, MAX_PATH, L"%d.%d build %d %s\0", osvi.dwMajorVersion, osvi.dwMinorVersion, osvi.dwBuildNumber, osvi.szCSDVersion);
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, szBufferW, iBuffer++, 1);

				// Connection State
				dwBuffer = 0;

				if(IsNetworkAlive(&dwBuffer))
				{
					wchar_t buff[MAX_PATH] = {0};
					
					if(dwBuffer & NETWORK_ALIVE_LAN)
						StringCchCat(buff, MAX_PATH, L"LAN\0");

					if(dwBuffer & NETWORK_ALIVE_WAN)
					{
						if(dwBuffer & NETWORK_ALIVE_LAN)
							StringCchCat(buff, MAX_PATH, L" + \0");

						StringCchCat(buff, MAX_PATH, L"WAN\0");
					}

					StringCchPrintf(szBufferW, MAX_PATH, L"Работает (%s)\0", buff);
				}
				else
				{
					StringCchCopy(szBufferW, MAX_PATH, L"Не работает\0");
				}

				Lv_InsertItem(hwndDlg, IDC_SYSINFO, szBufferW, iBuffer++, 1);

				// Network Configuration
				FIXED_INFO* fi = (FIXED_INFO*)malloc(sizeof(FIXED_INFO));
				ULONG ulOutBufLen = sizeof(fi);

				if(GetNetworkParams(fi, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW)
				{
					free(fi);
					fi = (FIXED_INFO*)malloc(ulOutBufLen);
				}

				if(GetNetworkParams(fi, &ulOutBufLen) == NO_ERROR)
				{
					switch(fi->NodeType)
					{
						case BROADCAST_NODETYPE:
							StringCchCopy(szBufferW, MAX_PATH, L"Broadcast\0");
							break;

						case PEER_TO_PEER_NODETYPE:
							StringCchCopy(szBufferW, MAX_PATH, L"P2P\0");
							break;
							
						case MIXED_NODETYPE:
							StringCchCopy(szBufferW, MAX_PATH, L"Mixed\0");
							break;

						case HYBRID_NODETYPE:
							StringCchCopy(szBufferW, MAX_PATH, L"Hybrid\0");
							break;

						default:
							StringCchCopy(szBufferW, MAX_PATH, L"Неизвестно\0");
							break;
					}

					Lv_InsertItem(hwndDlg, IDC_SYSINFO, szBufferW, iBuffer++, 1);
					Lv_InsertItem(hwndDlg, IDC_SYSINFO, fi->EnableRouting ? L"Включено" : L"Отключено", iBuffer++, 1);
					Lv_InsertItem(hwndDlg, IDC_SYSINFO, fi->EnableProxy ? L"Включено" : L"Отключено", iBuffer++, 1);
					Lv_InsertItem(hwndDlg, IDC_SYSINFO, fi->EnableDns ? L"Включено" : L"Отключено", iBuffer++, 1);
				}
				else
				{
					// Skip 4 Items
					Lv_Fill(hwndDlg, IDC_SYSINFO, L"n/a", 1, iBuffer, iBuffer + 4, IL_FAULT);
					iBuffer += 4;
				}

				if(fi)
					free(fi);

				// Address Family
				SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // IPv4
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, (WSAGetLastError() == WSAEAFNOSUPPORT) ? L"Не поддерживается" : L"Поддерживается", iBuffer++, 1, (WSAGetLastError() == WSAEAFNOSUPPORT) ? IL_FAULT : IL_SUCCESS);			
				closesocket(sock);

				sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP); // IPv6
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, (WSAGetLastError() == WSAEAFNOSUPPORT) ? L"Не поддерживается" : L"Поддерживается", iBuffer++, 1, (WSAGetLastError() == WSAEAFNOSUPPORT) ? IL_FAULT : IL_SUCCESS);			
				closesocket(sock);

				// User Name
				dwBuffer = MAX_PATH;
				GetUserName(szBufferW, &dwBuffer);
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, szBufferW, iBuffer++, 1);

				// Localhost Name
				Lv_InsertItemA(hwndDlg, IDC_SYSINFO, gethostname(szBufferA, MAX_PATH) ? "n/a" : szBufferA, iBuffer++, 1);

				// Computer Name
				dwBuffer = MAX_PATH;
				GetComputerNameEx(ComputerNameDnsHostname, szBufferW, &dwBuffer);
				Lv_InsertItem(hwndDlg, IDC_SYSINFO, szBufferW, iBuffer++, 1);
			}

			// TCP Statistic Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_TCP_STATISTIC)
			{
				ListView_SetTheme(hwndDlg, IDC_TCP_STATISTIC, 1);

				Lv_InsertColumn(hwndDlg, IDC_TCP_STATISTIC, L"Параметр", 170, 0, 0);
				Lv_InsertColumn(hwndDlg, IDC_TCP_STATISTIC, L"Значение", 190, 1, 0);

				Lv_InsertGroup(hwndDlg, IDC_TCP_STATISTIC, L"RTO (Retransmission Timeout)", 0, 0);
				Lv_InsertGroup(hwndDlg, IDC_TCP_STATISTIC, L"Принято сегментов", 1, 0);
				Lv_InsertGroup(hwndDlg, IDC_TCP_STATISTIC, L"Отправлено сегментов", 2, 0);
				Lv_InsertGroup(hwndDlg, IDC_TCP_STATISTIC, L"Ошибки", 3, 0);
				Lv_InsertGroup(hwndDlg, IDC_TCP_STATISTIC, L"Соединения", 4, 0);

				iBuffer = 0;
				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Алгоритм RTO", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Мин. значение RTO (мс)", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Макс. значение RTO (мс)", iBuffer++, 0, IL_SUCCESS, 0);

				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Принято", iBuffer++, 0, IL_SUCCESS, 1);

				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Отправлено", iBuffer++, 0, IL_SUCCESS, 2);
				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Повторно", iBuffer++, 0, IL_SUCCESS, 2);
				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"С флагом сброса", iBuffer++, 0, IL_SUCCESS, 2);

				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Полученных ошибок", iBuffer++, 0, IL_SUCCESS, 3);
				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Неудачных подключений", iBuffer++, 0, IL_SUCCESS, 3);

				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Открытые (активные)", iBuffer++, 0, IL_SUCCESS, 4);
				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Открытые (пассивные)", iBuffer++, 0, IL_SUCCESS, 4);
				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Установленные соединения", iBuffer++, 0, IL_SUCCESS, 4);
				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Сброшенные соединения", iBuffer++, 0, IL_SUCCESS, 4);
				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Макс. кол-во соединений", iBuffer++, 0, IL_SUCCESS, 4);
				Lv_InsertItem(hwndDlg, IDC_TCP_STATISTIC, L"Кол-во соединений", iBuffer++, 0, IL_SUCCESS, 4);

				CheckDlgButton(hwndDlg, IDC_TCP_STATISTIC_CHK, cfg.read(APP_NAME_SHORT, L"TcpStatisticUseIPv6", 0) ? BST_CHECKED : BST_UNCHECKED);
			}

			// UDP Statistic Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_UDP_STATISTIC)
			{
				ListView_SetTheme(hwndDlg, IDC_UDP_STATISTIC, 1);

				Lv_InsertColumn(hwndDlg, IDC_UDP_STATISTIC, L"Параметр", 170, 0, 0);
				Lv_InsertColumn(hwndDlg, IDC_UDP_STATISTIC, L"Значение", 190, 1, 0);

				Lv_InsertGroup(hwndDlg, IDC_UDP_STATISTIC, L"Принято дейтаграмм", 0, 0);
				Lv_InsertGroup(hwndDlg, IDC_UDP_STATISTIC, L"Отправлено дейтаграмм", 1, 0);
				Lv_InsertGroup(hwndDlg, IDC_UDP_STATISTIC, L"Прочее", 2, 0);

				iBuffer = 0;
				Lv_InsertItem(hwndDlg, IDC_UDP_STATISTIC, L"Принято", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_UDP_STATISTIC, L"С ошибками", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_UDP_STATISTIC, L"На неверный порт", iBuffer++, 0, IL_SUCCESS, 0);

				Lv_InsertItem(hwndDlg, IDC_UDP_STATISTIC, L"Отправлено", iBuffer++, 0, IL_SUCCESS, 1);

				Lv_InsertItem(hwndDlg, IDC_UDP_STATISTIC, L"Кол-во адресов", iBuffer++, 0, IL_SUCCESS, 2);

				CheckDlgButton(hwndDlg, IDC_UDP_STATISTIC_CHK, cfg.read(APP_NAME_SHORT, L"UdpStatisticUseIPv6", 0) ? BST_CHECKED : BST_UNCHECKED);
			}

			// Icmp Statistic Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_ICMP_STATISTIC)
			{
				ListView_SetTheme(hwndDlg, IDC_ICMP_STATISTIC, 1);

				Lv_InsertColumn(hwndDlg, IDC_ICMP_STATISTIC, L"Параметр", 170, 0, 0);
				Lv_InsertColumn(hwndDlg, IDC_ICMP_STATISTIC, L"Значение", 190, 1, 0);

				Lv_InsertGroup(hwndDlg, IDC_ICMP_STATISTIC, L"Принятые запросы", 0, 0);
				Lv_InsertGroup(hwndDlg, IDC_ICMP_STATISTIC, L"Отправленные запросы", 1, 0);

				iBuffer = 0;
				Lv_InsertItem(hwndDlg, IDC_ICMP_STATISTIC, L"Принято", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_ICMP_STATISTIC, L"С ошибками", iBuffer++, 0, IL_SUCCESS, 0);

				Lv_InsertItem(hwndDlg, IDC_ICMP_STATISTIC, L"Отправлено", iBuffer++, 0, IL_SUCCESS, 1);
				Lv_InsertItem(hwndDlg, IDC_ICMP_STATISTIC, L"С ошибками", iBuffer++, 0, IL_SUCCESS, 1);
			
				CheckDlgButton(hwndDlg, IDC_ICMP_STATISTIC_CHK, cfg.read(APP_NAME_SHORT, L"IcmpStatisticUseIPv6", 0) ? BST_CHECKED : BST_UNCHECKED);
			}

			// Ip Statistic Page
			if(page_list.dlg_id[GetCurrentPage()] == IDD_PAGE_IP_STATISTIC)
			{
				ListView_SetTheme(hwndDlg, IDC_IP_STATISTIC, 1);

				Lv_InsertColumn(hwndDlg, IDC_IP_STATISTIC, L"Параметр", 200, 0, 0);
				Lv_InsertColumn(hwndDlg, IDC_IP_STATISTIC, L"Значение", 160, 1, 0);

				Lv_InsertGroup(hwndDlg, IDC_IP_STATISTIC, L"Переадресация", 0, 0);
				Lv_InsertGroup(hwndDlg, IDC_IP_STATISTIC, L"Принятые пакеты", 1, 0);
				Lv_InsertGroup(hwndDlg, IDC_IP_STATISTIC, L"Ошибки", 2, 0);
				Lv_InsertGroup(hwndDlg, IDC_IP_STATISTIC, L"Сборка пакетов", 3, 0);
				Lv_InsertGroup(hwndDlg, IDC_IP_STATISTIC, L"Фрагментация", 4, 0);
				Lv_InsertGroup(hwndDlg, IDC_IP_STATISTIC, L"Статистика", 5, 0);
				Lv_InsertGroup(hwndDlg, IDC_IP_STATISTIC, L"Прочее", 6, 0);

				iBuffer = 0;
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Переадресация", iBuffer++, 0, IL_SUCCESS, 0);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Переадресовано пакетов", iBuffer++, 0, IL_SUCCESS, 0);

				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Принято", iBuffer++, 0, IL_SUCCESS, 1);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"С ошибками в заголовке", iBuffer++, 0, IL_SUCCESS, 1);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"С ошибками в адресе", iBuffer++, 0, IL_SUCCESS, 1);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"С ошибками в протоколе", iBuffer++, 0, IL_SUCCESS, 1);

				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Отброшенных входящих пакетов ", iBuffer++, 0, IL_SUCCESS, 2);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Отброшенных исходящих маршрутов", iBuffer++, 0, IL_SUCCESS, 2);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Отброшенных исходящих пакетов", iBuffer++, 0, IL_SUCCESS, 2);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Пакетов без маршрута", iBuffer++, 0, IL_SUCCESS, 2);

				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Собранных пакетов", iBuffer++, 0, IL_SUCCESS, 3);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Собранных пакетов (ошибка)", iBuffer++, 0, IL_SUCCESS, 3);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Пакетов требующих сборки", iBuffer++, 0, IL_SUCCESS, 3);

				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Фрагментированных пакетов", iBuffer++, 0, IL_SUCCESS, 4);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Фрагментированных пакетов (ошибка)", iBuffer++, 0, IL_SUCCESS, 4);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Фрагментов создано", iBuffer++, 0, IL_SUCCESS, 4);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Время сборки фрагментированного пакета", iBuffer++, 0, IL_SUCCESS, 4);

				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Доставленных пакетов", iBuffer++, 0, IL_SUCCESS, 5);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Отправленных пакетов", iBuffer++, 0, IL_SUCCESS, 5);

				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Значение TTL", iBuffer++, 0, IL_SUCCESS, 6);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Кол-во интерфейсов", iBuffer++, 0, IL_SUCCESS, 6);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Кол-во IP адресов", iBuffer++, 0, IL_SUCCESS, 6);
				Lv_InsertItem(hwndDlg, IDC_IP_STATISTIC, L"Кол-во маршрутов", iBuffer++, 0, IL_SUCCESS, 6);
			
				CheckDlgButton(hwndDlg, IDC_IP_STATISTIC_CHK, cfg.read(APP_NAME_SHORT, L"IpStatisticUseIPv6", 0) ? BST_CHECKED : BST_UNCHECKED);
			}

			break;
		}
		
		case WM_PAINT:
        {
			PAINTSTRUCT ps = {0};
			RECT rc = {0};

			GetClientRect(hwndDlg, &rc);
			rc.bottom = 53;

			// Get DC
			HDC hDC = BeginPaint(hwndDlg, &ps);

			// Fill Rect
			COLORREF clrOld = SetBkColor(hDC, RGB(216, 231, 239));
			ExtTextOut(hDC, 0, 0, ETO_OPAQUE, &rc, NULL, 0, NULL);
			SetBkColor(hDC, clrOld);

			// Paint Rect
			HRGN hRect = CreateRectRgnIndirect(&rc);
			FrameRgn(hDC, hRect, CreateSolidBrush(RGB(171, 208, 228)), 1, 1);
			DeleteObject(hRect);

			// Release DC
			EndPaint(hwndDlg, &ps);

			break;
        }

		case WM_CTLCOLORSTATIC:
        {
			if(GetDlgCtrlID((HWND)lParam) == IDC_TITLE || GetDlgCtrlID((HWND)lParam) == IDC_DESCRIPTION)
			{
				SetBkMode((HDC)wParam, TRANSPARENT);

				if(GetDlgCtrlID((HWND)lParam) == IDC_DESCRIPTION)
					SetTextColor((HDC)wParam, GetSysColor(COLOR_GRAYTEXT));

				return (INT_PTR)GetStockObject(NULL_BRUSH);
			}

			break;
        }

		case WM_CONTEXTMENU:
		{
			// Only Defined Controls
			if(!page_list.lv_id[GetCurrentPage()] || page_list.lv_id[GetCurrentPage()] != GetDlgCtrlID((HWND)wParam))
				return 0;

			// Load Menu
			HMENU hMenu = LoadMenu(GetModuleHandle(0), MAKEINTRESOURCE(IDM_LISTVIEW));
			HMENU hSubMenu = GetSubMenu(hMenu, 0);

			// Empty ListView
			if(!SendMessage((HWND)wParam, LVM_GETITEMCOUNT, 0, 0))
			{
				EnableMenuItem(hSubMenu, IDC_LISTVIEW_COPY, MF_BYCOMMAND | MF_DISABLED);
				EnableMenuItem(hSubMenu, IDC_LISTVIEW_COPY_VALUE, MF_BYCOMMAND | MF_DISABLED);
				EnableMenuItem(hSubMenu, IDC_LISTVIEW_SAVE_AS, MF_BYCOMMAND | MF_DISABLED);
			}

			// Non-Selected ListView
			if(!SendMessage((HWND)wParam, LVM_GETSELECTEDCOUNT, 0, 0))
			{
				EnableMenuItem(hSubMenu, IDC_LISTVIEW_COPY, MF_BYCOMMAND | MF_DISABLED);
				EnableMenuItem(hSubMenu, IDC_LISTVIEW_COPY_VALUE, MF_BYCOMMAND | MF_DISABLED);
			}

			// Over 2 Subitem
			if(SendMessage((HWND)SendMessage((HWND)wParam, LVM_GETHEADER, 0, 0), HDM_GETITEMCOUNT, 0, 0) != 2)
				EnableMenuItem(hSubMenu, IDC_LISTVIEW_COPY_VALUE, MF_BYCOMMAND | MF_DISABLED);

			// Get Cursor Position
			POINT pt = {0};
			GetCursorPos(&pt);

			// Show Menu
			TrackPopupMenuEx(hSubMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_LEFTBUTTON | TPM_NOANIMATION, pt.x, pt.y, hwndDlg, NULL);

			// Destroy Menu
			DestroyMenu(hMenu);
			DestroyMenu(hSubMenu);

			break;
		}

		case WM_DESTROY:
		{
			BOOL bStatus = 0;

			// Ping Page
			if(GetDlgItem(hwndDlg, IDC_PING_HOST))
			{
				GetDlgItemText(hwndDlg, IDC_PING_HOST, szBufferW, MAX_PATH);
				cfg.write(APP_NAME_SHORT, L"PingRetries", szBufferW);
			}

			iBuffer = GetDlgItemInt(hwndDlg, IDC_PING_RETRIES, &bStatus, 1);

			if(bStatus)
				cfg.write(APP_NAME_SHORT, L"PingRetries", iBuffer);
			
			// Speedmeter Page
			if(GetDlgItem(hwndDlg, IDC_SPEEDMETER_LINK))
			{
				iBuffer = GetDlgItemInt(hwndDlg, IDC_SPEEDMETER_LIMIT, &bStatus, 1);

				if(bStatus)
					cfg.write(APP_NAME_SHORT, L"SpeedMeterLimit", iBuffer);

				GetDlgItemText(hwndDlg, IDC_SPEEDMETER_LINK, szBufferW, MAX_PATH);
				cfg.write(APP_NAME_SHORT, L"SpeedmeterLink", szBufferW);
			}

			// Url Decoder Page
			if(GetDlgItem(hwndDlg, IDC_URLDECODER_LINK))
			{
				GetDlgItemText(hwndDlg, IDC_URLDECODER_LINK, szBufferW, MAX_PATH);
				cfg.write(APP_NAME_SHORT, L"UrlDecoderLink", szBufferW);
			}

			// Host Address Page
			if(GetDlgItem(hwndDlg, IDC_HOSTADDR_HOST))
			{
				GetDlgItemText(hwndDlg, IDC_HOSTADDR_HOST, szBufferW, MAX_PATH);
				cfg.write(APP_NAME_SHORT, L"HostAddrAddress", szBufferW);
			}

			// Url Info Page
			if(GetDlgItem(hwndDlg, IDC_URLINFO_LINK))
			{
				GetDlgItemText(hwndDlg, IDC_URLINFO_LINK, szBufferW, MAX_PATH);
				cfg.write(APP_NAME_SHORT, L"UrlInfoLink", szBufferW);
			}

			if(GetDlgItem(hwndDlg, IDC_URLINFO_HEADER_CHK))
				cfg.write(APP_NAME_SHORT, L"UrlInfoShowHeader", (IsDlgButtonChecked(hwndDlg, IDC_URLINFO_HEADER_CHK) == BST_CHECKED) ? 1 : 0);

			// Ip Page
			if(GetDlgItem(hwndDlg, IDC_IP_EXTERNAL_CHK))
				cfg.write(APP_NAME_SHORT, L"RetrieveExternalIp", (IsDlgButtonChecked(hwndDlg, IDC_IP_EXTERNAL_CHK) == BST_CHECKED) ? 1 : 0);

			// Whois Page
			if(GetDlgItem(hwndDlg, IDC_WHOIS_HOST))
			{
				GetDlgItemText(hwndDlg, IDC_WHOIS_HOST, szBufferW, MAX_PATH);
				cfg.write(APP_NAME_SHORT, L"WhoisAddress", szBufferW);
			}

			if(GetDlgItem(hwndDlg, IDC_WHOIS_SERVER))
			{
				iBuffer = SendDlgItemMessage(hwndDlg, IDC_WHOIS_SERVER, CB_GETCURSEL, 0, 0);

				if(iBuffer == CB_ERR)
				{
					GetDlgItemText(hwndDlg, IDC_WHOIS_SERVER, szBufferW, MAX_PATH);
					cfg.write(APP_NAME_SHORT, L"WhoisServerCustom", szBufferW);
				}

				cfg.write(APP_NAME_SHORT, L"WhoisServer", iBuffer);
			}

			// Statistics
			if(GetDlgItem(hwndDlg, IDC_TCP_STATISTIC_CHK))
				cfg.write(APP_NAME_SHORT, L"TcpStatisticUseIPv6", (IsDlgButtonChecked(hwndDlg, IDC_TCP_STATISTIC_CHK) == BST_CHECKED) ? 1 : 0);

			if(GetDlgItem(hwndDlg, IDC_UDP_STATISTIC_CHK))
				cfg.write(APP_NAME_SHORT, L"UdpStatisticUseIPv6", (IsDlgButtonChecked(hwndDlg, IDC_UDP_STATISTIC_CHK) == BST_CHECKED) ? 1 : 0);

			if(GetDlgItem(hwndDlg, IDC_ICMP_STATISTIC_CHK))
				cfg.write(APP_NAME_SHORT, L"IcmpStatisticUseIPv6", (IsDlgButtonChecked(hwndDlg, IDC_ICMP_STATISTIC_CHK) == BST_CHECKED) ? 1 : 0);

			if(GetDlgItem(hwndDlg, IDC_IP_STATISTIC_CHK))
				cfg.write(APP_NAME_SHORT, L"IpStatisticUseIPv6", (IsDlgButtonChecked(hwndDlg, IDC_IP_STATISTIC_CHK) == BST_CHECKED) ? 1 : 0);

			// Clear Memory
			DeleteObject(hBold);

			break;
		}

		case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
				case IDC_LISTVIEW_COPY:
				{
					wchar_t buff[4096] = {0};

					if(GetListViewText(GetDlgItem(hwndDlg, page_list.lv_id[GetCurrentPage()]), buff, 4096, 1))
						SetClipboardText(buff, 4096);

					break;
				}

				case IDC_LISTVIEW_COPY_VALUE:
				{
					wchar_t buff[4096] = {0};

					if(GetListViewText(GetDlgItem(hwndDlg, page_list.lv_id[GetCurrentPage()]), buff, 4096, 1, 1))
						SetClipboardText(buff, 4096);

					break;
				}

				case IDC_LISTVIEW_SAVE_AS:
				{
					OPENFILENAME of = {0};

					wchar_t buff[4096] = {0};
					StringCchCopy(szBufferW, MAX_PATH, L"report.txt\0");

					of.lStructSize = sizeof(of);
					of.hwndOwner = hwndDlg;
					of.lpstrFilter = L"Все файлы (*.*)\0*.*\0";
					of.lpstrFile = szBufferW;
					of.nMaxFile = MAX_PATH;
					of.Flags = OFN_EXPLORER | OFN_FORCESHOWHIDDEN | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;

					if(GetSaveFileName(&of))
					{
						if(GetListViewText(GetDlgItem(hwndDlg, page_list.lv_id[GetCurrentPage()]), buff, 4096))
						{
							HANDLE hFile = CreateFile(szBufferW, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

							if(!hFile)
								return 0;

							// UTF-16 LE File Encoding
							char header[2] = {0xFF, 0xFE};

							DWORD dwWriten = 0;
							WriteFile(hFile, header, 2, &dwWriten, NULL); // Write Header
							WriteFile(hFile, buff, (lstrlen(buff) * 2) + dwWriten - 1, &dwWriten, NULL); // Write Text

							CloseHandle(hFile);
						}
					}

					break;
				}

				// Ping Start (In New Thread)
				case IDC_PING_START:
				{
					iBuffer = GetPageId(IDD_PAGE_PING);

					if(page_list.thread[iBuffer])
					{
						if(MessageBox(hwndDlg, L"Вы действительно хотите остановить процесс?", APP_NAME, MB_YESNO | MB_ICONEXCLAMATION) == IDYES)
							page_list.thread[iBuffer] = 0;
					}
					else
					{
						_beginthread(Ping, 0, (LPVOID)hwndDlg);
					}

					break;
				}

				// Ping Clear
				case IDC_PING_CLEAR:
				{
					if(SendDlgItemMessage(hwndDlg, IDC_PING_RESULT, LVM_GETITEMCOUNT, 0, 0))
					{
						if(MessageBox(hwndDlg, L"Вы действительно хотите очистить полученные данные?", APP_NAME, MB_YESNO | MB_ICONEXCLAMATION) == IDYES)
							SendDlgItemMessage(hwndDlg, IDC_PING_RESULT, LVM_DELETEALLITEMS, 0, 0);
					}

					break;
				}

				// Speed Meter Start (In New Thread)
				case IDC_SPEEDMETER_START:
				{
					iBuffer = GetPageId(IDD_PAGE_SPEEDMETER);

					if(page_list.thread[iBuffer])
					{
						if(MessageBox(hwndDlg, L"Вы действительно хотите остановить процесс?", APP_NAME, MB_YESNO | MB_ICONEXCLAMATION) == IDYES)
							page_list.thread[GetPageId(IDD_PAGE_SPEEDMETER)] = 0;
					}
					else
					{
						if(MessageBox(hwndDlg, L"Вы действительно хотите начать?", APP_NAME, MB_YESNO | MB_ICONQUESTION) == IDYES)
							_beginthread(GetDownloadSpeed, 0, (LPVOID)hwndDlg);
					}

					break;
				}

				// Speed Meter Clear
				case IDC_SPEEDMETER_CLEAR:
				{
					if(MessageBox(hwndDlg, L"Вы действительно хотите очистить полученные данные?", APP_NAME, MB_YESNO | MB_ICONEXCLAMATION) == IDYES)
						Lv_Fill(hwndDlg, IDC_SPEEDMETER_RESULT, 0, 1, 0, -1);

					break;
				}

				// Url Decoder Start
				case IDC_URLDECODER_START:
				{
					wchar_t szResult[1024] = {0};
					DWORD dwSize = 1024;

					// Clear Previous Result
					SetDlgItemText(hwndDlg, IDC_URLDECODER_RESULT, 0);

					// Disable Button
					EnableWindow(GetDlgItem(hwndDlg, IDC_URLDECODER_START), 0);
					EnableWindow(GetDlgItem(hwndDlg, IDC_URLDECODER_CLEAR), 0);

					// Get Url
					if(!GetDlgItemText(hwndDlg, IDC_URLDECODER_LINK, szBufferW, MAX_PATH))
					{
						StringCchCopy(szResult, 1024, L"Необходимо ввести ссылку\0");
					}
					else
					{
						// Percent Decode
						if(UrlUnescape(szBufferW, szResult, &dwSize, 0) != S_OK)
							StringCchPrintf(szResult, 1024, L"Ошибка получения адреса (код ошибки: %i)\0", GetLastError());
					}

					// Show Result
					SetDlgItemText(hwndDlg, IDC_URLDECODER_RESULT, szResult);

					// Restore Buttons
					EnableWindow(GetDlgItem(hwndDlg, IDC_URLDECODER_START), 1);
					EnableWindow(GetDlgItem(hwndDlg, IDC_URLDECODER_CLEAR), 1);

					break;
				}

				// Url Decoder Clear
				case IDC_URLDECODER_CLEAR:
				{
					if(SendDlgItemMessage(hwndDlg, IDC_URLDECODER_RESULT, WM_GETTEXTLENGTH, 0, 0))
					{
						if(MessageBox(hwndDlg, L"Вы действительно хотите очистить полученные данные?", APP_NAME, MB_YESNO | MB_ICONEXCLAMATION) == IDYES)
							SetDlgItemText(hwndDlg, IDC_URLDECODER_RESULT, 0);
					}

					break;
				}

				// Host Address Start
				case IDC_HOSTADDR_START:
				{
					wchar_t szAddrList[1024] = {0};

					// Clear Previous Result
					SetDlgItemText(hwndDlg, IDC_HOSTADDR_RESULT, 0);

					// Disable Button
					EnableWindow(GetDlgItem(hwndDlg, IDC_HOSTADDR_START), 0);
					EnableWindow(GetDlgItem(hwndDlg, IDC_HOSTADDR_CLEAR), 0);

					// Get Host Name
					if(!GetDlgItemText(hwndDlg, IDC_HOSTADDR_HOST, szBufferW, MAX_PATH))
					{
						SetDlgItemText(hwndDlg, IDC_HOSTADDR_RESULT, L"Необходимо ввести адрес хоста");
					}
					else
					{
						wchar_t szHost[INTERNET_MAX_HOST_NAME_LENGTH] = {0};

						ADDRINFOW *result = {0}, hints = {0};

						hints.ai_family = AF_UNSPEC;
						hints.ai_socktype = SOCK_STREAM;
						hints.ai_protocol = IPPROTO_TCP;

						// Get Address List
						if(GetAddrInfoW(GetUrlHost(szBufferW, szHost, INTERNET_MAX_HOST_NAME_LENGTH) ? szHost : szBufferW, 0, &hints, &result))
						{
							StringCchPrintf(szBufferW, MAX_PATH, L"Ошибка получения адреса (код ошибки: %i)\0", WSAGetLastError());
							SetDlgItemText(hwndDlg, IDC_HOSTADDR_RESULT, szBufferW);
						}
						else
						{
							int i = 0;

							for(ADDRINFOW* ptr = result; ptr; ptr = ptr->ai_next)
							{
								wchar_t ipaddr[100] = {0};
								DWORD iLenght = 100;
								LPSOCKADDR sockaddr_ip = (LPSOCKADDR)ptr->ai_addr;

								if(!WSAAddressToString(sockaddr_ip, (DWORD)ptr->ai_addrlen, NULL, ipaddr, &iLenght))
								{
									StringCchPrintf(szBufferW, MAX_PATH, L"%i) %s [%s]\0", ++i, ipaddr, (ptr->ai_family == AF_INET) ? L"IPv4" : L"IPv6");
									StringCchCat(szAddrList, 1024, szBufferW);
								}
							}
						}

						// Clear Memory
						FreeAddrInfoW(result);
					}

					// Show Result
					SetDlgItemText(hwndDlg, IDC_HOSTADDR_RESULT, szAddrList);

					// Restore Buttons
					EnableWindow(GetDlgItem(hwndDlg, IDC_HOSTADDR_START), 1);
					EnableWindow(GetDlgItem(hwndDlg, IDC_HOSTADDR_CLEAR), 1);

					break;
				}

				// Host Address Clear
				case IDC_HOSTADDR_CLEAR:
				{
					if(SendDlgItemMessage(hwndDlg, IDC_HOSTADDR_RESULT, WM_GETTEXTLENGTH, 0, 0))
					{
						if(MessageBox(hwndDlg, L"Вы действительно хотите очистить полученные данные?", APP_NAME, MB_YESNO | MB_ICONEXCLAMATION) == IDYES)
							SetDlgItemText(hwndDlg, IDC_HOSTADDR_RESULT, 0);
					}

					break;
				}

				// Url Info Start
				case IDC_URLINFO_START:
				{
					_beginthread(GetUrlInfo, 0, (LPVOID)hwndDlg);
					break;
				}

				// Url Info Clear
				case IDC_URLINFO_CLEAR:
				{
					if(MessageBox(hwndDlg, L"Вы действительно хотите очистить полученные данные?", APP_NAME, MB_YESNO | MB_ICONEXCLAMATION) == IDYES)
					{
						Lv_Fill(hwndDlg, IDC_URLINFO_RESULT, 0, 1, 0, -1, IL_SUCCESS);
						SetDlgItemText(hwndDlg, IDC_URLINFO_HEADER, 0);
					}

					break;
				}

				// Url Info Header
				case IDC_URLINFO_HEADER_CHK:
				{
					iBuffer = IsDlgButtonChecked(hwndDlg, IDC_URLINFO_HEADER_CHK) == BST_CHECKED;

					ShowWindow(GetDlgItem(hwndDlg, IDC_URLINFO_HEADER), iBuffer ? SW_SHOW : SW_HIDE);
					ShowWindow(GetDlgItem(hwndDlg, IDC_URLINFO_RESULT), iBuffer ? SW_HIDE : SW_SHOW);

					break;
				}

				// Ip Start
				case IDC_IP_REFRESH:
				{
					// Get External Address (In Another Thread)
					if(IsDlgButtonChecked(hwndDlg, IDC_IP_EXTERNAL_CHK) == BST_CHECKED)
						_beginthread(GetExternalIp, 0, hwndDlg);
					else
						Lv_Fill(hwndDlg, IDC_IP_RESULT, L"n/a", 1, 0, 6, IL_SUCCESS);

					// Chean Old Address List
					while(SendDlgItemMessage(hwndDlg, IDC_IP_RESULT, LVM_DELETEITEM, 6, 0));
					
					// Get Local Address List
					if(!gethostname(szBufferA, MAX_PATH))
					{
						hostent* sh = gethostbyname((char*)&szBufferA);

						if(sh)
						{
							int iAdapter = 0;

							while(sh->h_addr_list[iAdapter])
							{
								sockaddr_in adr = {0};
								memcpy(&adr.sin_addr, sh->h_addr_list[iAdapter], sh->h_length);

								StringCchPrintf(szBufferW, MAX_PATH, L"Адрес №%i", iAdapter + 1);
								Lv_InsertItem(hwndDlg, IDC_IP_RESULT, szBufferW, 6 + iAdapter, 0, IL_SUCCESS, 1);
								Lv_InsertItemA(hwndDlg, IDC_IP_RESULT, inet_ntoa(adr.sin_addr), 6 + iAdapter, 1);
	
								iAdapter++;
							}
						}
					}

					break;
				}

				// Whois Start
				case IDC_WHOIS_START:
				{
					_beginthread(GetWhois, 0, (LPVOID)hwndDlg);
					break;
				}

				// Whois Clear
				case IDC_WHOIS_CLEAR:
				{
					if(SendDlgItemMessage(hwndDlg, IDC_WHOIS_RESULT, WM_GETTEXTLENGTH, 0, 0))
					{
						if(MessageBox(hwndDlg, L"Вы действительно хотите очистить полученные данные?", APP_NAME, MB_YESNO | MB_ICONEXCLAMATION) == IDYES)
							SetDlgItemText(hwndDlg, IDC_WHOIS_RESULT, 0);
					}

					break;
				}

				// Share Info Start
				case IDC_SHAREDINFO_START:
				{
					// Clear Previous Result
					SendDlgItemMessage(hwndDlg, IDC_SHAREDINFO, LVM_DELETEALLITEMS, 0, 0);

					NET_API_STATUS dwStatus = 0;
					PSHARE_INFO_502 pShareInfo, p;
					DWORD dwReaded = 0, dwTotal = 0, dwResume = 0;

					iBuffer = 0;

					do
					{
						dwStatus = NetShareEnum(0, 502, (LPBYTE*)&pShareInfo, MAX_PREFERRED_LENGTH, &dwReaded, &dwTotal, &dwResume);

						if(dwStatus == ERROR_SUCCESS || dwStatus == ERROR_MORE_DATA)
						{
							p = pShareInfo;

							for(int i = 1; i <= dwReaded; i++)
							{
								Lv_InsertItem(hwndDlg, IDC_SHAREDINFO, p->shi502_netname, iBuffer, 0, IL_SUCCESS);
								Lv_InsertItem(hwndDlg, IDC_SHAREDINFO, wcslen(p->shi502_path) ? p->shi502_path : L"n/a", iBuffer, 1);

								StringCchPrintf(szBufferW, MAX_PATH, L"%d\0", p->shi502_current_uses);
								Lv_InsertItem(hwndDlg, IDC_SHAREDINFO, szBufferW, iBuffer++, 2);

								p++;
							}

							NetApiBufferFree(pShareInfo);
						}
					}
					while(dwStatus == ERROR_MORE_DATA);

					break;
				}

				// Share Info Clear
				case IDC_SHAREDINFO_CLEAR:
				{
					if(SendDlgItemMessage(hwndDlg, IDC_SHAREDINFO, LVM_GETITEMCOUNT, 0, 0))
					{
						if(MessageBox(hwndDlg, L"Вы действительно хотите очистить полученные данные?", APP_NAME, MB_YESNO | MB_ICONEXCLAMATION) == IDYES)
							SendDlgItemMessage(hwndDlg, IDC_SHAREDINFO, LVM_DELETEALLITEMS, 0, 0);
					}

					break;
				}
			}

			break;
		}
	}

	return 0;
}

// TreeView Custom Draw
long TreeView_CustDraw(LPNMTVCUSTOMDRAW lptvcd)
{
	if(lptvcd->nmcd.hdr.idFrom != IDC_ITEMLIST)
		return 0;

	switch(lptvcd->nmcd.dwDrawStage)
	{ 
		case CDDS_PREPAINT:
		{
			return (CDRF_NOTIFYPOSTPAINT | CDRF_NOTIFYITEMDRAW);
		}

		case CDDS_ITEMPREPAINT:
		{
			COLORREF clTextClr = GetSysColor(COLOR_GRAYTEXT);
			DWORD dwWeight = 0, dwUnderline = 0;

			// Node Indication
            if(!lptvcd->iLevel)
			{
				dwWeight = FW_BOLD;
				clTextClr = RGB(0, 0, 0);
			}

			// Hot-Track Indication
			if(lptvcd->nmcd.uItemState & CDIS_HOT)
			{
				clTextClr = RGB(0, 78, 152);
				dwUnderline = 1;
				lptvcd->clrTextBk = RGB(216, 231, 239);
			}

			// Selection Indication
			if(lptvcd->nmcd.uItemState & CDIS_SELECTED)
			{
				clTextClr = RGB(0, 0, 0);
				lptvcd->clrTextBk = RGB(171, 208, 228);
			}

			// Change Font
			HFONT hFont = CreateFont(-11, 0, 0, 0, dwWeight, 0, dwUnderline, 0, DEFAULT_CHARSET, OUT_CHARACTER_PRECIS, CLIP_CHARACTER_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, 0);
            SelectObject(lptvcd->nmcd.hdc, hFont);
            DeleteObject(hFont);

			// Change Text Color
			lptvcd->clrText = clTextClr;

			return (CDRF_NOTIFYPOSTPAINT | CDRF_NEWFONT);
		}
	}

	return 0;
}

// Main Dialog Procedure
LRESULT CALLBACK DlgProc(HWND hwndDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	wchar_t szBuffer[MAX_PATH] = {0};
	int iBuffer = 0;

	switch(uMsg)
	{
		case WM_INITDIALOG:
		{
			// Check Mutex
			HANDLE hMutex = CreateMutex(NULL, TRUE, APP_NAME_SHORT);

			if(GetLastError() == ERROR_ALREADY_EXISTS)
			{
				CloseHandle(hMutex);
				ExitProcess(0);
			}

			// Load Winsock Library
			if(WSAStartup(MAKEWORD(2, 2), &wsa))
			{
				StringCchPrintf(szBuffer, MAX_PATH, L"Ошибка загрузки Windows Socket Library (код ошибки %i)", WSAGetLastError());
				MessageBox(hwndDlg, szBuffer, APP_NAME, MB_OK | MB_ICONSTOP);

				ExitProcess(0);
			}

			// Set Window Title
			SetWindowText(hwndDlg, APP_NAME L" " APP_VERSION);

			// Handles
			hMainDlg = hwndDlg;
			page_list.hWnd = GetDlgItem(hwndDlg, IDC_ITEMLIST);
			hBold = CreateFont(-11, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_CHARACTER_PRECIS, CLIP_CHARACTER_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, 0);

			// Modify System Menu
			HMENU hMenu = GetSystemMenu(hwndDlg, 0);
			InsertMenu(hMenu, -1, MF_BYCOMMAND | MF_SEPARATOR, 0, 0);
			InsertMenu(hMenu, -1, MF_BYCOMMAND | MF_STRING, IDM_ABOUT, L"О программе");

			// Load Settings
			GetModuleFileName(0, szBuffer, MAX_PATH);
			PathRenameExtension(szBuffer, L".cfg");
			cfg.load(szBuffer);

			// Configure Treeview
			SetWindowTheme(page_list.hWnd, L"Explorer", 0);
			SendMessage(page_list.hWnd, TVM_SETEXTENDEDSTYLE, 0, TVS_EX_DOUBLEBUFFER | TVS_EX_FADEINOUTEXPANDOS);

			// Set Icons
			SendMessage(hwndDlg, WM_SETICON, ICON_BIG, (LPARAM)LoadImage(GetModuleHandle(0), MAKEINTRESOURCE(IDI_MAIN), IMAGE_ICON, 32, 32, 0));
			SendMessage(hwndDlg, WM_SETICON, ICON_SMALL, (LPARAM)LoadImage(GetModuleHandle(0), MAKEINTRESOURCE(IDI_MAIN), IMAGE_ICON, 16, 16, 0));

			// Create ImageList
			hImgList = ImageList_Create(16, 16, ILC_COLOR32 | ILC_MASK, 0, 5);

			ImageList_Add(hImgList, IDI_FOLDER);
			ImageList_Add(hImgList, IDI_FOLDER_CURRENT);
			ImageList_Add(hImgList, IDI_SUCCESS);
			ImageList_Add(hImgList, IDI_FAULT);

			SendDlgItemMessage(hwndDlg, IDC_ITEMLIST, TVM_SETIMAGELIST, TVSIL_NORMAL, (LPARAM)hImgList);

			// StatusBar
			int iParts[] = {200, -1};
			SendDlgItemMessage(hwndDlg, IDC_STATUSBAR, SB_SETPARTS, 2, (LPARAM)iParts);

			HICON hIcon = ImageList_GetIcon(hImgList, IL_FOLDER, ILD_NORMAL);
			SendDlgItemMessage(hwndDlg, IDC_STATUSBAR, SB_SETICON, 0, (LPARAM)hIcon);

			// Insert Categories
			for(int i = 0; i < CATEGORY_COUNT; i++)
				category_list.hitem[i] = Tv_InsertItem(hwndDlg, IDC_ITEMLIST, category_list.name[i], 0, IL_FOLDER);

			// Insert Items
			for(int i = 0; i < PAGE_COUNT; i++)
				page_list.hItem[i] = Tv_InsertItem(hwndDlg, IDC_ITEMLIST, page_list.title[i], category_list.hitem[page_list.category[i]], IL_FOLDER, IL_FOLDER_CURRENT, i);

			// Restore Last Selection
			SetCurrentPage(cfg.read(APP_NAME_SHORT, L"LastItem", GetPageId(IDD_PAGE_SYSINFO)));

			// Check Updates
			iBuffer = cfg.read(APP_NAME_SHORT, L"CheckUpdateAtStartup", 1);
			CheckMenuItem(GetMenu(hwndDlg), IDM_CFG_CHECKUPDATES, MF_BYCOMMAND | (iBuffer) ? MF_CHECKED : MF_UNCHECKED);

			if(iBuffer)
				_beginthread(CheckUpdates, 0, (LPVOID)1);

			// Create Timer
			SetTimer(hwndDlg, 1337, 500, TimerProc);

			break;
		}

		case WM_CLOSE:
		{
			// Destroy Timer
			KillTimer(hwndDlg, 1337);

			// Destroy Threads
			for(int i = 0; i < PAGE_COUNT; i++)
				page_list.thread[i] = 0;

			// Save Settings
			cfg.write(APP_NAME_SHORT, L"LastItem", GetCurrentPage());

			// Unload Winsock Library
			WSACleanup();

			// Destroy Window
			DestroyWindow(hwndDlg);
			PostQuitMessage(0);

			break;
		}

		case WM_NOTIFY:
		{
			LPNMHDR lphdr = (LPNMHDR)lParam;

			switch(lphdr->code)
			{
				case TVN_SELCHANGED:
				{
					if(wParam == IDC_ITEMLIST)
					{
						LPNMTREEVIEW pnmtv = (LPNMTREEVIEW)lParam;
						iBuffer = pnmtv->itemNew.lParam;

						ShowWindow(page_list.hCurrent, SW_HIDE);

						// Category Selected
						if(iBuffer == -1)
						{
							TVITEMEX tvi = {0};

							tvi.hItem = (HTREEITEM)SendMessage(pnmtv->hdr.hwndFrom, TVM_GETNEXTITEM, TVGN_CHILD, (LPARAM)pnmtv->itemNew.hItem);
							tvi.mask = TVIF_HANDLE;

							SendMessage(pnmtv->hdr.hwndFrom, TVM_GETITEM, 0, (LPARAM)&tvi);
							SendMessage(pnmtv->hdr.hwndFrom, TVM_SELECTITEM, TVGN_CARET, (LPARAM)tvi.hItem);

							return 0;
						}

						// Show or Hide Window
						if(page_list.hPage[iBuffer])
						{
							ShowWindow(page_list.hPage[iBuffer], SW_SHOW);
							page_list.hCurrent = page_list.hPage[iBuffer];
						}
						else
						{
							page_list.hCurrent = CreateDialog(GetModuleHandle(0), MAKEINTRESOURCE(page_list.dlg_id[iBuffer]), hwndDlg, PageDlgProc);
							page_list.hPage[iBuffer] = page_list.hCurrent;
						}
						
						// Statusbar Text
						SendDlgItemMessage(hwndDlg, IDC_STATUSBAR, SB_SETTEXT, 0, (LPARAM)page_list.title[iBuffer]);
					}

					break;
				}

				case NM_CUSTOMDRAW:
				{
					SetWindowLong(hwndDlg, DWL_MSGRESULT, TreeView_CustDraw((LPNMTVCUSTOMDRAW)lParam));
					return 1;
				}
			}

			break;
		}

		case WM_SYSCOMMAND:
		{
			if(wParam == IDM_ABOUT)
				SendMessage(hwndDlg, WM_COMMAND, MAKELPARAM(IDM_ABOUT, 0), 0);

			break;
		}

		case WM_COMMAND:
		{
			switch(LOWORD(wParam))
			{
				case IDCANCEL: // process Esc key
				case IDM_EXIT:
					SendMessage(hwndDlg, WM_CLOSE, 0, 0);
					break;

				case IDM_CFG_CHECKUPDATES:
					iBuffer = cfg.read(APP_NAME_SHORT, L"CheckUpdateAtStartup", 1);
					CheckMenuItem(GetMenu(hwndDlg), IDM_CFG_CHECKUPDATES, MF_BYCOMMAND | (iBuffer) ? MF_UNCHECKED : MF_CHECKED);
					cfg.write(APP_NAME_SHORT, L"CheckUpdateAtStartup", iBuffer ? 0 : 1);

					break;

				case IDM_WEBSITE:
					ShellExecute(hwndDlg, L"open", APP_WEBSITE, NULL, NULL, SW_SHOW);
					break;

				case IDM_CHECK_UPDATES:
					_beginthread(CheckUpdates, 0, 0);
					break;

				case IDM_ABOUT:
					CAboutBox about;
					about.Create(hwndDlg);

					break;
			}

			break;
		}
	}

	return 0;
}

// Entry Point
int APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nShowCmd)
{
	MSG msg = {0};
	INITCOMMONCONTROLSEX icex = {0};

	icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
	icex.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES;

	if(!InitCommonControlsEx(&icex))
		return 0;

	if(!CreateDialog(hInstance, MAKEINTRESOURCE(IDD_MAIN), NULL, (DLGPROC)DlgProc))
		return 0;

	while(GetMessage(&msg, NULL, 0, 0))
	{
		if(!IsDialogMessage(hMainDlg, &msg))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	
	return msg.wParam;
}