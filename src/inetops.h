/************************************
*  	InetOps
*	Copyright © 2012 Henry++
*
*	GNU General Public License v2
*	http://www.gnu.org/licenses/
*
*	http://www.henrypp.org/
*************************************/

#ifndef __INETOPS_H__
#define __INETOPS_H__

// Define
#define APP_NAME L"InetOps"
#define APP_NAME_SHORT L"inetops"
#define APP_VERSION L"1.0"
#define APP_VERSION_RES 1,0
#define APP_HOST L"www.henrypp.org"
#define APP_WEBSITE L"http://" APP_HOST

// Variables
HWND hMainDlg = NULL;
HIMAGELIST hImgList = NULL;
WSADATA wsa = {0};
HFONT hBold = NULL;

// Prototypes
int GetPageId(int);
int GetCurrentPage();
void SetCurrentPage(int);
void ListView_SetTheme(HWND, int, bool);
void ImageList_Add(HIMAGELIST, int);

// Imagelist Icon Id
#define IL_FOLDER 0
#define IL_FOLDER_CURRENT 1
#define IL_SUCCESS 2
#define IL_FAULT 3

// Page Navigation Config
#define PAGE_COUNT 13
#define CATEGORY_COUNT 3

// Page List Structure
struct PAGE_LIST
{
	wchar_t* title[PAGE_COUNT];
	wchar_t* description[PAGE_COUNT];

	bool thread[PAGE_COUNT];

    HWND hWnd;
    HWND hCurrent;

	HWND hPage[PAGE_COUNT];
	HTREEITEM hItem[PAGE_COUNT];

    int dlg_id[PAGE_COUNT];
    int lv_id[PAGE_COUNT];
    int category[PAGE_COUNT];
};

// Category List Structure
struct CATEGORY_LIST
{
	wchar_t* name[PAGE_COUNT];
	HTREEITEM hitem[PAGE_COUNT];
};

// Whois Servers List
// http://www.iana.org/domains/root/db/
wchar_t* whois_servers[] =
{
	L"whois.verisign-grs.com", // com & net
	L"whois.dotgov.gov", // gov
	L"whois.afilias.net", // info
	L"whois.nic.kz", // kz
	L"whois.nic.name", // name
	L"whois.pir.org", // org
	L"whois.tcinet.ru", // ru
	L"whois.ua", // ua
	L"whois.website.ws", // ws
};

// Modified "fExportListView"
// http://www.codeproject.com/KB/list/fexportlistview.aspx
bool GetListViewText(HWND hWnd, wchar_t* szOut, size_t cbSize, bool bSelectedOnly = 0, int iSubItem = -1)
{
	LVITEM lvi = {0};
	wchar_t szBuffer[MAX_PATH] = {0}, szTemp[MAX_PATH] = {0};

	// Get Item Count
	int iCount = SendMessage(hWnd, LVM_GETITEMCOUNT, 0, 0);

	if(!iCount)
		return 0;
	
	// Get Column Count
	int iCols = SendMessage((HWND)SendMessage(hWnd, LVM_GETHEADER, 0, 0), HDM_GETITEMCOUNT, 0, 0);

	if(!iCols)
		return 0;

	// Get Items
	for(int i = 0; i < iCount; i++)
	{
		// Only Selected items
		if(bSelectedOnly)
		{
			if(!SendMessage(hWnd, LVM_GETITEMSTATE, i, LVIS_SELECTED | LVIS_FOCUSED))
				continue;
		}

		// Configure Structure
		lvi.mask = LVIF_TEXT;
		lvi.pszText = szBuffer;
		lvi.cchTextMax = MAX_PATH;

		// Get Subitems
		for(int j = 0; j < iCols; j++)
		{
			if(iSubItem != -1)
			{
				if(iSubItem != j)
					continue;
			}

			lvi.iSubItem = j;
			SendMessage(hWnd, LVM_GETITEMTEXT, i, (LPARAM)&lvi);

			StringCchPrintf(szTemp, MAX_PATH, (iSubItem != -1) ? L"%s\0" : L"%-20s", szBuffer);
			StringCchCat(szOut, cbSize, szTemp);
		}

		StringCchCat(szOut, cbSize, L"\r\n\0");
	}

	return 1;
}

bool ValidateUrl(wchar_t* szUrl, size_t cbSize)
{
	URL_COMPONENTS urlc = {0};

	if(!InternetCrackUrl(szUrl, cbSize, 0, &urlc) && GetLastError() == ERROR_INTERNET_UNRECOGNIZED_SCHEME)
	{
		wchar_t szBuffer[MAX_PATH] = L"http://\0";

		StringCchCat(szBuffer, MAX_PATH, szUrl);
		StringCchCopy(szUrl, cbSize, szBuffer);

		return 1;
	}

	return 0;
}

// Check String Is Ip
bool StringIsIp(char* addr)
{
	unsigned long ulCheck = inet_addr(addr);

	if(ulCheck == INADDR_NONE || ulCheck == INADDR_ANY)
		return 0;
	
	return 1;
}

// Extract Host From Url
bool GetUrlHost(wchar_t* szUrl, wchar_t* szOut, int iSize)
{
	URL_COMPONENTS urlc = {0}; 

	urlc.dwStructSize = sizeof(urlc);
    urlc.lpszHostName = szOut;
    urlc.dwHostNameLength = iSize;

	return InternetCrackUrl(szUrl, wcslen(szUrl) + 1, ICU_DECODE, &urlc) ? 1 : 0;
}

// Insert Item (TreeView)
HTREEITEM Tv_InsertItem(HWND hWnd, int iDlgItem, wchar_t* szText, HTREEITEM hParent = 0, int iImage = -1, int iSelImage = -1, LPARAM lParam = -1)
{
	TVINSERTSTRUCT insert = {0};
	
	insert.hParent = hParent;
	insert.hInsertAfter = TVI_LAST;
	insert.itemex.mask = TVIF_TEXT | TVIF_PARAM;
	insert.itemex.pszText = szText;
	insert.itemex.cchTextMax = MAX_PATH;
	insert.itemex.lParam = lParam;

	// Expand Node
	if(!hParent)
	{
		insert.itemex.mask |= TVIF_STATE;
		insert.itemex.state = TVIS_EXPANDED;
		insert.itemex.stateMask = TVIS_EXPANDED;
	}

	if(iImage != -1)
	{
		insert.itemex.mask |= TVIF_IMAGE | TVIF_SELECTEDIMAGE;
		insert.itemex.iImage = iImage;
		insert.itemex.iSelectedImage = (iSelImage == -1) ? iImage : iSelImage;
	}

	return (HTREEITEM)SendDlgItemMessage(hWnd, iDlgItem, TVM_INSERTITEM, 0, (LPARAM)&insert);
}

// Insert Group (ListView)
void Lv_InsertGroup(HWND hWnd, int iDlgItem, wchar_t* szText, int iGroupId, int iState)
{
	LVGROUP group = {0};

	group.cbSize = sizeof(group);
	group.mask = LVGF_GROUPID | LVGF_HEADER | LVGF_STATE;
	group.pszHeader = szText;
	group.cchHeader = MAX_PATH;
	group.iGroupId = iGroupId;
	group.state = LVGS_NORMAL | iState;

	SendDlgItemMessage(hWnd, iDlgItem, LVM_INSERTGROUP, iGroupId, (LPARAM)&group);
}

// Insert Column (ListView)
void Lv_InsertColumn(HWND hWnd, int iDlgItem, wchar_t* szText, int iWidth, int iItem, int iFmt)
{
	LVCOLUMN lvc = {0};

	lvc.mask = LVCF_WIDTH | LVCF_TEXT | LVCF_FMT | LVCF_SUBITEM;
	lvc.fmt = iFmt;
	lvc.pszText = szText;
	lvc.cchTextMax = MAX_PATH;
	lvc.cx = iWidth;
	lvc.iSubItem = iItem;

	SendDlgItemMessage(hWnd, iDlgItem, LVM_INSERTCOLUMN, iItem, (LPARAM)&lvc);
}

// Insert Item (ListView)
void Lv_InsertItem(HWND hWnd, int iDlgItem, wchar_t* szText, int iItem, int iSubItem, int iImage = -1, int iGroupId = -1)
{
	LVITEM item = {0};
	
	item.mask = LVIF_TEXT;
	item.pszText = szText;
	item.cchTextMax = MAX_PATH;
	item.iItem = iItem;
	item.iSubItem = iSubItem;

	if(iImage != -1 && iSubItem > 0)
	{
		LVITEM item_edit = {0};

		item_edit.mask = LVIF_IMAGE;
		item_edit.iItem = iItem;
		item_edit.iSubItem = 0;
		item_edit.iImage = iImage;

		SendDlgItemMessage(hWnd, iDlgItem, LVM_SETITEM, 0, (LPARAM)&item_edit);
	}

	if(iImage != -1)
	{
		item.mask |= LVIF_IMAGE;
		item.iImage = iImage;
	}

	if(iGroupId != -1)
	{
		item.mask |= LVIF_GROUPID;
		item.iGroupId = iGroupId;
	}

	SendDlgItemMessage(hWnd, iDlgItem, (iSubItem > 0) ? LVM_SETITEM : LVM_INSERTITEM, 0, (LPARAM)&item);
}

// Insert Item (ListView) (ANSI)
void Lv_InsertItemA(HWND hWnd, int iDlgItem, char* szText, int iItem, int iSubItem, int iImage = -1, int iGroupId = -1)
{
	wchar_t szBuffer[MAX_PATH] = {0};
	MultiByteToWideChar(CP_ACP, 0, szText, MAX_PATH, szBuffer, MAX_PATH);

	Lv_InsertItem(hWnd, iDlgItem, szBuffer, iItem, iSubItem, iImage, iGroupId);
}

// Fill Listview With Text
void Lv_Fill(HWND hWnd, int iDlgItem, wchar_t* szText, int iSubItem, int iFrom, int iTo, int iImage = -1)
{
	if(iTo == -1)
		iTo = SendDlgItemMessage(hWnd, iDlgItem, LVM_GETITEMCOUNT, 0, 0);

	for(int i = iFrom; i < iTo; i++)
		Lv_InsertItem(hWnd, iDlgItem, szText, i, iSubItem, iImage);
}

// Time Format
void time_format(DWORD dwTime, wchar_t* szBuffer)
{
	DWORD dwBuff = dwTime % 3600;

	StringCchPrintf(szBuffer, MAX_PATH, L"%02d:%02d:%02d\0", dwTime / 3600, dwBuff / 60, dwBuff % 60);
}
// Date Format
void date_format(SYSTEMTIME* st, wchar_t* szBuffer)
{
	wchar_t szTemp[MAX_PATH] = {0};

	switch(st->wMonth)
	{
		case 1:
			wcsncpy(szTemp, L"января", MAX_PATH);
			break;
			
		case 2:
			wcsncpy(szTemp, L"февраля", MAX_PATH);
			break;
			
		case 3:
			wcsncpy(szTemp, L"марта", MAX_PATH);
			break;
			
		case 4:
			wcsncpy(szTemp, L"апреля", MAX_PATH);
			break;
			
		case 5:
			wcsncpy(szTemp, L"мая", MAX_PATH);
			break;
			
		case 6:
			wcsncpy(szTemp, L"июня", MAX_PATH);
			break;
			
		case 7:
			wcsncpy(szTemp, L"июля", MAX_PATH);
			break;
			
		case 8:
			wcsncpy(szTemp, L"августа", MAX_PATH);
			break;
			
		case 9:
			wcsncpy(szTemp, L"сентября", MAX_PATH);
			break;
			
		case 10:
			wcsncpy(szTemp, L"октября", MAX_PATH);
			break;
			
		case 11:
			wcsncpy(szTemp, L"ноября", MAX_PATH);
			break;
			
		case 12:
			wcsncpy(szTemp, L"декабря", MAX_PATH);
			break;

		default:
			StringCchPrintf(szTemp, MAX_PATH, L"%d\0", st->wMonth);
			break;
	}

	StringCchPrintf(szBuffer, MAX_PATH, L"%d %s %04d (%02d:%02d:%02d)\0", st->wDay, szTemp, st->wYear, st->wHour, st->wMinute, st->wSecond);
}

// Number Format
void number_format(long long lNumber, wchar_t* szBuffer, wchar_t cSeparator = L',')
{
    if(!lNumber)
    {
        szBuffer[0] = L'0';
        szBuffer[1] = '\0';
 
        return;
    }
 
    int i = 0;
 
    do
    {
        if((i + 1) % 4 == 0)
            szBuffer[i++] = cSeparator;
 
        int mod = lNumber % 10;
 
        if(lNumber < 0)
            mod = -mod;
 
        szBuffer[i++] = mod + wchar_t('0');
    }
    while(lNumber /= 10);
 
    if(lNumber < 0)
    {
        szBuffer[i] = '-';
        szBuffer[i + 1] = '\0';
    }
    else
    {
        szBuffer[i] = '\0';
    }
 
    szBuffer = _wcsrev(szBuffer);
}

// Centering Window by Parent
void CenterDialog(HWND hwndWindow)
{
     HWND hParent = GetParent(hwndWindow);
	 RECT rcChild = {0}, rcParent = {0};

	 // If Parent Doesn't Exists - Use Desktop
	 if(!hParent)
		 hParent = GetDesktopWindow();

    GetWindowRect(hwndWindow, &rcChild);
    GetWindowRect(hParent, &rcParent);
 
    int nWidth = rcChild.right - rcChild.left;
    int nHeight = rcChild.bottom - rcChild.top;
 
    int nX = ((rcParent.right - rcParent.left) - nWidth) / 2 + rcParent.left;
    int nY = ((rcParent.bottom - rcParent.top) - nHeight) / 2 + rcParent.top;
 
    int nScreenWidth = GetSystemMetrics(SM_CXSCREEN);
    int nScreenHeight = GetSystemMetrics(SM_CYSCREEN);

    if (nX < 0) nX = 0;
    if (nY < 0) nY = 0;
    if (nX + nWidth > nScreenWidth) nX = nScreenWidth - nWidth;
    if (nY + nHeight > nScreenHeight) nY = nScreenHeight - nHeight;
 
    MoveWindow(hwndWindow, nX, nY, nWidth, nHeight, FALSE);
}

#endif // __INETOPS_H__
