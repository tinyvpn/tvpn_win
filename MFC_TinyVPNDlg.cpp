
// MFC_TinyVPNDlg.cpp : implementation file
//
#include "resource.h"
#include "pch.h"

#include "framework.h"
#include "MFC_TinyVPN.h"
#include "MFC_TinyVPNDlg.h"
#include "afxdialogex.h"
#include "Iphlpapi.h"

#include <string>
#include "tun_socket.h"
#include "log.h"
#include "stringutl.h"
#include "sockutl.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

int g_premium = 0;
uint32_t g_day_limit = 0;
uint32_t g_month_limit = 0;
//uint32_t g_day_traffic = 0;
//uint32_t g_month_traffic = 0;
int out_of_quota = 0;
std::string g_device_id;
std::string g_strUserName;
std::string g_strPassword;
std::string g_country_code;
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CMFCTinyVPNDlg dialog

bool RegSetDNS(LPCTSTR lpszAdapterName, LPCTSTR pDNS)
{
	HKEY hKey;
	std::string strKeyName = "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\";
	strKeyName += lpszAdapterName;
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		strKeyName.c_str(),
		0,
		KEY_WRITE,
		&hKey) != ERROR_SUCCESS)
		return false;

	char mszDNS[100];

	strncpy(mszDNS, pDNS, 98);

	int nDNS;

	nDNS = (int)strlen(mszDNS);

	*(mszDNS + nDNS + 1) = 0x00;	// REG_MULTI_SZ need add one more 0
	nDNS += 2;

	RegSetValueEx(hKey, "NameServer", 0, REG_SZ, (unsigned char*)mszDNS, nDNS);

	RegCloseKey(hKey);

	return true;
}
void test_network()
{
	ULONG ulAdapterInfoSize = sizeof(IP_ADAPTER_INFO);
	IP_ADAPTER_INFO* pAdapterInfoBkp, * pAdapterInfo = (IP_ADAPTER_INFO*)new char[ulAdapterInfoSize];
	pAdapterInfoBkp = pAdapterInfo;

	if (GetAdaptersInfo(pAdapterInfo, &ulAdapterInfoSize) ==
		ERROR_BUFFER_OVERFLOW) // out of buff
	{
		delete pAdapterInfo;
		pAdapterInfo = (IP_ADAPTER_INFO*)new char[ulAdapterInfoSize];
		pAdapterInfoBkp = pAdapterInfo;
	}

	if (GetAdaptersInfo(pAdapterInfo, &ulAdapterInfoSize) == ERROR_SUCCESS)
	{
		do {
			if ((pAdapterInfo->Type == MIB_IF_TYPE_ETHERNET|| pAdapterInfo->Type == IF_TYPE_PROP_VIRTUAL) && strncmp(pAdapterInfo->Description, "TAP-", 4) == 0) // 
			{
				//Here to use GetPerAdapterInfo 
				INFO("TAP type:%d,index:%d,name:%s,des:%s", pAdapterInfo->Type, pAdapterInfo->Index, pAdapterInfo->AdapterName, pAdapterInfo->Description);
				break;
			}
			INFO("type:%d,index:%d,name:%s,des:%s", pAdapterInfo->Type, pAdapterInfo->Index, pAdapterInfo->AdapterName, pAdapterInfo->Description);
			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
		//FlushDNS();
	}
	if (!pAdapterInfo)
		return;
	char tmp[16];
	strcpy(tmp, "8.8.8.8");

	RegSetDNS(pAdapterInfo->AdapterName, tmp);
	delete pAdapterInfoBkp;
}
CMFCTinyVPNDlg::CMFCTinyVPNDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_MFC_TINYVPN_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CMFCTinyVPNDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_USERNAME, txtUserName);
	DDX_Control(pDX, IDC_EDIT_PASSWORD, txtPassword);
	DDX_Control(pDX, IDC_BUTTON_LOGIN, btnLogin);
	DDX_Control(pDX, IDC_CHECK_VPN, chkVPN);
}

BEGIN_MESSAGE_MAP(CMFCTinyVPNDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_LOGIN, &CMFCTinyVPNDlg::OnBnClickedButtonLogin)
	ON_WM_CREATE()
	ON_WM_ACTIVATEAPP()
	ON_BN_CLICKED(IDC_CHECK_VPN, &CMFCTinyVPNDlg::OnBnClickedCheckVpn)
	ON_MESSAGE(WM_TRAFFIC_MESSAGE, OnTrafficMessage)
	ON_MESSAGE(WM_CONNECTED_MESSAGE, OnConnectedMessage)
	ON_MESSAGE(WM_DISCONNECTED_MESSAGE, OnDisconnectedMessage)
	ON_MESSAGE(WM_ERROR_MESSAGE, OnErrorMessage)
END_MESSAGE_MAP()


// CMFCTinyVPNDlg message handlers

BOOL CMFCTinyVPNDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	CString str1 = AfxGetApp()->GetProfileString(_T("UserInfo"), _T("Name"));
	CString str2 = AfxGetApp()->GetProfileString(_T("UserInfo"), _T("Password"));
	txtUserName.SetWindowTextA(str1);
	txtPassword.SetWindowTextA(str2);

	GEOID myGEO = GetUserGeoID(GEOCLASS_NATION);
	int sizeOfBuffer = GetGeoInfo(myGEO, GEO_ISO2, NULL, 0, 0);
	char* buffer = new char[sizeOfBuffer];
	int result = GetGeoInfo(myGEO, GEO_ISO2, buffer, sizeOfBuffer, 0);
	INFO("country code:%s", buffer);
	g_country_code = buffer;
	delete buffer;

	SetWindowText("TinyVPN");

	test_network();
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CMFCTinyVPNDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CMFCTinyVPNDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CMFCTinyVPNDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

int CMFCTinyVPNDlg::show_traffic(uint32_t d, uint32_t m)
{
	std::string strtemp;
	string_utl::RecursiveCommas(strtemp, d);
	out_of_quota = 0;
	if (g_premium < 2 && g_day_limit != 0 && d > g_day_limit) {
		strtemp = "Today: " + strtemp + " kB. No enough quota, pleaes upgrade to premium user.";
		GetDlgItem(IDC_STATIC_TODAY)->SetWindowText(strtemp.c_str());
		stop_vpn(1);
		INFO("out of quota");
		out_of_quota = 1;
	}
	else {
		if (g_premium < 2) {
			std::string strtemp2;
			string_utl::RecursiveCommas(strtemp2, g_day_limit);
			strtemp = "Today: " + strtemp + " kB / " + strtemp2 + " kB";
		}
		else {
	//		txtToday.stringValue = "Today: " + dd + " kB"
			strtemp = "Today: " + strtemp + " kB";
		}
		GetDlgItem(IDC_STATIC_TODAY)->SetWindowText(strtemp.c_str());
	}
//	let mm = format.string(from: m as NSNumber) ? ? ""
		//let ml = format.string(from : g_month_limit as NSNumber) ? ? ""
	strtemp.clear();
	string_utl::RecursiveCommas(strtemp, m);
	if (g_premium >= 2 && g_month_limit != 0 && m > g_month_limit) {  // 10 G
		strtemp = "This month: " + strtemp + " kB. No enough quota for premium user.";
		GetDlgItem(IDC_STATIC_THIS_MONTH)->SetWindowText(strtemp.c_str());
		stop_vpn(1);
		INFO("out of quota.");
		out_of_quota = 1;
	}
	else {
		if (g_premium >= 2) {
			std::string strtemp2;
			string_utl::RecursiveCommas(strtemp2, g_month_limit);
			strtemp = "This month: " + strtemp + " kB / " + strtemp2 + " kB";
		}
		else {
			strtemp = "This month: " + strtemp + " kB";
		}
		GetDlgItem(IDC_STATIC_THIS_MONTH)->SetWindowText(strtemp.c_str());
	}
		
	return 0;
}
void CMFCTinyVPNDlg::OnBnClickedButtonLogin()
{
	if (g_premium != 0) {
		txtUserName.EnableWindow(true);
		txtPassword.EnableWindow(true);
		g_premium = 0;
		btnLogin.SetWindowTextA("Login");
		GetDlgItem(IDC_STATIC_USER_STATUS)->SetWindowText("unregistered user.");
		return;
	}
	// TODO: Add your control notification handler code here
	CString strUserName;
	CString strPassword;
	txtUserName.GetWindowTextA(strUserName);
	txtPassword.GetWindowTextA(strPassword);
	g_strUserName = (LPCTSTR)strUserName;
	g_strPassword = (LPCTSTR)strPassword;

	HW_PROFILE_INFO hwProfileInfo;
	if (!GetCurrentHwProfile(&hwProfileInfo))
		return;
	INFO("HWID: %s\n", hwProfileInfo.szHwProfileGuid);
	std::string device_id = hwProfileInfo.szHwProfileGuid;
	device_id = "Win." + device_id.substr(1, device_id.size() - 2);
	INFO("HWID2: %s\n", device_id.c_str());
	g_device_id = device_id;

	uint32_t day_traffic, month_traffic, day_limit, month_limit;
	int ret1, ret2;
	int ret = login((LPCTSTR)strUserName, (LPCTSTR)strPassword, device_id, day_traffic, month_traffic, day_limit, month_limit, ret1,ret2);
	if (ret != 0) {
		GetDlgItem(IDC_STATIC_USER_STATUS)->SetWindowText("Login fail.");
		return;
	}

	if (ret1 == 0) {
		if (ret2 == 1) {
			GetDlgItem(IDC_STATIC_USER_STATUS)->SetWindowText("basic user login ok.");
		}
		else if (ret2 == 2) {
			GetDlgItem(IDC_STATIC_USER_STATUS)->SetWindowText("premium user login ok.");
		}
		else {
			GetDlgItem(IDC_STATIC_USER_STATUS)->SetWindowText("login fail.");
			txtUserName.SetWindowTextA("");
			txtPassword.SetWindowTextA("");
			return;
		}
		g_premium = ret2;
		g_day_limit = day_limit;
		g_month_limit = month_limit;
			//btnSubLaunch.setEnabled(true)
	}
	else {
		GetDlgItem(IDC_STATIC_USER_STATUS)->SetWindowText("login fail.");
		txtUserName.SetWindowTextA("");
		txtPassword.SetWindowTextA("");
		return;
	}
	show_traffic(day_traffic, month_traffic);
	
	AfxGetApp()->WriteProfileString(_T("UserInfo"), _T("Name"), strUserName);
	AfxGetApp()->WriteProfileString(_T("UserInfo"), _T("Password"), strPassword);
	txtUserName.EnableWindow(false);
	txtPassword.EnableWindow(false);
	btnLogin.SetWindowTextA("Logout");
	return;
}

int CMFCTinyVPNDlg::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CDialogEx::OnCreate(lpCreateStruct) == -1)
		return -1;
	// TODO:  Add your specialized creation code here
	tun_socket_init();
	INFO("OnCreate");

	return 0;
}


void CMFCTinyVPNDlg::OnActivateApp(BOOL bActive, DWORD dwThreadID)
{
	CDialogEx::OnActivateApp(bActive, dwThreadID);

	// TODO: Add your message handler code here
}

DWORD WINAPI start_vpn_thread(LPVOID lpParameter)
{
	uint32_t day_traffic, month_traffic;
	start_vpn((CWnd*)lpParameter, g_strUserName, g_strPassword, g_device_id, g_premium, g_country_code, day_traffic, month_traffic, g_day_limit, g_month_limit);
	return 0;
}
void CMFCTinyVPNDlg::OnBnClickedCheckVpn()
{
	// TODO: Add your control notification handler code here
	int ret = chkVPN.GetCheck();
	if (ret == BST_UNCHECKED) {
		stop_vpn(1);
	}
	else if (ret == BST_CHECKED) {
		chkVPN.SetWindowTextA("Connecting...");
		DWORD dwThreadIDRecv = 0;
		HANDLE hand = CreateThread(NULL, 0, start_vpn_thread, this, 0, &dwThreadIDRecv);//用来处理手法消息的进程
		if (hand == NULL)
		{
			ERROR2("Create work thread failed");
			//getchar();
			return;
		}

		//show_traffic(day_traffic, month_traffic);
	}
}
LRESULT CMFCTinyVPNDlg::OnTrafficMessage(WPARAM wParam, LPARAM lParam)
{
	//UNREFERENCED_PARAMETER(wParam);
	//UNREFERENCED_PARAMETER(lParam);
	// Handle message here.
	uint32_t d = *(uint32_t*)wParam;
	uint32_t m = *(uint32_t*)lParam;
	INFO("recv traffic show message:%d,%d", d,m);
	show_traffic(d,m);
	return 0;
}
LRESULT CMFCTinyVPNDlg::OnConnectedMessage(WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(wParam);
	UNREFERENCED_PARAMETER(lParam);
	chkVPN.SetWindowTextA("VPN ON");
	SetWindowText("TinyVPN(ON)");
	return 0;
}
LRESULT CMFCTinyVPNDlg::OnDisconnectedMessage(WPARAM wParam, LPARAM lParam)
{
	UNREFERENCED_PARAMETER(wParam);
	UNREFERENCED_PARAMETER(lParam);
	chkVPN.SetWindowTextA("VPN OFF");
	SetWindowText("TinyVPN(OFF)");
	chkVPN.SetCheck(BST_UNCHECKED);
	return 0;
}
LRESULT CMFCTinyVPNDlg::OnErrorMessage(WPARAM wParam, LPARAM lParam)
{
	uint32_t id = *(uint32_t*)wParam;
	UNREFERENCED_PARAMETER(lParam);
	INFO("error message:%d", id);
	if (id == 1) {
		MessageBox("please install tap-windows-*.exe.");
		chkVPN.SetWindowTextA("VPN OFF");
		SetWindowText("TinyVPN(OFF-TAP)");
		chkVPN.SetCheck(BST_UNCHECKED);
	}
	return 0;
}