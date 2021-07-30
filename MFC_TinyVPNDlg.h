
// MFC_TinyVPNDlg.h : header file
//

#pragma once
#include <stdint.h>

// CMFCTinyVPNDlg dialog
class CMFCTinyVPNDlg : public CDialogEx
{
// Construction
public:
	CMFCTinyVPNDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MFC_TINYVPN_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButtonLogin();
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
	afx_msg LRESULT OnTrafficMessage(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnConnectedMessage(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnDisconnectedMessage(WPARAM wParam, LPARAM lParam);
	afx_msg LRESULT OnErrorMessage(WPARAM wParam, LPARAM lParam);
	CEdit txtUserName;
	CEdit txtPassword;
	CButton btnLogin;

	int show_traffic(uint32_t d, uint32_t m);

	afx_msg void OnActivateApp(BOOL bActive, DWORD dwThreadID);
	afx_msg void OnBnClickedCheckVpn();
	CButton chkVPN;
};
