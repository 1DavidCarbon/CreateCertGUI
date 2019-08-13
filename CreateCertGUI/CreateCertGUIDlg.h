
// CreateCertGUIDlg.h : header file
//

#pragma once


// CCreateCertGUIDlg dialog
class CCreateCertGUIDlg : public CDialogEx
{
// Construction
public:
	CCreateCertGUIDlg(CWnd* pParent = NULL);	// standard constructor

// Dialog Data
	enum { IDD = IDD_CREATECERTGUI_DIALOG };

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
	int m_edit_years;
	CString m_edit_common_name;
	CString m_edit_country;
	CString m_edit_organization;
	afx_msg void OnBnClickedGenerate();
	void CreateCert();
	CString m_edit_password;
};
