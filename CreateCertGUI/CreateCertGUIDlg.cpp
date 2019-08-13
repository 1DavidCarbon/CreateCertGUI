
// CreateCertGUIDlg.cpp : implementation file
//

#include "stdafx.h"
#include "CreateCertGUI.h"
#include "CreateCertGUIDlg.h"
#include "afxdialogex.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

BIGNUM *oBIGNUM = NULL;
EVP_PKEY *oEVP_PKEY = NULL;
X509 *oX509 = NULL;
STACK_OF(X509) *oSTACK_X509 = NULL;
PKCS12 *oPKCS12 = NULL;

// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CCreateCertGUIDlg dialog



CCreateCertGUIDlg::CCreateCertGUIDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(CCreateCertGUIDlg::IDD, pParent)
	, m_edit_years(0)
	, m_edit_common_name(_T(""))
	, m_edit_country(_T(""))
	, m_edit_organization(_T(""))
	, m_edit_password(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CCreateCertGUIDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_YEARS, m_edit_years);
	DDV_MinMaxInt(pDX, m_edit_years, 1, 10);
	DDX_Text(pDX, IDC_EDIT_COMMON_NAME, m_edit_common_name);
	DDV_MaxChars(pDX, m_edit_common_name, 1000);
	DDX_Text(pDX, IDC_EDIT_COUNTRY, m_edit_country);
	DDV_MaxChars(pDX, m_edit_country, 2);
	DDX_Text(pDX, IDC_EDIT_ORGANIZATION, m_edit_organization);
	DDV_MaxChars(pDX, m_edit_organization, 1000);
	DDX_Text(pDX, IDC_EDIT_PASSWORD, m_edit_password);
}

BEGIN_MESSAGE_MAP(CCreateCertGUIDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_GENERATE, &CCreateCertGUIDlg::OnBnClickedGenerate)
END_MESSAGE_MAP()


// CCreateCertGUIDlg message handlers

BOOL CCreateCertGUIDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
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
	m_edit_years = 1;
	m_edit_country = "BE";
	m_edit_organization = "Example";
	m_edit_common_name = "example.com";
	m_edit_password = "";
	UpdateData(FALSE);

	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CCreateCertGUIDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

void CCreateCertGUIDlg::OnPaint()
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
HCURSOR CCreateCertGUIDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

void CCreateCertGUIDlg::CreateCert()
{
	const int kBits = 4096;

	RSA *oRSA = NULL;
	X509_NAME *name = NULL;
	char szFilenameCert[MAX_COMPUTERNAME_LENGTH + 256];
	char szFilenameKey[MAX_COMPUTERNAME_LENGTH + 256];
	char szFilenamePKCS12[MAX_COMPUTERNAME_LENGTH + 256];
	SYSTEMTIME sST;

	if (!UpdateData())
		return;
	CT2A szCountry(m_edit_country);
	CT2A szOrganization(m_edit_organization);
	CT2A szCommonName(m_edit_common_name);
	CT2A szPassword(m_edit_password);

	GetLocalTime(&sST);
	sprintf_s(szFilenameCert, "cert-%04d%02d%02d-%02d%02d%02d.crt", sST.wYear, sST.wMonth, sST.wDay, sST.wHour, sST.wMinute, sST.wSecond);
	sprintf_s(szFilenameKey, "key-%04d%02d%02d-%02d%02d%02d.pem", sST.wYear, sST.wMonth, sST.wDay, sST.wHour, sST.wMinute, sST.wSecond);
	sprintf_s(szFilenamePKCS12, "cert-key-%04d%02d%02d-%02d%02d%02d.p12", sST.wYear, sST.wMonth, sST.wDay, sST.wHour, sST.wMinute, sST.wSecond);

	OpenSSL_add_all_algorithms(); // Necessary for PKCS12_create

	oBIGNUM = BN_new();
	if (NULL == oBIGNUM)
	{
		MessageBox(TEXT("An error occurred: 1"), TEXT("CreateCertGUI"), 0);
		return;
	}
	oRSA = RSA_new();
	if (NULL == oRSA)
	{
		MessageBox(TEXT("An error occurred: 2"), TEXT("CreateCertGUI"), 0);
		return;
	}
	oEVP_PKEY = EVP_PKEY_new();
	if (NULL == oEVP_PKEY)
	{
		MessageBox(TEXT("An error occurred: 3"), TEXT("CreateCertGUI"), 0);
		return;
	}
	oX509 = X509_new();
	if (NULL == oX509)
	{
		MessageBox(TEXT("An error occurred: 4"), TEXT("CreateCertGUI"), 0);
		return;
	}

	BeginWaitCursor();

	// http://openssl.6102.n7.nabble.com/Use-Rand-Seed-on-windows-td13403.html
	if (0 == BN_set_word(oBIGNUM, RSA_F4))
	{
		MessageBox(TEXT("An error occurred: 5"), TEXT("CreateCertGUI"), 0);
		return;
	}
	if (0 == RSA_generate_key_ex(oRSA, kBits, oBIGNUM, NULL))
	{
		MessageBox(TEXT("An error occurred: 6"), TEXT("CreateCertGUI"), 0);
		return;
	}
	if (0 == EVP_PKEY_assign_RSA(oEVP_PKEY, oRSA))
	{
		MessageBox(TEXT("An error occurred: 7"), TEXT("CreateCertGUI"), 0);
		return;
	}
	if (0 == ASN1_INTEGER_set(X509_get_serialNumber(oX509), 1))
	{
		MessageBox(TEXT("An error occurred: 8"), TEXT("CreateCertGUI"), 0);
		return;
	}
	if (NULL == X509_gmtime_adj(X509_get_notBefore(oX509), 0))
	{
		MessageBox(TEXT("An error occurred: 9"), TEXT("CreateCertGUI"), 0);
		return;
	}
	if (NULL == X509_gmtime_adj(X509_get_notAfter(oX509), m_edit_years * 365 * 24 * 60 * 60))
	{
		MessageBox(TEXT("An error occurred: 10"), TEXT("CreateCertGUI"), 0);
		return;
	}
	if (0 == X509_set_pubkey(oX509, oEVP_PKEY))
	{
		MessageBox(TEXT("An error occurred: 11"), TEXT("CreateCertGUI"), 0);
		return;
	}
	name = X509_get_subject_name(oX509);
	if (NULL == name)
	{
		MessageBox(TEXT("An error occurred: 12"), TEXT("CreateCertGUI"), 0);
		return;
	}
	if (0 == X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *)szCountry.m_psz, -1, -1, 0))
	{
		MessageBox(TEXT("An error occurred when setting Country: 13"), TEXT("CreateCertGUI"), 0);
		return;
	}
	if (0 == X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *)szOrganization.m_psz, -1, -1, 0))
	{
		MessageBox(TEXT("An error occurred when setting Organization: 14"), TEXT("CreateCertGUI"), 0);
		return;
	}
	if (0 == X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *)szCommonName.m_psz, -1, -1, 0))
	{
		MessageBox(TEXT("An error occurred when setting Common Name: 15"), TEXT("CreateCertGUI"), 0);
		return;
	}
	if (0 == X509_set_issuer_name(oX509, name))
	{
		MessageBox(TEXT("An error occurred: 16"), TEXT("CreateCertGUI"), 0);
		return;
	}
	if (0 == X509_sign(oX509, oEVP_PKEY, EVP_sha256()))
	{
		MessageBox(TEXT("An error occurred: 17"), TEXT("CreateCertGUI"), 0);
		return;
	}

	oSTACK_X509 = sk_X509_new_null();
	if (NULL == oSTACK_X509)
	{
		MessageBox(TEXT("An error occurred: 18"), TEXT("CreateCertGUI"), 0);
		return;
	}
	if (0 == sk_X509_push(oSTACK_X509, oX509))
	{
		MessageBox(TEXT("An error occurred: 19"), TEXT("CreateCertGUI"), 0);
		return;
	}
	oPKCS12 = PKCS12_create(szPassword.m_psz, szCommonName.m_psz, oEVP_PKEY, oX509, oSTACK_X509, 0, 0, 0, 0, 0);
	if (NULL == oPKCS12)
	{
		MessageBox(TEXT("An error occurred: 20"), TEXT("CreateCertGUI"), 0);
		return;
	}

	FILE * f;
	if (0 == fopen_s(&f, szFilenameCert, "wb"))
	{
		if (0 == PEM_write_X509(f, oX509))
		{
			MessageBox(TEXT("Error writing cert file"), TEXT("CreateCertGUI"), 0);
		}
		fclose(f);
	}
	else
	{
		MessageBox(TEXT("Error opening cert file"), TEXT("CreateCertGUI"), 0);
	}
	if (0 == fopen_s(&f, szFilenameKey, "wb"))
	{
		if (0 == PEM_write_PrivateKey(f, oEVP_PKEY, NULL, NULL, 0, NULL, NULL))
		{
			MessageBox(TEXT("Error writing key file"), TEXT("CreateCertGUI"), 0);
		}
		fclose(f);
	}
	else
	{
		MessageBox(TEXT("Error opening key file"), TEXT("CreateCertGUI"), 0);
	}
	if (0 == fopen_s(&f, szFilenamePKCS12, "wb"))
	{
		if (0 == i2d_PKCS12_fp(f, oPKCS12))
		{
			MessageBox(TEXT("Error writing PKCS12 file"), TEXT("CreateCertGUI"), 0);
		}
		fclose(f);
	}
	else
	{
		MessageBox(TEXT("Error opening PKCS12 file"), TEXT("CreateCertGUI"), 0);
	}

	EndWaitCursor();

	MessageBox(TEXT("Files generated!"), TEXT("CreateCertGUI"), 0);
}

void CCreateCertGUIDlg::OnBnClickedGenerate()
{
	/*
	http://stackoverflow.com/questions/11383942/how-to-use-openssl-with-visual-studio
	http://stackoverflow.com/questions/5927164/how-to-generate-rsa-private-key-using-openssl
	http://stackoverflow.com/questions/30672804/is-it-possible-to-statically-link-libcurl-libeay32-and-ssleay32
	http://stackoverflow.com/questions/256405/programmatically-create-x509-certificate-using-openssl
	http://fm4dd.com/openssl/pkcs12test.htm
	*/

	CreateCert();

	if (NULL != oBIGNUM)
	{
		BN_free(oBIGNUM);
		oBIGNUM = NULL;
	}
	if (NULL != oEVP_PKEY)
	{
		EVP_PKEY_free(oEVP_PKEY);
		oEVP_PKEY = NULL;
	}
	if (NULL != oX509)
	{
		X509_free(oX509);
		oX509 = NULL;
	}
	if (NULL != oSTACK_X509)
	{
		sk_X509_free(oSTACK_X509);
		oSTACK_X509 = NULL;
	}
	if (NULL != oPKCS12)
	{
		PKCS12_free(oPKCS12);
		oPKCS12 = NULL;
	}
}
