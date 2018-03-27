
// wsniffDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "wsniff.h"
#include "wsniffDlg.h"
#include "fns.h"
#include "log.h"
#include "Protocols.h"
#include <pcap.h>
#include <iostream>
#include <conio.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


/*************  �Զ��幦��  *************/
Fns fn;
/***********  �Զ��幦�� END  ***********/




// ����Ӧ�ó��򡰹��ڡ��˵���� CAboutDlg �Ի���

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

// ʵ��
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


// CwsniffDlg �Ի���



CwsniffDlg::CwsniffDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_WSNIFF_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CwsniffDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_PACKAGE_LIST, List_Control);
	DDX_Control(pDX, IDC_LIST_INTERFACE, List_Interface);
	DDX_Control(pDX, IDC_START, Btn_Start);
	DDX_Control(pDX, IDC_TREE, Tree_Ctrl);
}

BEGIN_MESSAGE_MAP(CwsniffDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_CBN_SELCHANGE(IDC_LIST_INTERFACE, &CwsniffDlg::OnCbnSelchangeListInterface)
	ON_BN_CLICKED(IDC_START, &CwsniffDlg::OnBnClickedStart)
	ON_NOTIFY(NM_CLICK, IDC_PACKAGE_LIST, &CwsniffDlg::OnNMClickPackageList)
END_MESSAGE_MAP()


// CwsniffDlg ��Ϣ�������

BOOL CwsniffDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// ��������...���˵�����ӵ�ϵͳ�˵��С�

	// IDM_ABOUTBOX ������ϵͳ���Χ�ڡ�
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

	// ���ô˶Ի����ͼ�ꡣ  ��Ӧ�ó��������ڲ��ǶԻ���ʱ����ܽ��Զ�
	//  ִ�д˲���
	SetIcon(m_hIcon, TRUE);			// ���ô�ͼ��
	SetIcon(m_hIcon, FALSE);		// ����Сͼ��

	// TODO: �ڴ���Ӷ���ĳ�ʼ������
	List_Control.SetExtendedStyle(LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
	List_Control.InsertColumn(0, L"No.", LVCFMT_CENTER, 60);
	List_Control.InsertColumn(1, L"Source", LVCFMT_CENTER, 120);
	List_Control.InsertColumn(2, L"Destination", LVCFMT_CENTER, 120);
	List_Control.InsertColumn(3, L"Protocol", LVCFMT_CENTER, 100);
	List_Control.InsertColumn(4, L"Len", LVCFMT_CENTER, 80);
	List_Control.InsertColumn(5, L"Source Port", LVCFMT_CENTER, 120);
	List_Control.InsertColumn(6, L"Destination Port", LVCFMT_CENTER, 120);

	//AllocConsole();
	getTimestamp();
	fn.getDevList();
	CString cs;
	CComboBox* ccomb = (CComboBox*)GetDlgItem(IDC_LIST_INTERFACE);
	while (fn.dlist)
	{
		CString cs(fn.dlist->description);
		ccomb->AddString(cs);
		fn.dlist = fn.dlist->next;
	}
	

	CButton*  cstart = (CButton*)GetDlgItem(IDC_START);
	CListCtrl* clist = (CListCtrl*)GetDlgItem(IDC_PACKAGE_LIST);
	CTreeCtrl* ctree = (CTreeCtrl*)GetDlgItem(IDC_TREE);
	fn.u = (UI*)malloc(sizeof(UI));
	fn.u->cstart = cstart;
	fn.u->clist  = clist;
	fn.u->ctree  = ctree;

	return TRUE;  // ���ǽ��������õ��ؼ������򷵻� TRUE
}


void CwsniffDlg::OnSysCommand(UINT nID, LPARAM lParam)
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

// �����Ի��������С����ť������Ҫ����Ĵ���
//  �����Ƹ�ͼ�ꡣ  ����ʹ���ĵ�/��ͼģ�͵� MFC Ӧ�ó���
//  �⽫�ɿ���Զ���ɡ�

void CwsniffDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // ���ڻ��Ƶ��豸������

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// ʹͼ���ڹ����������о���
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// ����ͼ��
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//���û��϶���С������ʱϵͳ���ô˺���ȡ�ù��
//��ʾ��
HCURSOR CwsniffDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CwsniffDlg::OnCbnSelchangeListInterface() //�ӿ��б�
{
	TRACE("\n%d\n", List_Interface.GetCurSel());
}

void CwsniffDlg::OnBnClickedStart()  //��ʼ��ť
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	

	if (fn.run == 0)
	{
		
		int index = List_Interface.GetCurSel();
		if (index == -1)
		{
			AfxMessageBox(L"Please choose a Interface.");
			return;
		}
		if (fn.isStart == 0)
		{
			fn.isStart = 1;
			if (int res = fn.openInterface(index) != 0) //�򿪽ӿ�
			{
				if (res == -1)
				{
					AfxMessageBox(L"Can't open the Interface.");
					return;
				}
				if (res == -2)
				{
					AfxMessageBox(L"Can't open a not-Ethernet Interface.");
					return;
				}
			}
		}
		fn.run = 1;
		fn.startCap();
		Btn_Start.SetWindowTextW(L"ֹͣ");
		
	}
	else
	{
		fn.stopCap();
		Btn_Start.SetWindowTextW(L"��ʼ");
	}

}


void CwsniffDlg::OnNMClickPackageList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������

	int nId;
	//���ȵõ������λ��
	POSITION pos = List_Control.GetFirstSelectedItemPosition();
	if (pos == NULL)
		return;
	//�õ��кţ�ͨ��POSITIONת��
	nId = (int)List_Control.GetNextSelectedItem(pos);
	TRACE("fn.d_pkt[%d]->src: %s\n", nId, fn.d_pkt[nId]->src);

	fn.insertTree(nId);
}
