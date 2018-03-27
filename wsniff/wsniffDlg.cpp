
// wsniffDlg.cpp : 实现文件
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


/*************  自定义功能  *************/
Fns fn;
/***********  自定义功能 END  ***********/




// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
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


// CwsniffDlg 对话框



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


// CwsniffDlg 消息处理程序

BOOL CwsniffDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
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

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
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

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
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

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CwsniffDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CwsniffDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


void CwsniffDlg::OnCbnSelchangeListInterface() //接口列表
{
	TRACE("\n%d\n", List_Interface.GetCurSel());
}

void CwsniffDlg::OnBnClickedStart()  //开始按钮
{
	// TODO: 在此添加控件通知处理程序代码
	

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
			if (int res = fn.openInterface(index) != 0) //打开接口
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
		Btn_Start.SetWindowTextW(L"停止");
		
	}
	else
	{
		fn.stopCap();
		Btn_Start.SetWindowTextW(L"开始");
	}

}


void CwsniffDlg::OnNMClickPackageList(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: 在此添加控件通知处理程序代码

	int nId;
	//首先得到点击的位置
	POSITION pos = List_Control.GetFirstSelectedItemPosition();
	if (pos == NULL)
		return;
	//得到行号，通过POSITION转化
	nId = (int)List_Control.GetNextSelectedItem(pos);
	TRACE("fn.d_pkt[%d]->src: %s\n", nId, fn.d_pkt[nId]->src);

	fn.insertTree(nId);
}
