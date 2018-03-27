
// wsniffDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"


// CwsniffDlg 对话框
class CwsniffDlg : public CDialogEx
{
// 构造
public:
	CwsniffDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_WSNIFF_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnCbnSelchangeListInterface();
	afx_msg void OnBnClickedStart();
	CListCtrl List_Control;
	CComboBox List_Interface;
	CButton Btn_Start;
	afx_msg void OnLvnItemchangedPackageList(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnNMClickPackageList(NMHDR *pNMHDR, LRESULT *pResult);
	CTreeCtrl Tree_Ctrl;
};
