
// wsniffDlg.h : ͷ�ļ�
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"


// CwsniffDlg �Ի���
class CwsniffDlg : public CDialogEx
{
// ����
public:
	CwsniffDlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_WSNIFF_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
