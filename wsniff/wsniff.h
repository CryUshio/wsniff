
// wsniff.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������


// CwsniffApp: 
// �йش����ʵ�֣������ wsniff.cpp
//

class CwsniffApp : public CWinApp
{
public:
	CwsniffApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CwsniffApp theApp;