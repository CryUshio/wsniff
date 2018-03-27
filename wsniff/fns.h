#ifndef FNS_H  
#define FNS_H

#include "stdafx.h"
#include "Protocols.h"
#include <pcap.h>

struct UI
{
	CButton*  cstart;
	CListCtrl* clist;
	CTreeCtrl* ctree;
};

class Fns
{
public:
	int count = 0;	//��¼�豸��
	pcap_if_t *dlist = NULL; //�豸����ָ��
	pcap_if_t *alldevs = NULL; //�����豸
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_t *devHandle = NULL;
	pcap_handler p_handler = NULL;
	HANDLE threadHandle = NULL;
	struct pcap_pkthdr *packetHeader;	//�����ݰ������йص�һ��Header
	const u_char *packetData;	//���ݰ����ݵ�ָ��
	int isStart = 0;  //��ʼָʾ
	int run = 0;  //����ָʾ
	int pkgCount = 0; //�ܱ�����
	DATA_PKT* d_pkt[5000];
	UI *u;
public:
	Fns() {};
	int getDevList();
	int openInterface(int index);
	int startCap();
	int stopCap();
	int insertTree(int index);
	void expandTree(HTREEITEM child);
};
#endif //FNS_H
