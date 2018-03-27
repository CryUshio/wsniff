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
	int count = 0;	//记录设备数
	pcap_if_t *dlist = NULL; //设备链表指针
	pcap_if_t *alldevs = NULL; //所有设备
	char errbuf[PCAP_ERRBUF_SIZE] = {0};
	pcap_t *devHandle = NULL;
	pcap_handler p_handler = NULL;
	HANDLE threadHandle = NULL;
	struct pcap_pkthdr *packetHeader;	//与数据包捕获有关的一个Header
	const u_char *packetData;	//数据包内容的指针
	int isStart = 0;  //开始指示
	int run = 0;  //运行指示
	int pkgCount = 0; //总报文数
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
