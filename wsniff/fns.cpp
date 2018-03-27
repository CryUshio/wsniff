#include "fns.h"
#include "log.h"
#include "stdafx.h"
#include "Protocols.h"
#include <pcap.h>
#include <iostream>
#include <conio.h>

void struct_init(Fns *fn, int type);
int Fns::getDevList()
{
	std::wcout.imbue(std::locale("chs"));

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		LOG_ERROR("Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}
	for (dlist = alldevs; dlist; dlist = dlist->next)
	{
		LOG_INFO("%d. %s", ++count, dlist->name);
		if (dlist->description)
			LOG_INFO("(%s)\n", dlist->description);
		else
			LOG_INFO("No description available\n");
	}
	if (count == 0)
	{
		LOG_INFO("No interfaces found! Make sure WinPcap is installed.\n");
		return -2;
	}
	dlist = alldevs; //回头部
	return 0;
}

int Fns::openInterface(int index)
{
	//跳转到所选设备
	int i;
	for (dlist = alldevs, i = 0; i< index; dlist = dlist->next, i++);


	if ((devHandle = pcap_open_live(dlist->name,  // 设备名  
		65536,     //捕获数据包长度  
		1, // 混杂模式 (非0意味着是混杂模式)  
		1000,     // 读超时设置  
		errbuf    // 错误信息  
	)) == NULL)
	{
		LOG_ERROR("Can't open the Interface: %s\n", dlist->description);
		pcap_freealldevs(alldevs);
		return -1;
	}
	if (pcap_datalink(devHandle) != DLT_EN10MB)
	{
		LOG_ERROR("Can't open a not-Ethernet Interface: %s\n", dlist->description);
		pcap_freealldevs(alldevs);
		return -2;
	}
	LOG_INFO("Listening on %s...", dlist->description);
	pcap_freealldevs(alldevs); // At this point, we don't need any more the device list. Free it 

							   /*dumpfile = pcap_dump_open(devHandle, "../save/cap.txt");
							   if (dumpfile == NULL)
							   {
							   LOG_ERROR("File create error.\n");
							   return -1;
							   }*/

	return 0;
}

void onCap(void* fnd);
int Fns::startCap()
{
	if (isStart == 1)
	{
		run = 1;
		LOG_INFO("Continue capture packets.");
	}
	threadHandle = (HANDLE)_beginthread(onCap, 0, (void*)this);
	if (threadHandle == NULL)
	{
		LOG_ERROR("Create thread error, code: %d.", GetLastError());
		return -1;
	}
	return 0;
}

int UIThread(Fns* fn);
void IP_analysis(ETH_HEAD* ethHdr, Fns *fn);
void onCap(void* fnx)
{
	Fns *fn = (Fns*) fnx;
	_cprintf("Fns *fn->dlist: %s", fn->dlist->description);
	LOG_INFO_LINE("==========================");
	LOG_INFO     ("=     start capture.     =");
	LOG_INFO     ("==========================");

	int ret;
	UIThread(fn);
	while (fn->run == 1 && (ret = pcap_next_ex(fn->devHandle, &fn->packetHeader, &fn->packetData)) >= 0) {		//开始抓包,pcap_dispatch(...)阻塞,pcap_loop(...)非阻塞
		if (ret == 0)
			continue;
		if (ret == -1) {
			LOG_ERROR_LINE("Error reading the packet:%s\n", pcap_geterr(fn->devHandle));
			continue;
		}
		if (fn->pkgCount == 1000)
		{
			LOG_WRAN_LINE("The maximum number of packets captured have reached.");
			return;
		}
		
		struct_init(fn, 0);

		LOG_INFO_LINE("Captured no.%d package.", fn->pkgCount);
		LOG_INFO("length of packet: %d", fn->packetHeader->len);
		sprintf(fn->d_pkt[fn->pkgCount]->len, "%d", fn->packetHeader->len);

		// 以太网帧
		ETH_HEAD* ethHdr = (ETH_HEAD*)fn->packetData;
		sprintf(fn->d_pkt[fn->pkgCount]->src, "%02x-%02x-%02x-%02x-%02x-%02x", ethHdr->src[0], ethHdr->src[1], ethHdr->src[2], ethHdr->src[3], ethHdr->src[4], ethHdr->src[5]);
		sprintf(fn->d_pkt[fn->pkgCount]->des, "%02x-%02x-%02x-%02x-%02x-%02x", ethHdr->des[0], ethHdr->des[1], ethHdr->des[2], ethHdr->des[3], ethHdr->des[4], ethHdr->des[5]);
		LOG_INFO("Source mac     : %02x-%02x-%02x-%02x-%02x-%02x", ethHdr->src[0], ethHdr->src[1], ethHdr->src[2], ethHdr->src[3], ethHdr->src[4], ethHdr->src[5]);
		LOG_INFO("Destination mac: %02x-%02x-%02x-%02x-%02x-%02x", ethHdr->des[0], ethHdr->des[1], ethHdr->des[2], ethHdr->des[3], ethHdr->des[4], ethHdr->des[5]);
		LOG_INFO("Protocol: 0x%04x", htons(ethHdr->type));

		
		if (0x0800 == htons(ethHdr->type))	// IP 数据包
		{
			struct_init(fn, 1);
			sprintf(fn->d_pkt[fn->pkgCount]->type, "IP");
			IP_analysis(ethHdr, fn);
		}
		else if (0x86dd == htons(ethHdr->type))	// IPv6 数据包
		{
			sprintf(fn->d_pkt[fn->pkgCount]->type, "IPv6");
			sprintf(fn->d_pkt[fn->pkgCount]->toptype, "IPv6");
			LOG_INFO("IPv6 data packet");
		}
		else if (0x0806 == htons(ethHdr->type))	// ARP 数据包
		{
			sprintf(fn->d_pkt[fn->pkgCount]->type, "ARP");
			sprintf(fn->d_pkt[fn->pkgCount]->toptype, "ARP");
			LOG_INFO("ARP data packet");
		}
		else {
			sprintf(fn->d_pkt[fn->pkgCount]->type, "其他");
			sprintf(fn->d_pkt[fn->pkgCount]->toptype, "其他");
		}
		fn->pkgCount++;
	}

	LOG_INFO_LINE("Capture end.");
	return;
}

int Fns::stopCap()
{
	run = 0;
	u->cstart->SetWindowTextW(L"开始");
	LOG_INFO("Pause the Interface success.");
	/*pkgCount = 0;
	pcap_close(devHandle);
	devHandle = NULL;
	LOG_INFO("Close the Interface success.");*/
	Sleep(1000);
	getTimestamp();
	return 0;
}

void ICMP_analysis(IP_HEAD* ipHdr, Fns *fn);
void TCP_analysis(IP_HEAD* ipHdr, Fns *fn);
void UDP_analysis(IP_HEAD* ipHdr, Fns *fn);
void IP_analysis(ETH_HEAD* ethHdr, Fns *fn)
{
	LOG_INFO("");
	LOG_INFO("Packet Type: IP");
	IP_HEAD *ipHdr = (IP_HEAD *)((char *)ethHdr + sizeof(eth_hdr));
	/*if ((ipHdr->Version >> 4) == 4)
		LOG_INFO("版本号: IPv4");
	else
	{
		LOG_INFO("版本号: IPv6");
		return;
	}*/

	LOG_INFO("首部长度：%d", (ipHdr->HeadLen & 0x0f) << 2);
	LOG_INFO("服务类型：%02x", ipHdr->ServiceType);
	LOG_INFO("总长度：%d", ntohs(ipHdr->TotalLen));
	LOG_INFO("标识：0x%04x", ntohs(ipHdr->Identifier));
	LOG_INFO("标志：0x%02x", (ipHdr->Flags >> 13) & 0x07);
	LOG_INFO("片偏移：%d", ipHdr->FragOffset);
	LOG_INFO("TTL：%d", ipHdr->TTL);
	LOG_INFO("上层协议标识：%d", ipHdr->Protocol);
	LOG_INFO("首部校验和：0x%04x", ntohs(ipHdr->HeadChecksum));
	LOG_INFO("源IP地址  ：%s", inet_ntoa(*(in_addr*)&ipHdr->SourceAddr));
	LOG_INFO("目的IP地址：%s", inet_ntoa(*(in_addr*)&ipHdr->DestinAddr));

	sprintf(fn->d_pkt[fn->pkgCount]->iph.Version, "IPv4");
	sprintf(fn->d_pkt[fn->pkgCount]->iph.HeadLen, "%d", (ipHdr->HeadLen & 0x0f) << 2);
	sprintf(fn->d_pkt[fn->pkgCount]->iph.ServiceType, "%02x", ipHdr->ServiceType);
	sprintf(fn->d_pkt[fn->pkgCount]->iph.TotalLen, "%d", ntohs(ipHdr->TotalLen));
	sprintf(fn->d_pkt[fn->pkgCount]->iph.Identifier, "0x%04x", ntohs(ipHdr->Identifier));
	sprintf(fn->d_pkt[fn->pkgCount]->iph.Flags, "0x%02x", (ipHdr->Flags >> 13) & 0x07);
	sprintf(fn->d_pkt[fn->pkgCount]->iph.FragOffset, "%d", ipHdr->FragOffset);
	sprintf(fn->d_pkt[fn->pkgCount]->iph.TTL, "%d", ipHdr->TTL);
	sprintf(fn->d_pkt[fn->pkgCount]->iph.Protocol, "%d", ipHdr->Protocol);
	sprintf(fn->d_pkt[fn->pkgCount]->iph.HeadChecksum, "0x%04x", ntohs(ipHdr->HeadChecksum));

	//char* saddr = inet_ntoa(*(in_addr*)&ipHdr->SourceAddr);
	//char* daddr = inet_ntoa(*(in_addr*)&ipHdr->DestinAddr);
	sprintf(fn->d_pkt[fn->pkgCount]->iph.SourceAddr, "%s", inet_ntoa(*(in_addr*)&ipHdr->SourceAddr));
	sprintf(fn->d_pkt[fn->pkgCount]->iph.DestinAddr, "%s", inet_ntoa(*(in_addr*)&ipHdr->DestinAddr));
	

	switch (ipHdr->Protocol)
	{
	case 1: //ICMP
		struct_init(fn, 2);
		ICMP_analysis(ipHdr, fn);
		break;
	case 6: //TCP
		struct_init(fn, 3);
		TCP_analysis(ipHdr, fn);
		break;
	case 17: //UDP
		struct_init(fn, 4);
		UDP_analysis(ipHdr, fn);
		break;
	default:
		sprintf(fn->d_pkt[fn->pkgCount]->type, "IP");
		sprintf(fn->d_pkt[fn->pkgCount]->toptype, "IP");
		break;
	}
	
}

void ICMP_analysis(IP_HEAD* ipHdr, Fns *fn)
{
	LOG_INFO("");
	LOG_INFO("Packet Type: ICMP");
	ICMP_HEAD *icmpHdr = (ICMP_HEAD *)((char *)ipHdr + ((ipHdr->HeadLen & 0x0f) << 2));
	LOG_INFO("类型：%d", icmpHdr->type);
	LOG_INFO("代码：%d", icmpHdr->code);
	LOG_INFO("校验和：0x%04x", icmpHdr->chksum);
	LOG_INFO("首部其他部分：%d", icmpHdr->seq);

	sprintf(fn->d_pkt[fn->pkgCount]->toptype, "ICMP");
	sprintf(fn->d_pkt[fn->pkgCount]->icmph.type, "%d", icmpHdr->type);
	sprintf(fn->d_pkt[fn->pkgCount]->icmph.code, "%d", icmpHdr->code);
	sprintf(fn->d_pkt[fn->pkgCount]->icmph.chksum, "0x%04x", icmpHdr->chksum);
	sprintf(fn->d_pkt[fn->pkgCount]->icmph.seq, "%d", icmpHdr->seq);
}

void HTTP_analysis(TCP_HEAD *tcpHdr, IP_HEAD *ipHdr, Fns *fn);
void POP3_analysis(TCP_HEAD *tcpHdr, IP_HEAD *ipHdr, Fns *fn);
void TCP_analysis(IP_HEAD* ipHdr, Fns *fn)
{
	LOG_INFO("");
	LOG_INFO("Packet Type: TCP");
	TCP_HEAD *tcpHdr = (TCP_HEAD *)((char *)ipHdr + ((ipHdr->HeadLen & 0x0f) << 2));

	LOG_INFO("源端口号  ：%d", htons(tcpHdr->sport));
	LOG_INFO("目的端口号：%d", htons(tcpHdr->dport));
	LOG_INFO("序列号：%d", htons(tcpHdr->seq));
	LOG_INFO("确认号：%d", htons(tcpHdr->ack_seq));
	LOG_INFO("首部长度：%d", (tcpHdr->res & 0xf) * 4);
	LOG_INFO("标志：");
	LOG_INFO("   URG：%d", (tcpHdr->flags & 0x20) == 0 ? 0 : 1);
	LOG_INFO("   ACK：%d", (tcpHdr->flags & 0x10) == 0 ? 0 : 1);
	LOG_INFO("   PSH：%d", (tcpHdr->flags & 0x08) == 0 ? 0 : 1);
	LOG_INFO("   RST：%d", (tcpHdr->flags & 0x04) == 0 ? 0 : 1);
	LOG_INFO("   SYN：%d", (tcpHdr->flags & 0x02) == 0 ? 0 : 1);
	LOG_INFO("   FIN：%d", (tcpHdr->flags & 0x01) == 0 ? 0 : 1);
	LOG_INFO("窗口大小：%d", htons(tcpHdr->window));
	LOG_INFO("校验和：0x%x", htons(tcpHdr->check));
	LOG_INFO("紧急指针：%d", htons(tcpHdr->urg_ptr));

	sprintf(fn->d_pkt[fn->pkgCount]->tcph.sport, "%d", htons(tcpHdr->sport));
	sprintf(fn->d_pkt[fn->pkgCount]->tcph.dport, "%d", htons(tcpHdr->dport));
	sprintf(fn->d_pkt[fn->pkgCount]->tcph.seq, "%d", htons(tcpHdr->seq));
	sprintf(fn->d_pkt[fn->pkgCount]->tcph.ack_seq, "%d", htons(tcpHdr->ack_seq));
	sprintf(fn->d_pkt[fn->pkgCount]->tcph.res, "%d", (tcpHdr->res & 0xf) * 4);
	sprintf(fn->d_pkt[fn->pkgCount]->tcph.flags, "0x%x", tcpHdr->flags);
		sprintf(fn->d_pkt[fn->pkgCount]->tcph.URG, "%d", (tcpHdr->flags & 0x20) == 0 ? 0 : 1);
		sprintf(fn->d_pkt[fn->pkgCount]->tcph.ACK, "%d", (tcpHdr->flags & 0x10) == 0 ? 0 : 1);
		sprintf(fn->d_pkt[fn->pkgCount]->tcph.PSH, "%d", (tcpHdr->flags & 0x08) == 0 ? 0 : 1);
		sprintf(fn->d_pkt[fn->pkgCount]->tcph.RST, "%d", (tcpHdr->flags & 0x04) == 0 ? 0 : 1);
		sprintf(fn->d_pkt[fn->pkgCount]->tcph.SYN, "%d", (tcpHdr->flags & 0x02) == 0 ? 0 : 1);
		sprintf(fn->d_pkt[fn->pkgCount]->tcph.FIN, "%d", (tcpHdr->flags & 0x01) == 0 ? 0 : 1);
	sprintf(fn->d_pkt[fn->pkgCount]->tcph.window, "%d", htons(tcpHdr->window));
	sprintf(fn->d_pkt[fn->pkgCount]->tcph.check, "0x%x", htons(tcpHdr->check));
	sprintf(fn->d_pkt[fn->pkgCount]->tcph.urg_ptr, "%d", htons(tcpHdr->urg_ptr));
	sprintf(fn->d_pkt[fn->pkgCount]->tcph.opt, "0x%x", htons(tcpHdr->opt));

	if (htons(tcpHdr->sport) == 80 || htons(tcpHdr->dport) == 80)
	{
		struct_init(fn, 6);
		HTTP_analysis(tcpHdr, ipHdr, fn);
	}
	else if (htons(tcpHdr->sport) == 110 || htons(tcpHdr->dport) == 110)
	{
		struct_init(fn, 7);
		POP3_analysis(tcpHdr, ipHdr, fn);
	}
	else
	{
		sprintf(fn->d_pkt[fn->pkgCount]->toptype, "TCP");
	}
}

void DNS_analysis(UDP_HEAD *udpHdr, Fns *fn);
void UDP_analysis(IP_HEAD* ipHdr, Fns *fn)
{
	LOG_INFO("");
	LOG_INFO("Packet Type: UDP");
	UDP_HEAD *udpHdr = (UDP_HEAD *)((char *)ipHdr + ((ipHdr->HeadLen & 0x0f) << 2));
	LOG_INFO("源端口号    ：%d", ntohs(udpHdr->sport));
	LOG_INFO("目的源端口号：%d", ntohs(udpHdr->dport));
	LOG_INFO("数据报总长度：%d", ntohs(udpHdr->len));
	LOG_INFO("校验和：0x%0x", ntohs(udpHdr->check));

	sprintf(fn->d_pkt[fn->pkgCount]->toptype, "UDP");
	sprintf(fn->d_pkt[fn->pkgCount]->udph.sport, "%d", ntohs(udpHdr->sport));
	sprintf(fn->d_pkt[fn->pkgCount]->udph.dport, "%d", ntohs(udpHdr->dport));
	sprintf(fn->d_pkt[fn->pkgCount]->udph.len, "%d", ntohs(udpHdr->len));
	sprintf(fn->d_pkt[fn->pkgCount]->udph.check, "0x%0x", ntohs(udpHdr->check));

	if (ntohs(udpHdr->dport) == 53 || ntohs(udpHdr->sport) == 53)
	{
		struct_init(fn, 5);
		DNS_analysis(udpHdr, fn);
	}
}

void DNS_analysis(UDP_HEAD *udpHdr, Fns *fn)
{
	LOG_INFO("");
	LOG_INFO("Packet Type: DNS");
	DNS_HEAD *dnsHdr = (DNS_HEAD *)((char *)udpHdr + sizeof(UDP_HEAD));
	LOG_INFO("标识：0x%04x", ntohs(dnsHdr->id));
	LOG_INFO("标志：0x%04x", ntohs(dnsHdr->flags));
	LOG_INFO("	QR：%s", dnsHdr->flags >> 15 ? "1（响应报文）" : "0（查询报文）");
	LOG_INFO("	OC：%s", ((dnsHdr->flags >> 11) & 0x0f) == 0 ? "0（标准）" : dnsHdr->flags >> 11 == 1 ? "1（相反）" : "2（服务器状态请求）");
	LOG_INFO("	AA：%s", ((dnsHdr->flags >> 10) & 0x0f) == 1 ? "1（授权服务器）" : "0（非授权服务器）");
	LOG_INFO("查询记录数：%d", ntohs(dnsHdr->questNum));
	LOG_INFO("回答记录数：%d", ntohs(dnsHdr->answerNum));
	LOG_INFO("授权回答记录数：%d", ntohs(dnsHdr->authorNum));
	LOG_INFO("附加信息记录数：%d", ntohs(dnsHdr->additionNum));

	sprintf(fn->d_pkt[fn->pkgCount]->toptype, "DNS");
	sprintf(fn->d_pkt[fn->pkgCount]->dnsh.id, "0x%04x", ntohs(dnsHdr->id));
	sprintf(fn->d_pkt[fn->pkgCount]->dnsh.flags, "0x%04x", ntohs(dnsHdr->flags));
		sprintf(fn->d_pkt[fn->pkgCount]->dnsh.QR, "%s", dnsHdr->flags >> 15 ? "1 （响应报文）" : "0 （查询报文）");
		sprintf(fn->d_pkt[fn->pkgCount]->dnsh.OC, "%s", ((dnsHdr->flags >> 11) & 0x0f) == 0 ? "0（标准）" : dnsHdr->flags >> 11 == 1 ? "1（相反）" : "2（服务器状态请求）");
		sprintf(fn->d_pkt[fn->pkgCount]->dnsh.AA, "%s", ((dnsHdr->flags >> 10) & 0x0f) == 1 ? "1 (授权服务器)" : " 0 （非授权服务器）");
	sprintf(fn->d_pkt[fn->pkgCount]->dnsh.questNum, "%d", ntohs(dnsHdr->questNum));
	sprintf(fn->d_pkt[fn->pkgCount]->dnsh.answerNum, "%d", ntohs(dnsHdr->answerNum));
	sprintf(fn->d_pkt[fn->pkgCount]->dnsh.authorNum, "%d", ntohs(dnsHdr->authorNum));
	sprintf(fn->d_pkt[fn->pkgCount]->dnsh.additionNum, "%d", ntohs(dnsHdr->additionNum));
}

void HTTP_analysis(TCP_HEAD *tcpHdr, IP_HEAD *ipHdr, Fns *fn)
{
	LOG_INFO("");
	LOG_INFO("Packet Type: HTTP");
	char* http_p = (char*)ipHdr;
	int src_len = ipHdr->TotalLen;
	//int src_len = ntohs(ipHdr->TotalLen) - ((ipHdr->HeadLen & 0x0f) << 2) - (tcpHdr->res & 0xf) * 4;
	bool http_req = false, http_res = false;
	char* buf = new char[65000];
	int size = 0;

	while(src_len--)
	{
		if ((!http_req || !http_res) && src_len > 4 && (strncmp(http_p, "GET", strlen("GET")) == 0 || strncmp(http_p, "POST", strlen("POST")) == 0))
			http_req = true;

		if ((!http_req || !http_res) && src_len > 4 && strncmp(http_p, "HTTP", strlen("HTTP")) == 0)
			http_res = true;

		if (http_res || http_req)
		{
			buf[size++] = *http_p;
		}
		http_p++;
	}

	if (http_res || http_req)
	{
		LOG_INFO("%s：", http_req ? "HTTP 请求头" : "HTTP 响应头");
		LOG_INFO("%s：", buf);
	}
	buf[size] = '\0';

	TRACE("buf: %s\n", buf);
	sprintf(fn->d_pkt[fn->pkgCount]->toptype, "HTTP");
	sprintf(fn->d_pkt[fn->pkgCount]->httpd.type, "%s", http_req ? "HTTP 请求头" : "HTTP 响应头");
	sprintf(fn->d_pkt[fn->pkgCount]->httpd.content, "%s", buf);
	delete[] buf;
}

void POP3_analysis(TCP_HEAD *tcpHdr, IP_HEAD *ipHdr, Fns *fn)
{
	LOG_INFO("");
	LOG_INFO("Packet Type: POP3");
	char* pop3_p = (char*)ipHdr;
	int src_len = ipHdr->TotalLen;
	bool find_pop = false;
	char* buf = new char[65000];
	int size = 0;
	while (src_len--)
	{
		if (!find_pop && src_len > 3 && strncmp(pop3_p, "+OK", strlen("+OK")) == 0) {
			find_pop = true;
		}
		else if (!find_pop && src_len > 3 && strncmp(pop3_p, "-ER", strlen("-ER")) == 0) {
			find_pop = true;
		}
		if(find_pop)
			buf[size++] = *pop3_p;
		pop3_p++;
	}
	buf[size] = '\0';

	LOG_INFO("%s：", pop3_p);
	sprintf(fn->d_pkt[fn->pkgCount]->toptype, "POP3");
	sprintf(fn->d_pkt[fn->pkgCount]->pop3, "%s", pop3_p);
	delete[] buf;
}

void struct_init(Fns *fn, int type)
{
	if (type == 0)
	{
		fn->d_pkt[fn->pkgCount] = (DATA_PKT*)malloc(sizeof(DATA_PKT));
		//ETH
		fn->d_pkt[fn->pkgCount]->len = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->src = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->des = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->type = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->toptype = (char*)malloc(sizeof(char) * 48);
	}
	if (type == 1)
	{
		//IP
		fn->d_pkt[fn->pkgCount]->iph.Version = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->iph.HeadLen = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->iph.ServiceType = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->iph.TotalLen = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->iph.Identifier = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->iph.Flags = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->iph.FragOffset = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->iph.TTL = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->iph.Protocol = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->iph.HeadChecksum = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->iph.SourceAddr = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->iph.DestinAddr = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->iph.Options = (char*)malloc(sizeof(char) * 248);
	}
	if (type == 4)
	{
		//UDP
		fn->d_pkt[fn->pkgCount]->udph.sport = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->udph.dport = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->udph.len = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->udph.check = (char*)malloc(sizeof(char) * 48);
	}
	
	if (type == 2)
	{
		//ICMP
		fn->d_pkt[fn->pkgCount]->icmph.type = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->icmph.code = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->icmph.seq = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->icmph.chksum = (char*)malloc(sizeof(char) * 48);
	}
	if (type == 3)
	{
		//TCP
		fn->d_pkt[fn->pkgCount]->tcph.sport = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->tcph.dport = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->tcph.seq = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->tcph.ack_seq = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->tcph.len = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->tcph.res = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->tcph.flags = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->tcph.window = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->tcph.check = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->tcph.urg_ptr = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->tcph.opt = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->tcph.URG = (char*)malloc(sizeof(char) * 2);
		fn->d_pkt[fn->pkgCount]->tcph.ACK = (char*)malloc(sizeof(char) * 2);
		fn->d_pkt[fn->pkgCount]->tcph.PSH = (char*)malloc(sizeof(char) * 2);
		fn->d_pkt[fn->pkgCount]->tcph.RST = (char*)malloc(sizeof(char) * 2);
		fn->d_pkt[fn->pkgCount]->tcph.SYN = (char*)malloc(sizeof(char) * 2);
		fn->d_pkt[fn->pkgCount]->tcph.FIN = (char*)malloc(sizeof(char) * 2);
	}
	if (type == 5)
	{
		//DNS
		fn->d_pkt[fn->pkgCount]->dnsh.id = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->dnsh.flags = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->dnsh.questNum = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->dnsh.answerNum = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->dnsh.authorNum = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->dnsh.additionNum = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->dnsh.QR = (char*)malloc(sizeof(char) * 24);
		fn->d_pkt[fn->pkgCount]->dnsh.OC = (char*)malloc(sizeof(char) * 24);
		fn->d_pkt[fn->pkgCount]->dnsh.AA = (char*)malloc(sizeof(char) * 24);
	}
	if (type == 6)
	{
		//HTTP
		fn->d_pkt[fn->pkgCount]->httpd.type = (char*)malloc(sizeof(char) * 48);
		fn->d_pkt[fn->pkgCount]->httpd.content = (char*)malloc(sizeof(char) * 65000);
	}
	if (type == 7)
	{
		//POP3
		fn->d_pkt[fn->pkgCount]->pop3 = (char*)malloc(sizeof(char) * 65000);
	}
	
}

CString CtoCS(char* c)
{
	CString cst;
	cst = c;
	return cst;
}

void insertListItem(void *fnx);
int UIThread(Fns *fn)
{
	HANDLE threadHandle = (HANDLE)_beginthread(insertListItem, 0, (void*)fn);
	if (threadHandle == NULL)
	{
		LOG_ERROR("Create UI thread error, code: %d.", GetLastError());
		return -1;
	}
	return 0;
}

int count = 0;
void insertListItem(void *fnx)
{
	Fns *fn = (Fns*)fnx;
	CString cs;
	
	while (fn->run == 1) {
		TRACE("count: %d, pkgCount: %d\n", count, fn->pkgCount);
		if (fn->pkgCount == 1000 && count == 1000)
		{
			AfxMessageBox(L"The maximum number of packets captured have reached.");
			fn->stopCap();
			return;
		}
		else if (count == fn->pkgCount)
			//continue;
			Sleep(300);
		else
		{
			cs.Format(L"%d", count);
			TRACE("index: %d\n\n", fn->u->clist->GetItemCount());
			fn->u->clist->InsertItem(count, cs);
			if (strcmp(fn->d_pkt[count]->type, "IP") == 0)
			{
				fn->u->clist->SetItemText(count, 1, CtoCS(fn->d_pkt[count]->iph.SourceAddr));//源ip
				fn->u->clist->SetItemText(count, 2, CtoCS(fn->d_pkt[count]->iph.DestinAddr));//目的ip
				if (strcmp(fn->d_pkt[count]->toptype, "ICMP") == 0 || strcmp(fn->d_pkt[count]->toptype, "IP") == 0)
				{
					fn->u->clist->SetItemText(count, 5, CtoCS("--"));//源端口
					fn->u->clist->SetItemText(count, 6, CtoCS("--"));//目的端口
				}
				if (strcmp(fn->d_pkt[count]->toptype, "TCP") == 0 || strcmp(fn->d_pkt[count]->toptype, "HTTP") == 0
					|| strcmp(fn->d_pkt[count]->toptype, "POP3") == 0)
				{
					fn->u->clist->SetItemText(count, 5, CtoCS(fn->d_pkt[count]->tcph.sport));//源端口
					fn->u->clist->SetItemText(count, 6, CtoCS(fn->d_pkt[count]->tcph.dport));//目的端口
				}
				if (strcmp(fn->d_pkt[count]->toptype, "UDP") == 0 || strcmp(fn->d_pkt[count]->toptype, "DNS") == 0)
				{
					fn->u->clist->SetItemText(count, 5, CtoCS(fn->d_pkt[count]->udph.sport));//源端口
					fn->u->clist->SetItemText(count, 6, CtoCS(fn->d_pkt[count]->udph.dport));//目的端口
				}
			}
			else {
				fn->u->clist->SetItemText(count, 1, CtoCS("--")); //源ip
				fn->u->clist->SetItemText(count, 2, CtoCS("--")); //目的ip
				fn->u->clist->SetItemText(count, 5, CtoCS("--"));  //源端口
				fn->u->clist->SetItemText(count, 6, CtoCS("--"));  //目的端口			
			}
			fn->u->clist->SetItemText(count, 3, CtoCS(fn->d_pkt[count]->toptype));//协议
			fn->u->clist->SetItemText(count, 4, CtoCS(fn->d_pkt[count]->len)); //长度
	
			count++;
		}
	}
	return;
}

wchar_t* ctow(const char *str);
int Fns::insertTree(int index)
{
	TVINSERTSTRUCT itInsert;
	wchar_t* wc;
	u->ctree->DeleteAllItems();
	
	//eth头部
/*root*/HTREEITEM hroot = u->ctree->InsertItem(L"ethernet", 0, 0); 
/*1*/	HTREEITEM ethhdr = u->ctree->InsertItem(L"头部信息", 0, 0, hroot, TVI_LAST);
/*1.1*/	HTREEITEM len = u->ctree->InsertItem(wc = ctow(mformat("帧总长度：%s", d_pkt[index]->len).data()), 1, 1, ethhdr, TVI_LAST); delete wc;
/*1.2*/	HTREEITEM src = u->ctree->InsertItem(wc = ctow(mformat("源mac：%s", d_pkt[index]->src).data()), 1, 1, ethhdr, TVI_LAST);	delete wc;
/*1.3*/	HTREEITEM des = u->ctree->InsertItem(wc = ctow(mformat("目的mac：%s", d_pkt[index]->des).data()), 1, 1, ethhdr, TVI_LAST);	delete wc;
/*1.4*/	HTREEITEM toptype = u->ctree->InsertItem(wc = ctow(mformat("上层协议类型：%s", d_pkt[index]->toptype).data()), 1, 1, ethhdr, TVI_LAST);	delete wc;

/*ethsrc*///eth数据部分
/*2.1*/	HTREEITEM ethsrc = u->ctree->InsertItem(L"数据部分", 0, 0, hroot, TVI_LAST); 	

	if (strcmp(d_pkt[index]->type, "IP") == 0)
	{
			//IP头部
/*2.2*/		HTREEITEM type = u->ctree->InsertItem(wc = ctow(mformat("协议：%s", d_pkt[index]->type).data()), 1, 1, ethsrc, TVI_LAST);	delete wc;
/*2.3*/		HTREEITEM iphdr = u->ctree->InsertItem(L"IP头部", 0, 0, ethsrc, TVI_LAST);
/*2.3.1*/	HTREEITEM HeadLen = u->ctree->InsertItem(wc = ctow(mformat("头部长度：%s", d_pkt[index]->iph.HeadLen).data()), 1, 1, iphdr, TVI_LAST);	delete wc;
/*2.3.2*/	HTREEITEM Version = u->ctree->InsertItem(wc = ctow(mformat("服务类型：%s", d_pkt[index]->iph.ServiceType).data()), 1, 1, iphdr, TVI_LAST);	delete wc;
/*2.3.3*/	HTREEITEM TotalLen = u->ctree->InsertItem(wc = ctow(mformat("总长：%s", d_pkt[index]->iph.TotalLen).data()), 1, 1, iphdr, TVI_LAST);	delete wc;
/*2.3.4*/	HTREEITEM Identifier = u->ctree->InsertItem(wc = ctow(mformat("标识：%s", d_pkt[index]->iph.Identifier).data()), 1, 1, iphdr, TVI_LAST);	delete wc;
/*2.3.5*/	HTREEITEM Flags = u->ctree->InsertItem(wc = ctow(mformat("标志：%s", d_pkt[index]->iph.Flags).data()), 1, 1, iphdr, TVI_LAST);	delete wc;
/*2.3.6*/	HTREEITEM FragOffset = u->ctree->InsertItem(wc = ctow(mformat("偏移：%s", d_pkt[index]->iph.FragOffset).data()), 1, 1, iphdr, TVI_LAST);	delete wc;
/*2.3.7*/	HTREEITEM TTL = u->ctree->InsertItem(wc = ctow(mformat("TTL：%s", d_pkt[index]->iph.TTL).data()), 1, 1, iphdr, TVI_LAST);	delete wc;
/*2.3.8*/	HTREEITEM Protocol = u->ctree->InsertItem(wc = ctow(mformat("协议：%s", d_pkt[index]->iph.Protocol).data()), 1, 1, iphdr, TVI_LAST);	delete wc;
/*2.3.9*/	HTREEITEM HeadChecksum = u->ctree->InsertItem(wc = ctow(mformat("头部校验和：%s", d_pkt[index]->iph.HeadChecksum).data()), 1, 1, iphdr, TVI_LAST);	delete wc;
/*2.3.10*/	HTREEITEM SourceAddr = u->ctree->InsertItem(wc = ctow(mformat("源IP地址：%s", d_pkt[index]->iph.SourceAddr).data()), 1, 1, iphdr, TVI_LAST);	delete wc;
/*2.3.11*/	HTREEITEM DestinAddr = u->ctree->InsertItem(wc = ctow(mformat("目的IP地址：%s", d_pkt[index]->iph.DestinAddr).data()), 1, 1, iphdr, TVI_LAST);	delete wc;
			
			//IP数据部分
/*2.4*/		HTREEITEM ipsrc = u->ctree->InsertItem(L"IP数据部分", 1, 1, ethsrc, TVI_LAST);
			if (strcmp(d_pkt[index]->toptype, "IP") == 0)
			{
				HTREEITEM ipinfo = u->ctree->InsertItem(L"未知的数据包", 1, 1, ipsrc, TVI_LAST);
			}
			if (strcmp(d_pkt[index]->toptype, "ICMP") == 0)
			{
				HTREEITEM icmp_title = u->ctree->InsertItem(L"协议：ICMP", 1, 1, ipsrc, TVI_LAST);
				HTREEITEM icmp_type = u->ctree->InsertItem(wc = ctow(mformat("类型：%s", d_pkt[index]->icmph.type).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
				HTREEITEM icmp_code = u->ctree->InsertItem(wc = ctow(mformat("代码：%s", d_pkt[index]->icmph.code).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
				HTREEITEM icmp_seq  = u->ctree->InsertItem(wc = ctow(mformat("序列号：%s", d_pkt[index]->icmph.seq ).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
				HTREEITEM icmp_chksum = u->ctree->InsertItem(wc = ctow(mformat("校验和：%s", d_pkt[index]->icmph.chksum).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
			}
			if (strcmp(d_pkt[index]->toptype, "UDP") == 0 || strcmp(d_pkt[index]->toptype, "DNS") == 0)
			{
				HTREEITEM udp_title = u->ctree->InsertItem(L"协议：UDP", 1, 1, ipsrc, TVI_LAST);
				HTREEITEM udp_sport = u->ctree->InsertItem(wc = ctow(mformat("源端口：%s", d_pkt[index]->udph.sport).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
				HTREEITEM udp_dport = u->ctree->InsertItem(wc = ctow(mformat("目的端口：%s", d_pkt[index]->udph.dport).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
				HTREEITEM udp_len = u->ctree->InsertItem(wc = ctow(mformat("长度：%s", d_pkt[index]->udph.len).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
				HTREEITEM udp_check = u->ctree->InsertItem(wc = ctow(mformat("校验和：%s", d_pkt[index]->udph.check).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
				if (strcmp(d_pkt[index]->toptype, "DNS") == 0)
				{
					HTREEITEM dns = u->ctree->InsertItem(L"数据部分", 1, 1, ipsrc, TVI_LAST);
					HTREEITEM dns_title = u->ctree->InsertItem(L"协议：DNS", 1, 1, dns, TVI_LAST);
					HTREEITEM dns_id = u->ctree->InsertItem(wc = ctow(mformat("标识：%s", d_pkt[index]->dnsh.id).data()), 1, 1, dns, TVI_LAST);	delete wc;
					HTREEITEM dns_flags = u->ctree->InsertItem(wc = ctow(mformat("标志：%s", d_pkt[index]->dnsh.flags).data()), 1, 1, dns, TVI_LAST);	delete wc;
						HTREEITEM dns_QR = u->ctree->InsertItem(wc = ctow(mformat("QR：%s", d_pkt[index]->dnsh.QR).data()), 1, 1, dns_flags, TVI_LAST);	delete wc;
						HTREEITEM dns_OC = u->ctree->InsertItem(wc = ctow(mformat("OC：%s", d_pkt[index]->dnsh.OC).data()), 1, 1, dns_flags, TVI_LAST);	delete wc;
						HTREEITEM dns_AA = u->ctree->InsertItem(wc = ctow(mformat("AA：%s", d_pkt[index]->dnsh.AA).data()), 1, 1, dns_flags, TVI_LAST);	delete wc;
					HTREEITEM dns_questNum = u->ctree->InsertItem(wc = ctow(mformat("查询记录数：%s", d_pkt[index]->dnsh.questNum).data()), 1, 1, dns, TVI_LAST);	delete wc;
					HTREEITEM dns_answerNum = u->ctree->InsertItem(wc = ctow(mformat("回答记录数：%s", d_pkt[index]->dnsh.answerNum).data()), 1, 1, dns, TVI_LAST);	delete wc;
					HTREEITEM dns_authorNum = u->ctree->InsertItem(wc = ctow(mformat("授权回答记录数：%s", d_pkt[index]->dnsh.authorNum).data()), 1, 1, dns, TVI_LAST);	delete wc;
					HTREEITEM dns_additionNum = u->ctree->InsertItem(wc = ctow(mformat("附加信息记录数：%s", d_pkt[index]->dnsh.additionNum).data()), 1, 1, dns, TVI_LAST);	delete wc;
				}
			}
			if (strcmp(d_pkt[index]->toptype, "TCP") == 0 || strcmp(d_pkt[index]->toptype, "HTTP") == 0 || strcmp(d_pkt[index]->toptype, "POP3") == 0)
			{
				HTREEITEM tcp_title = u->ctree->InsertItem(L"协议：TCP", 1, 1, ipsrc, TVI_LAST);

				HTREEITEM tcp_sport = u->ctree->InsertItem(wc = ctow(mformat("源端口：%s", d_pkt[index]->tcph.sport).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
				HTREEITEM tcp_dport = u->ctree->InsertItem(wc = ctow(mformat("目的端口：%s", d_pkt[index]->tcph.dport).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
				HTREEITEM tcp_seq = u->ctree->InsertItem(wc = ctow(mformat("序列号：%s", d_pkt[index]->tcph.seq).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
				HTREEITEM tcp_ack_seq = u->ctree->InsertItem(wc = ctow(mformat("确认号：%s", d_pkt[index]->tcph.ack_seq).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
				HTREEITEM tcp_res = u->ctree->InsertItem(wc = ctow(mformat("长度：%s", d_pkt[index]->tcph.res).data()), 1, 1, ipsrc, TVI_LAST);	delete wc;
				HTREEITEM tcp_flags = u->ctree->InsertItem(wc = ctow(mformat("标识：%s", d_pkt[index]->tcph.flags).data()), 1, 1, ipsrc, TVI_LAST); delete wc;
					HTREEITEM tcp_URG = u->ctree->InsertItem(wc = ctow(mformat("URG：%s", d_pkt[index]->tcph.URG).data()), 1, 1, tcp_flags, TVI_LAST);	delete wc;
					HTREEITEM tcp_ACK = u->ctree->InsertItem(wc = ctow(mformat("ACK：%s", d_pkt[index]->tcph.ACK).data()), 1, 1, tcp_flags, TVI_LAST);	delete wc;
					HTREEITEM tcp_PSH = u->ctree->InsertItem(wc = ctow(mformat("PSH：%s", d_pkt[index]->tcph.PSH).data()), 1, 1, tcp_flags, TVI_LAST);	delete wc;
					HTREEITEM tcp_RST = u->ctree->InsertItem(wc = ctow(mformat("RST：%s", d_pkt[index]->tcph.RST).data()), 1, 1, tcp_flags, TVI_LAST);	delete wc;
					HTREEITEM tcp_SYN = u->ctree->InsertItem(wc = ctow(mformat("SYN：%s", d_pkt[index]->tcph.SYN).data()), 1, 1, tcp_flags, TVI_LAST);	delete wc;
					HTREEITEM tcp_FIN = u->ctree->InsertItem(wc = ctow(mformat("FIN：%s", d_pkt[index]->tcph.FIN).data()), 1, 1, tcp_flags, TVI_LAST);	delete wc;
				HTREEITEM tcp_window = u->ctree->InsertItem(wc = ctow(mformat("窗口大小：%s", d_pkt[index]->tcph.window).data()), 1, 1, ipsrc, TVI_LAST); delete wc;
				HTREEITEM tcp_check = u->ctree->InsertItem(wc = ctow(mformat("校验和：%s", d_pkt[index]->tcph.check).data()), 1, 1, ipsrc, TVI_LAST); delete wc;
				HTREEITEM tcp_urg_ptr = u->ctree->InsertItem(wc = ctow(mformat("紧急指针：%s", d_pkt[index]->tcph.urg_ptr).data()), 1, 1, ipsrc, TVI_LAST); delete wc;

				if (strcmp(d_pkt[index]->toptype, "HTTP") == 0)
				{
					HTREEITEM tcp = u->ctree->InsertItem(L"数据部分", 1, 1, ipsrc, TVI_LAST);
					HTREEITEM http_title = u->ctree->InsertItem(L"协议：HTTP", 1, 1, tcp, TVI_LAST);
					HTREEITEM http_type = u->ctree->InsertItem(wc = ctow(mformat("type：%s", d_pkt[index]->httpd.type).data()), 1, 1, tcp, TVI_LAST); delete wc;
					HTREEITEM http_content = u->ctree->InsertItem(wc = ctow(mformat("content：%s", d_pkt[index]->httpd.content).data()), 1, 1, tcp, TVI_LAST); delete wc;
				}
				if (strcmp(d_pkt[index]->toptype, "POP3") == 0)
				{
					HTREEITEM tcp = u->ctree->InsertItem(L"数据部分", 1, 1, ipsrc, TVI_LAST);
					HTREEITEM pop3_title = u->ctree->InsertItem(L"协议：POP3", 1, 1, tcp, TVI_LAST);
					HTREEITEM pop3 = u->ctree->InsertItem(wc = ctow(mformat("content：%s", d_pkt[index]->pop3).data()), 1, 1, tcp, TVI_LAST); delete wc;
				}
			}
	
	}
	else
	{
/*2.2*/		HTREEITEM type = u->ctree->InsertItem(wc = ctow(mformat("协议：%s", d_pkt[index]->type).data()), 1, 1, ethsrc, TVI_LAST); 	delete wc;
/*2.3*/		HTREEITEM ethinfo = u->ctree->InsertItem(L"暂时不能解析该数据包", 1, 1, ethsrc, TVI_LAST);
	}

	expandTree(hroot);
	return 0;
}

//自动展开
void Fns::expandTree(HTREEITEM root)
{
	u->ctree->Expand(root, TVE_EXPAND);
	HTREEITEM brother = u->ctree->GetNextSiblingItem(root);
	HTREEITEM child = u->ctree->GetChildItem(root);
	if (child)
	{
		u->ctree->Expand(child, TVE_EXPAND);
		expandTree(child);
	}
	if (brother)
	{
		u->ctree->Expand(brother, TVE_EXPAND);
		expandTree(brother);
	}

	return;
}

wchar_t* ctow(const char *str)
{
	int length = strlen(str) + 1;
	wchar_t *buffer = (wchar_t*)malloc(sizeof(wchar_t)*length);
	memset(buffer, 0, length * sizeof(wchar_t));
	MultiByteToWideChar(CP_ACP, 0, str, strlen(str), buffer, length);
	return buffer;
}