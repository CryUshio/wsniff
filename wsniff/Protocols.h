#ifndef PROTOCOL_H  
#define PROTOCOL_H  
#define PROTO_ICMP 1  
#define PROTO_TCP 6                   
#define PROTO_UDP 17                       
#define LITTLE_ENDIAN 1234  
#define BIG_ENDIAN    4321  
#define BUFFER_SIZE 65535 



#include<winsock2.h> 
#pragma comment(lib,"ws2_32.lib")
//Mac帧头 占14个字节  
typedef struct ETH_HEAD
{
	u_char des[6];         //6个字节 目标地址  
	u_char src[6];              //6个字节 源地址  
	u_short type;               //2个字节 类型  
}eth_hdr;

//ARP头  
typedef struct ARP_HEAD
{
	unsigned short ar_hrd;                     //硬件类型  
	unsigned short ar_pro;                     //协议类型  
	u_char ar_hln;                      //硬件地址长度  
	u_char ar_pln;                      //协议地址长度  
	unsigned short ar_op;                      //操作码，1为请求 2为回复  
	u_char ar_srcmac[6];            //发送方MAC  
	u_char ar_srcip[4];             //发送方IP  
	u_char ar_destmac[6];           //接收方MAC  
	u_char ar_destip[4];                //接收方IP  
}arp_hdr;


typedef struct IP_HEAD
{
	union //定义联合
	{
		unsigned char Version;      //版本（前4位）
		unsigned char HeadLen;      //IHL（后4位），IP头的长度
	};
	unsigned char ServiceType;      //服务类型
	unsigned short TotalLen;        //总长
	unsigned short Identifier;      //标识
	union
	{
		unsigned short Flags;       //标志（前3位）
		unsigned short FragOffset;  //分段偏移（后13位）
	};
	unsigned char TTL;       //生命期
	unsigned char Protocol;         //协议
	unsigned short HeadChecksum;    //对校验和
	unsigned int SourceAddr;        //源地址
	unsigned int DestinAddr;        //目的地址
	unsigned char Options;          //选项
}ip_hdr; //定义IP头部的数据结构


		 //定义TCP头  
typedef struct TCP_HEAD
{
	u_short sport;                          //源端口地址  16位  
	u_short dport;                          //目的端口地址 16位  
	u_int seq;                                  //序列号 32位  
	u_int ack_seq;                          //确认序列号   
	u_char len : 4, res : 4;
	u_char flags;
	u_short window;                 //窗口大小 16位  
	u_short check;                      //校验和 16位  
	u_short urg_ptr;                    //紧急指针 16位  
	u_int opt;                              //选项  
}tcp_hdr;


//定义UDP头  
typedef struct UDP_HEAD
{
	u_short sport;      //源端口  16位  
	u_short dport;      //目的端口 16位  
	u_short len;            //数据报长度 16位  
	u_short check;      //校验和 16位     
}udp_hdr;

//定义ICMP  
typedef struct ICMP_HEAD
{
	u_char type;            //8位 类型  
	u_char code;            //8位 代码  
	u_char seq;         //序列号 8位  
	u_char chksum;      //8位校验和  
}icmp_hdr;

typedef struct DNS_HEAD		//DNS报文首部
{
	unsigned short id;
	unsigned short flags;
	unsigned short questNum;
	unsigned short answerNum;
	unsigned short authorNum;
	unsigned short additionNum;
}dns_hdr, *pDNSHDR;


//定义IPv6  
typedef struct IPv6_HEAD
{
	//#if defined(BIG_ENDIAN)  
	u_int version : 4,                //版本  
		flowtype : 8,         //流类型  
		flowid : 20;              //流标签  
								  /*#elif defined(LITTLE_ENDIAN)
								  u_int  flowid:20,               //流标签
								  flowtype:8,         //流类型
								  version:4;              //版本
								  //#endif*/
	u_short plen;                   //有效载荷长度  
	u_char nh;                      //下一个头部  
	u_char hlim;                    //跳限制  
	u_short saddr[8];           //源地址  
	u_short daddr[8];           //目的地址  
}ipv6_hdr;

//定义ICMPv6  
typedef struct ICMPv6_HEAD
{
	u_char type;            //8位 类型  
	u_char code;            //8位 代码  
	u_char seq;         //序列号 8位  
	u_char chksum;      //8位校验和  
	u_char op_type; //选项：类型  
	u_char op_len;      //选项：长度  
	u_char op_ethaddr[6];       //选项：链路层地址  
}icmpv6_hdr;

//对各种包进行计数  
typedef struct pkt_count
{
	int n_ip;
	int n_ip6;
	int n_arp;
	int n_tcp;
	int n_udp;
	int n_icmp;
	int n_icmp6;
	int n_http;
	int n_other;
	int n_sum;
};

//////////////////////////////////////////////////////////////////////////  
//要保存的数据结构  
typedef struct DATA_PKT
{
	//char  pktType[8];                   //包类型  
	//int time[6];                                //时间  
	char* len;                                    //长度  

	//链路层包头
	char* src;    //源mac
	char* des;	//目的mac
	char* type;   //协议类型
	char* toptype;  //上层协议类型 

	struct ip_hdr
	{
		char* Version;      //版本（前4位）
		char* HeadLen;      //IHL（后4位），IP头的长度
		char* ServiceType;      //服务类型
		char* TotalLen;        //总长
		char* Identifier;      //标识
		char* Flags;       //标志（前3位）
		char* FragOffset;  //分段偏移（后13位）
		char* TTL;       //生命期
		char* Protocol;         //协议
		char* HeadChecksum;    //对校验和
		char* SourceAddr;        //源地址
		char* DestinAddr;        //目的地址
		char* Options;          //选项
	}iph;

	//arp_hdr* arph;                //ARP包头  
	//ipv6_hdr* iph6;                //IPV6  
	//icmpv6_hdr* icmph6;    //ICMPv6包头  

	//定义UDP头  
	struct udp_hdr
	{
		char* sport;      //源端口  16位  
		char* dport;      //目的端口 16位  
		char* len;            //数据报长度 16位  
		char* check;      //校验和 16位     
	}udph;

	//定义ICMP  
	struct icmp_hdr
	{
		char* type;            //8位 类型  
		char* code;            //8位 代码  
		char* seq;         //序列号 8位  
		char* chksum;      //8位校验和  
	}icmph;

	struct dns_hdr		//DNS报文首部
	{
		char* id;
		char* flags;
			char* QR;
			char* OC;
			char* AA;
		char* questNum;
		char* answerNum;
		char* authorNum;
		char* additionNum;
	}dnsh;

	struct tcp_hdr
	{
		char* sport;                          //源端口地址  16位  
		char* dport;                          //目的端口地址 16位  
		char* seq;                                  //序列号 32位  
		char* ack_seq;                          //确认序列号   
		char* len;
		char* res;
		char* flags;
			char* URG;
			char* ACK;
			char* PSH;
			char* RST;
			char* SYN;
			char* FIN;
		char* window;                 //窗口大小 16位  
		char* check;                      //校验和 16位  
		char* urg_ptr;                    //紧急指针 16位  
		char* opt;                              //选项  
	}tcph;                //TCP包头  

	struct http                         //应用层包头  
	{
		char* type;
		char* content;
	}httpd;

	char* pop3;
};

#endif  