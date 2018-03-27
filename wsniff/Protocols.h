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
//Mac֡ͷ ռ14���ֽ�  
typedef struct ETH_HEAD
{
	u_char des[6];         //6���ֽ� Ŀ���ַ  
	u_char src[6];              //6���ֽ� Դ��ַ  
	u_short type;               //2���ֽ� ����  
}eth_hdr;

//ARPͷ  
typedef struct ARP_HEAD
{
	unsigned short ar_hrd;                     //Ӳ������  
	unsigned short ar_pro;                     //Э������  
	u_char ar_hln;                      //Ӳ����ַ����  
	u_char ar_pln;                      //Э���ַ����  
	unsigned short ar_op;                      //�����룬1Ϊ���� 2Ϊ�ظ�  
	u_char ar_srcmac[6];            //���ͷ�MAC  
	u_char ar_srcip[4];             //���ͷ�IP  
	u_char ar_destmac[6];           //���շ�MAC  
	u_char ar_destip[4];                //���շ�IP  
}arp_hdr;


typedef struct IP_HEAD
{
	union //��������
	{
		unsigned char Version;      //�汾��ǰ4λ��
		unsigned char HeadLen;      //IHL����4λ����IPͷ�ĳ���
	};
	unsigned char ServiceType;      //��������
	unsigned short TotalLen;        //�ܳ�
	unsigned short Identifier;      //��ʶ
	union
	{
		unsigned short Flags;       //��־��ǰ3λ��
		unsigned short FragOffset;  //�ֶ�ƫ�ƣ���13λ��
	};
	unsigned char TTL;       //������
	unsigned char Protocol;         //Э��
	unsigned short HeadChecksum;    //��У���
	unsigned int SourceAddr;        //Դ��ַ
	unsigned int DestinAddr;        //Ŀ�ĵ�ַ
	unsigned char Options;          //ѡ��
}ip_hdr; //����IPͷ�������ݽṹ


		 //����TCPͷ  
typedef struct TCP_HEAD
{
	u_short sport;                          //Դ�˿ڵ�ַ  16λ  
	u_short dport;                          //Ŀ�Ķ˿ڵ�ַ 16λ  
	u_int seq;                                  //���к� 32λ  
	u_int ack_seq;                          //ȷ�����к�   
	u_char len : 4, res : 4;
	u_char flags;
	u_short window;                 //���ڴ�С 16λ  
	u_short check;                      //У��� 16λ  
	u_short urg_ptr;                    //����ָ�� 16λ  
	u_int opt;                              //ѡ��  
}tcp_hdr;


//����UDPͷ  
typedef struct UDP_HEAD
{
	u_short sport;      //Դ�˿�  16λ  
	u_short dport;      //Ŀ�Ķ˿� 16λ  
	u_short len;            //���ݱ����� 16λ  
	u_short check;      //У��� 16λ     
}udp_hdr;

//����ICMP  
typedef struct ICMP_HEAD
{
	u_char type;            //8λ ����  
	u_char code;            //8λ ����  
	u_char seq;         //���к� 8λ  
	u_char chksum;      //8λУ���  
}icmp_hdr;

typedef struct DNS_HEAD		//DNS�����ײ�
{
	unsigned short id;
	unsigned short flags;
	unsigned short questNum;
	unsigned short answerNum;
	unsigned short authorNum;
	unsigned short additionNum;
}dns_hdr, *pDNSHDR;


//����IPv6  
typedef struct IPv6_HEAD
{
	//#if defined(BIG_ENDIAN)  
	u_int version : 4,                //�汾  
		flowtype : 8,         //������  
		flowid : 20;              //����ǩ  
								  /*#elif defined(LITTLE_ENDIAN)
								  u_int  flowid:20,               //����ǩ
								  flowtype:8,         //������
								  version:4;              //�汾
								  //#endif*/
	u_short plen;                   //��Ч�غɳ���  
	u_char nh;                      //��һ��ͷ��  
	u_char hlim;                    //������  
	u_short saddr[8];           //Դ��ַ  
	u_short daddr[8];           //Ŀ�ĵ�ַ  
}ipv6_hdr;

//����ICMPv6  
typedef struct ICMPv6_HEAD
{
	u_char type;            //8λ ����  
	u_char code;            //8λ ����  
	u_char seq;         //���к� 8λ  
	u_char chksum;      //8λУ���  
	u_char op_type; //ѡ�����  
	u_char op_len;      //ѡ�����  
	u_char op_ethaddr[6];       //ѡ���·���ַ  
}icmpv6_hdr;

//�Ը��ְ����м���  
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
//Ҫ��������ݽṹ  
typedef struct DATA_PKT
{
	//char  pktType[8];                   //������  
	//int time[6];                                //ʱ��  
	char* len;                                    //����  

	//��·���ͷ
	char* src;    //Դmac
	char* des;	//Ŀ��mac
	char* type;   //Э������
	char* toptype;  //�ϲ�Э������ 

	struct ip_hdr
	{
		char* Version;      //�汾��ǰ4λ��
		char* HeadLen;      //IHL����4λ����IPͷ�ĳ���
		char* ServiceType;      //��������
		char* TotalLen;        //�ܳ�
		char* Identifier;      //��ʶ
		char* Flags;       //��־��ǰ3λ��
		char* FragOffset;  //�ֶ�ƫ�ƣ���13λ��
		char* TTL;       //������
		char* Protocol;         //Э��
		char* HeadChecksum;    //��У���
		char* SourceAddr;        //Դ��ַ
		char* DestinAddr;        //Ŀ�ĵ�ַ
		char* Options;          //ѡ��
	}iph;

	//arp_hdr* arph;                //ARP��ͷ  
	//ipv6_hdr* iph6;                //IPV6  
	//icmpv6_hdr* icmph6;    //ICMPv6��ͷ  

	//����UDPͷ  
	struct udp_hdr
	{
		char* sport;      //Դ�˿�  16λ  
		char* dport;      //Ŀ�Ķ˿� 16λ  
		char* len;            //���ݱ����� 16λ  
		char* check;      //У��� 16λ     
	}udph;

	//����ICMP  
	struct icmp_hdr
	{
		char* type;            //8λ ����  
		char* code;            //8λ ����  
		char* seq;         //���к� 8λ  
		char* chksum;      //8λУ���  
	}icmph;

	struct dns_hdr		//DNS�����ײ�
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
		char* sport;                          //Դ�˿ڵ�ַ  16λ  
		char* dport;                          //Ŀ�Ķ˿ڵ�ַ 16λ  
		char* seq;                                  //���к� 32λ  
		char* ack_seq;                          //ȷ�����к�   
		char* len;
		char* res;
		char* flags;
			char* URG;
			char* ACK;
			char* PSH;
			char* RST;
			char* SYN;
			char* FIN;
		char* window;                 //���ڴ�С 16λ  
		char* check;                      //У��� 16λ  
		char* urg_ptr;                    //����ָ�� 16λ  
		char* opt;                              //ѡ��  
	}tcph;                //TCP��ͷ  

	struct http                         //Ӧ�ò��ͷ  
	{
		char* type;
		char* content;
	}httpd;

	char* pop3;
};

#endif  