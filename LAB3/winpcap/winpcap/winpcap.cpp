// winpcap.cpp : 定义控制台应用程序的入口点。
//


#include "stdafx.h"

#include <iostream>
#include <string>
#include <pcap.h>

#define ETH_ALEN 6
/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ether_header
{
	u_char  ether_dhost[ETH_ALEN];      // destination ether addr 
	u_char  ether_shost[ETH_ALEN];      // source ether addr    
	u_short ether_type;                 // packet type ID field 
}ether_header;
/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/*ARP header*/
typedef struct arphdr
{
	//arp首部
	unsigned short arp_hrd;      /* format of hardware address */
	unsigned short arp_pro;      /* format of protocol address */
	unsigned char arp_hln;       /* length of hardware address */
	unsigned char arp_pln;       /* length of protocol address */
	unsigned short arp_op;       /* ARP/RARP operation */

	unsigned char arp_sha[6];    /* sender hardware address */
	ip_address arp_spa;          /* sender protocol address */
	unsigned char arp_tha[6];    /* target hardware address */
	ip_address arp_dpa;          /* target protocol address */
}arp_header;
/*tcp header*/
typedef struct _TCP_HEADER
{
	short m_sSourPort;        // 源端口号16bit
	short m_sDestPort;       // 目的端口号16bit
	unsigned int m_uiSequNum;       // 序列号32bit
	unsigned int m_uiAcknowledgeNum;  // 确认号32bit
	short m_sHeaderLenAndFlag;      // 前4位：TCP头长度；中6位：保留；后6位：标志位
	short m_sWindowSize;       // 窗口大小16bit
	short m_sCheckSum;        // 检验和16bit
	short m_surgentPointer;   // 紧急数据偏移量16bit
}tcp_header,*PTCP_HEADER;
/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

using namespace std;
string set_filter();
void analyse_packet(pcap_pkthdr *header, const u_char *data, char *sMac,
	char *dMac, char *srcIP, char *dstIP, char *sPort, char *dPort, char *protoType);
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	struct bpf_program fcode;
	int res;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct tm *ltime;
	char timestr[16];
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	time_t local_tv_sec;


	/* Retrieve the device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		return -1;
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);
	

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
						// 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	/*set filter*/
	string m_filter = set_filter();
	if (!m_filter.empty())
	{
		// Let's do things simpler: we suppose to be in a C class network ;-)
		u_int NetMask = 0xffffff;

		//compile the filter
		if (pcap_compile(adhandle, &fcode, m_filter.c_str(), 1, NetMask) < 0)
		{
			fprintf(stderr, "\nError compiling filter: wrong syntax.\n");

			pcap_close(adhandle);
			return -3;
		}

		//set the filter
		if (pcap_setfilter(adhandle, &fcode)<0)
		{
			fprintf(stderr, "\nError setting the filter\n");

			pcap_close(adhandle);
			return -4;
		}
	}
	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);

	/* Retrieve the packets */
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

		if (res == 0)
			/* Timeout elapsed */
			continue;

		/* convert the timestamp to readable format */
		//local_tv_sec = header->ts.tv_sec;
		//ltime = localtime(&local_tv_sec);
		//strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
		char sMac[20], dMac[20], srcIP[20], dstIP[20], sPort[8], dPort[8], protoType[10];
		analyse_packet(header, pkt_data,sMac,dMac,srcIP,dstIP,sPort,dPort,protoType);
		cout << "\nThe Format of Packet:" << endl;
		cout << "Source Mac Address:" << sMac << endl;
		cout << "Destination Mac Address:" << sMac << endl;
		cout << "Proto Type\tSrc IP\tSrc Port\tDest IP\tDest Port" << endl;
		cout << protoType << "\t" << srcIP << "\t" << sPort << "\t" << dstIP << "\t" << dPort << endl;
		//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	}

	if (res == -1) {
		printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
		return -1;
	}

	pcap_close(adhandle);
	return 0;
}
string set_filter() {
	string m_filter;
	//input protocol type
	int proto_type;
	cout << "Enter the Protocol type (1:AllProtocol 0:Special Special Protocol):" << endl;	
	cin >> proto_type;
	if (proto_type) {
		//m_filter.append("");
	}
	else {
		cout << "Filter ARP Protocol?(1/0)" << endl;
		cin >> proto_type;
		if (proto_type) {
			m_filter.append("( arp ");
		}
		else {
			m_filter.append("(not arp ");
		}
		cout << "Filter ICMP Protocol?(1/0)" << endl;
		cin >> proto_type;
		if (proto_type) {
			m_filter.append("or  icmp ");
		}
		else {
			m_filter.append("and not icmp ");
		}
		cout << "Filter TCP Protocol?(1/0)" << endl;
		cin >> proto_type;
		if (proto_type) {
			m_filter.append("or tcp ");
		}
		else {
			m_filter.append("and not tcp ");
		}
		cout << "Filter UDP Protocol?(1/0)" << endl;
		cin >> proto_type;
		if (proto_type) {
			m_filter.append("or udp ) ");
		}
		else {
			m_filter.append("and not udp) ");
		}
	}
	cout << "Filter all IP?(1/0)" << endl;
	int ip_flag;
	cin >> ip_flag;
	if (ip_flag == 0) {
		cout << "Input ip address:" << endl;
		string ipadd;
		cin >> ipadd;
		m_filter.append(" host ");
		m_filter.append(ipadd);
	}
	cout << "Filter all PORT?(1/0)" << endl;
	int port_flag;
	cin >> port_flag;
	if (port_flag == 0) {
		cout << "Input port:" << endl;
		int port;
		cin >> port;
		if (port > 65535 || port <= 1024) {
			cerr << "Input port err!" << endl;
		}
		else {
			m_filter.append(" port ");
			char s[10];
			sprintf_s(s, "%d", port);
			m_filter.append(s);
		}		
	}
	return m_filter;
}
void analyse_packet(pcap_pkthdr *header, const u_char *data,char *sMac,
	char *dMac,char *srcIP,char *dstIP, char *sPort,char *dPort,char *protoType) {
	struct ether_header *eth;
	u_char* mac_string;
	ip_header *ipHead;
	arp_header *arpHead;
	ip_address ipaddr;
	eth = (ether_header *)data;	
	mac_string = eth->ether_shost;
	sprintf(sMac, "%02X:%02X:%02X:%02X:%02X:%02X", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	mac_string = eth->ether_dhost;
	sprintf(dMac, "%02X:%02X:%02X:%02X:%02X:%02X", *mac_string, *(mac_string + 1), *(mac_string + 2), *(mac_string + 3), *(mac_string + 4), *(mac_string + 5));
	
	switch (ntohs(eth->ether_type)) {
	case 0x0806://arp
		strcpy(protoType,"ARP");
		arpHead = (arp_header *)(data + 14);
		sprintf(srcIP,"%u.%u.%u.%u", arpHead->arp_spa.byte1, arpHead->arp_spa.byte2,
			arpHead->arp_spa.byte3, arpHead->arp_spa.byte4);
		sprintf(dstIP, "%u.%u.%u.%u", arpHead->arp_dpa.byte1, arpHead->arp_dpa.byte2,
			arpHead->arp_dpa.byte3, arpHead->arp_dpa.byte4);
		strcpy(sPort, "--");
		strcpy(dPort, "--");
		break;
	case 0x8035://rarp
		strcpy(protoType, "RARP");
		strcpy(sPort, "--");
		strcpy(dPort, "--");
		break;
	case 0x0800://ip
		//protoType = "ARP";
		ipHead = (ip_header*)(data + 14);
		ipaddr = ipHead->saddr;
		sprintf(srcIP, "%u.%u.%u.%u", ipaddr.byte1, ipaddr.byte2, ipaddr.byte3, ipaddr.byte4);
		ipaddr = ipHead->daddr;
		sprintf(dstIP, "%u.%u.%u.%u", ipaddr.byte1, ipaddr.byte2, ipaddr.byte3, ipaddr.byte4);
		switch (ipHead->proto) {
		case 1:
			strcpy(protoType, "ICMP");
			strcpy(sPort, "--");
			strcpy(dPort, "--");
			break;
		case 6:
			strcpy(protoType, "TCP");
			sprintf(sPort, "%d",ntohs(((tcp_header*)(data+16+20))->m_sSourPort));
			sprintf(dPort, "%d", ntohs(((tcp_header*)(data + 16 + 20))->m_sDestPort));
			break;
		case 17:
			strcpy(protoType, "UDP");
			sprintf(sPort, "%d", ntohs(((udp_header*)(data + 16 + 20))->sport));
			sprintf(dPort, "%d", ntohs(((udp_header*)(data + 16 + 20))->sport));
			break;
		default:
			strcpy(protoType, "未知的IP包");
			strcpy(srcIP, "----------");
			strcpy(dstIP, "----------");
			strcpy(sPort, "--");
			strcpy(dPort, "--");
			break;
		}
		break;
	case 0x0200://pub
		strcpy(protoType, "PUB");
		strcpy(srcIP, "----------");
		strcpy(dstIP, "----------");
		strcpy(sPort, "--");
		strcpy(dPort, "--");
		break;
	default://未知以太网包
		strcpy(protoType, "未知的以太网包");
		strcpy(srcIP, "----------");
		strcpy(dstIP, "----------");
		strcpy(sPort, "--");
		strcpy(dPort, "--");
		break;
	}
}