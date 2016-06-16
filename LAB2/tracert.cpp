#include <iostream>
#include <iomanip>
#include <WINSOCK2.H>
#include <ws2tcpip.h>
#include <STDIO.H>

#pragma comment(lib,"ws2_32.lib")

using namespace std;

typedef struct icmp_hdr{  
    unsigned char icmp_type;  
    unsigned char icmp_code;  
    unsigned short icmp_checksum;  
    unsigned short icmp_id;  
    unsigned short icmp_sequence;  
    unsigned long icmp_timnestamp;  
}ICMP_HDR, *PICMP_HDR;  

#define ICMP_HEADER_LEN 12

typedef struct _IPHeader{  
    UCHAR iphVerLen;  
    UCHAR ipTOS;  
    USHORT ipLength;  
    USHORT ipID;  
    USHORT ipFlags;  
    UCHAR ipTTL;  
    UCHAR ipProtocol;  
    USHORT ipChecksum;  
    ULONG ipSource;  
    ULONG ipDestination;  
}IPHeader, *PIPHeader; 

USHORT checksum(USHORT* buffer, int size)  
{  
    unsigned long cksum = 0;  
	
    while(size > 1)  
    {  
        cksum += *buffer++;  
        size -= sizeof(USHORT);  
    }  
	
    // 奇数，将最后一个字节扩展到双字， 再累加  
    if(size)  
        cksum += *(UCHAR*)buffer;  
	
    //高16  低16相加，取反  
    cksum = (cksum >> 16) + (cksum & 0xffff);  
    cksum += (cksum >> 16);  
    return (USHORT)(~cksum);  
} 
bool Decode_Icmp_Response(char *recvBuf,int packet_size,ICMP_HDR &RecvIcmp){

	IPHeader *pHeader =(IPHeader *)recvBuf;
	if(packet_size<(sizeof(IPHeader) + sizeof(ICMP_HDR))){
		cout << "size is too lower" << endl;
		return false;
	}
	cout << "IP Length:" << pHeader->ipLength << endl;
	ICMP_HDR *pIcmpHeader=(ICMP_HDR *)(recvBuf+sizeof(IPHeader));
	USHORT usID,usSquNo;
	if(pIcmpHeader->icmp_type==0){//回声报文
		usID=pIcmpHeader->icmp_id;
		usSquNo=pIcmpHeader->icmp_sequence;
		cout << "回声报文" << endl;
	}else if(pIcmpHeader->icmp_type==11){//超时报文
		char *pInnerIPHdr=recvBuf+sizeof(IPHeader)+sizeof(ICMP_HDR);
		ICMP_HDR *pInnerIcmpHeadr=(ICMP_HDR *)(pInnerIPHdr+sizeof(IPHeader));
		usID=pInnerIcmpHeadr->icmp_id;
		usSquNo=pInnerIcmpHeadr->icmp_sequence;
		
		//usID=pIcmpHeader->icmp_id;
		//usSquNo=pIcmpHeader->icmp_sequence;
		
		cout << "超时报文ID:" << usID << endl;
		cout << "sdsd:" << pIcmpHeader->icmp_id <<endl;
	}else{	
		cout << "other type packet" << endl;
		return false;
	}
	if(usID!=(USHORT)GetCurrentProcessId()||usSquNo!=RecvIcmp.icmp_sequence){
		cout << "cur Id:" << (USHORT)GetCurrentProcessId() <<endl;
		
		cout << "not my packet" << endl;
		return false;
	}
	if(pIcmpHeader->icmp_type==0||pIcmpHeader->icmp_type==11){
		RecvIcmp.icmp_id=usID;
		RecvIcmp.icmp_sequence=usSquNo;
		RecvIcmp.icmp_type=pIcmpHeader->icmp_code;
		RecvIcmp.icmp_type=pIcmpHeader->icmp_type;
		RecvIcmp.icmp_timnestamp=pIcmpHeader->icmp_timnestamp;
		return true;
	}
	//struct icmp *Iicmp = (struct icmp *)(recvBuf + 2);
	
	return false;

} 
#define MaxHop 128 

int main(int argc,char *argv[]){
	if(argc!=2){
		cerr << "用法：tracert[ip or hostname]\n";
		return -1;
	}
	WSADATA wsaData;
	int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (WSAStartup(MAKEWORD(2, 2), &wsaData)!=0) {
		printf("位打开套接字\n");
		return -1;
	}
	u_long ulDestIp=inet_addr(argv[1]);
	if(ulDestIp==INADDR_NONE){
		HOSTENT* pHost=gethostbyname(argv[1]);
		if(pHost){
			ulDestIp=(*(in_addr*)pHost->h_addr).s_addr;
			cout << "通过最多" << MaxHop << "个跃点跟踪到 " << argv[1] << " 的路由" << endl;
			
		}else{
			cerr << "无法解析目标系统。" << endl;
			WSACleanup();
			return -1;
		}
	}else{
		cout << "通过最多" << MaxHop << "个跃点跟踪到 " << argv[1] << " 的路由" << endl;
	}
	sockaddr_in dst_socket_addr;
	ZeroMemory(&dst_socket_addr,sizeof(sockaddr_in));
	dst_socket_addr.sin_family=AF_INET;
	dst_socket_addr.sin_addr.S_un.S_addr=ulDestIp;
	SOCKET socket_raw=WSASocket(AF_INET,SOCK_RAW,IPPROTO_ICMP,NULL,0,WSA_FLAG_OVERLAPPED); 
	if(socket_raw==INVALID_SOCKET){
		cerr << "Create raw socket failed Error code:" << WSAGetLastError()<< endl;
		if(WSAGetLastError()==10013){
			 cerr << "Please use administer permission!" << endl;
			 return -1;
		}
	}
	int myTimeout=5;
	//设置超时时间
	setsockopt(socket_raw,SOL_SOCKET,SO_RCVTIMEO,(char *)&myTimeout,sizeof(int));
	char buff[sizeof(ICMP_HDR) + 32];  
    ICMP_HDR *pIcmp = (ICMP_HDR*)buff;  
    pIcmp->icmp_type = 8;  
    pIcmp->icmp_code = 0;  
    pIcmp->icmp_id = (USHORT)::GetCurrentProcessId();  
    pIcmp->icmp_checksum = 0;  
    pIcmp->icmp_sequence = 0;  
    memset(&buff[sizeof(ICMP_HDR)], 'E', 32);  
    //发送  
    USHORT nSeq = 0;  
    char recvBuf[1024];  
    SOCKADDR_IN from;  
    int nLen = sizeof(from);  
	bool reachDstFlag=false;
	int imaxhop=MaxHop;
	int iTTL=1;
	cout << "Target:" << inet_ntoa(dst_socket_addr.sin_addr) << endl;
    while(!reachDstFlag&&imaxhop--)  
    {  
		//设置IP数据包头的ttl字段
		setsockopt(socket_raw,IPPROTO_IP,IP_TTL,(CHAR *)&iTTL,sizeof(iTTL));
		cout << "TTL:" << iTTL << endl;
        int nRet;       
        pIcmp->icmp_checksum = 0;  
        pIcmp->icmp_timnestamp = GetTickCount();  
        pIcmp->icmp_sequence = htons(nSeq++);  
        pIcmp->icmp_checksum = checksum((USHORT*)buff, sizeof(ICMP_HDR) + 32); 
        nRet = sendto(socket_raw, buff, sizeof(ICMP_HDR) + 32, 0, (SOCKADDR*)&dst_socket_addr, sizeof(dst_socket_addr));  
        if(nRet == SOCKET_ERROR)  
        {  
            cout << "sendto error:" << WSAGetLastError() << endl;  
            return -1;  
        } 
		while(1)
		{
			nRet = recvfrom(socket_raw, recvBuf, 1024, 0, (sockaddr*)&from, &nLen);  
			if(nRet == SOCKET_ERROR)  
			{  
				if(::WSAGetLastError() == WSAETIMEDOUT)  
				{  
					cout << "time out" << endl;
					break; 
				}  
				cout << "recvfrom failed:" << WSAGetLastError() << endl;  
				return -1;
					 
			} 
			//解析  
			int nTick = GetTickCount();			
			if(nRet < sizeof(IPHeader) + sizeof(ICMP_HDR))  
			{  
				cout << "Too few bytes from " << inet_ntoa(from.sin_addr) << endl;
				break;
			}
			//ICMP_HDR retIcmp;
			IPHeader *pHeader =(IPHeader *)recvBuf;
			
			ICMP_HDR *pRecvIcmp = (ICMP_HDR*)(recvBuf + sizeof(IPHeader)); 

			//cout << "time: " << nTick - pRecvIcmp->icmp_timnestamp << " ms" << endl;  
			cout << nRet << " bytes from " << inet_ntoa(from.sin_addr)<< endl ;
			
			//判断是否是统一报文
			if(pRecvIcmp->icmp_id != (USHORT)GetCurrentProcessId())  
			{  
				break;
			}
			
			//回应报文
			if(pRecvIcmp->icmp_type==0||pRecvIcmp->icmp_type==11){
				
				if(from.sin_addr.S_un.S_addr==ulDestIp){
					cout << nRet << " bytes from " << inet_ntoa(from.sin_addr) ;  
					cout << " icmp_seq = " << pRecvIcmp->icmp_sequence ;  
					cout << " time: " << nTick - pRecvIcmp->icmp_timnestamp << " ms";  
					cout << endl; 
					reachDstFlag=true;
					break;					
				}else if(WSAGetLastError()==WSAETIMEDOUT){
					cout << setw(9) << '*' << '\t' << "请求超时" <<endl;
					break;
				}else{
					break;
				}
			}								
		}
		Sleep(1000); 
		iTTL++;
    }  
	cout << "\n追踪完成。" << endl;
	closesocket(socket_raw);
	WSACleanup();
	return 0;
}
