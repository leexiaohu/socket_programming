#include <iostream>
#incldue <iomanip>
#include <WINSOCK2.H>
#include <ws2tcpip.h>
#include <STDIO.H>

#pragma comment(lib,"ws2_32.lib")

using namespace std;

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
			ulDestIp=(pHost->a)
		}
	}
	return 0;
}