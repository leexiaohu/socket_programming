#include <WinSock2.h>
#include <iostream>
#include <stdio.h>
#include <WS2tcpip.h>
#include <Windows.h>

using namespace std;
#pragma comment(lib,"ws2_32.lib")

#define SERVER_UDP_PORT 8880
#define SERVER_TCP_PORT 8881

int main()
{
	
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("Failed to load Winsock.\n");
		return -1;
	}
	for (int i = 0;i < 100;i++) {
		SOCKET socket_serv_udp;
		int iLen;
		
		SOCKADDR_IN socket_addr;					
		socket_addr.sin_family = AF_INET;
		socket_addr.sin_port = htons(8880);
		socket_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		//inet_pton(AF_INET, "127.0.0.1", &socket_addr.sin_addr.s_addr);
		socket_serv_udp = socket(AF_INET, SOCK_DGRAM, 0);
		int len = sizeof(socket_addr);
		if (socket_serv_udp == INVALID_SOCKET)
		{
			printf("socket() Failed: %d\n", WSAGetLastError());
			return -1;
		}
		cout << "I am  UDP Client: " << i << endl;
		char sendBuffer[100];
		sprintf(sendBuffer,"Hello server,I am UDP client %d!",i);
		sendto(socket_serv_udp, sendBuffer, strlen(sendBuffer)+1, 0,
			(sockaddr *)&socket_addr,len);
		char recvBuffer[100];
		int result = recvfrom(socket_serv_udp, recvBuffer, sizeof(recvBuffer), 0,
			(sockaddr *)&socket_addr, &len);
		
		cout << "Receive from server:" << recvBuffer << endl;
		closesocket(socket_serv_udp);
		Sleep(3000);
	}
	WSACleanup();
	return 0;
}