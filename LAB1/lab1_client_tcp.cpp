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
		SOCKET sClient;
		int iLen;//�ӷ������˽��յ����ݳ���
		char buf[100];//�������ݵĻ�����
		SOCKADDR_IN ser;//�������˵�ַ
		memset(buf, 0, sizeof(buf));//���ջ�������ʼ��
		//��дҪ���ӵķ�������ַ��Ϣ
		ser.sin_family = AF_INET;
		ser.sin_port = htons(8881);
		ser.sin_addr.s_addr = inet_addr("127.0.0.1");
		//inet_pton(AF_INET, "127.0.0.1",&ser.sin_addr.s_addr);
		//�����ͻ�����ʽ�׽ӿ�
		sClient = socket(AF_INET, SOCK_STREAM, 0);
		if (sClient == INVALID_SOCKET)
		{
			printf("socket() Failed: %d\n", WSAGetLastError());
			return -1;
		}
		//������������˽���TCP����
		if (connect(sClient, (struct sockaddr *)&ser, sizeof(ser)) == INVALID_SOCKET)
		{
			printf("connect() Failed: %d\n", WSAGetLastError());
			return -1;
		}
		else
		{
			char sendBuf[100];
			sprintf(sendBuf, "Hello Server,I am client %d", i);
			//printf("Send:%s\n", sendBuf);
			int ret=send(sClient, sendBuf, strlen(sendBuf) + 1, 0);
			if(ret==SOCKET_ERROR){
				cout << "send error:" << WSAGetLastError() << endl;
			}else{
				//�ӷ������˽�������
				iLen = recv(sClient, buf, sizeof(buf), 0);
				if (iLen == 0)
					return -1;
				else if (iLen == SOCKET_ERROR)
				{
					printf("recv() Failed: %d\n", WSAGetLastError());
					return -1;
				}
				else {
					cout << "I am  TCP Client: " << i << endl;
					cout << "Receive from server:" << buf << endl;
				}
			}
			
			
		}
		closesocket(sClient);
		Sleep(5000);
	}
	WSACleanup();
	//system("pause");
	return 0;
}