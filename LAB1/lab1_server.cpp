#include <WinSock2.h>
#include <iostream>
#include <stdio.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <vector>
#include <algorithm>

#pragma comment(lib,"ws2_32.lib")

#define SERVER_UDP_PORT 8880
#define SERVER_TCP_PORT 8881

using namespace std;

int main()
{
	//创建套接字
	WORD myVersionRequest;
	WSADATA wsaData;
	myVersionRequest = MAKEWORD(2, 2);
	int err;
	vector<int> read_sockets;
	err = WSAStartup(myVersionRequest, &wsaData);
	if (!err) {
		//printf("已打开套接字\n");
	}
	else {
		printf("ERROR:套接字未打开!");
		return 1;
	}
	
	//绑定套接字tcp
	SOCKET socket_serv_tcp = socket(AF_INET, SOCK_STREAM, 0);//创建了可识别套接字
	SOCKADDR_IN addr_tcp;
	addr_tcp.sin_family = AF_INET;
	addr_tcp.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//ip地址
	addr_tcp.sin_port = htons(SERVER_TCP_PORT);//绑定端口

	bind(socket_serv_tcp, (SOCKADDR*)&addr_tcp, sizeof(SOCKADDR));//绑定完成
	listen(socket_serv_tcp, 10);//其中第二个参数代表能够接收的最多的连接数
	//绑定套接字udp
	SOCKET socket_serv_udp = socket(AF_INET, SOCK_DGRAM, 0);//创建了可识别套接字
	SOCKADDR_IN addr_udp;
	addr_udp.sin_family = AF_INET;
	addr_udp.sin_addr.S_un.S_addr = htonl(INADDR_ANY);//ip地址
	//addr_udp.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr_udp.sin_port = htons(SERVER_UDP_PORT);//绑定端口

	bind(socket_serv_udp, (SOCKADDR*)&addr_udp, sizeof(SOCKADDR));//绑定完成

	SOCKADDR_IN clientsocket;
	int len = sizeof(clientsocket);

	fd_set readfds;
	read_sockets.push_back(socket_serv_tcp);
	read_sockets.push_back(socket_serv_udp);
	struct timeval tv = { 2, 0 };
	while (1)
	{
		int fd;
		FD_ZERO(&readfds);
		for(int i=0;i<read_sockets.size();i++){
			FD_SET(read_sockets[i],&readfds);
		}
		cout << "Server waiting!" << endl;

		int result = select(FD_SETSIZE, &readfds, (fd_set *)0, (fd_set *)0, 0);
		if(result<0)
		{
			cout<<"Faild Select()"<<endl;
			exit(-1);
		}
		else if(result ==0)
		{
			//cout<<"time out()"<<endl;
			continue;
		}
		else{
			for (int index = 0;index < read_sockets.size();index++) {
				fd=read_sockets[index];
				if (FD_ISSET(fd, &readfds)) {
					
					SOCKADDR_IN clientsocket_tcp;
					if (fd == socket_serv_tcp) {//tcp连接请求
						SOCKET serConn = accept(socket_serv_tcp, (SOCKADDR*)&clientsocket_tcp, &len);
						bind(serConn, (SOCKADDR*)&clientsocket_tcp, sizeof(SOCKADDR));
						read_sockets.push_back(serConn);
						cout << "accepted a tcp connection!" << endl;
						
					}
					else if (fd == socket_serv_udp) {//udp连接请求
						char *sendBuffer;
						char recvBuffer[100];				
						int result = recvfrom(socket_serv_udp, recvBuffer, sizeof(recvBuffer),0,
							(sockaddr *)&clientsocket, &len);
						cout << "Received message form UDP client:\n"
							<< recvBuffer <<endl;
						sendBuffer = "hello client,I am server!";
						sendto(socket_serv_udp, sendBuffer,strlen(sendBuffer)+1,0,
							(sockaddr *)&clientsocket, len);
						
					}
					else {//新建的tcp连接
						
						char receiveBuf[100];//接收
						int ret=recv(fd, receiveBuf, sizeof(receiveBuf), 0);
						if(ret <= 0)
						{
							cout<<"client closed! "<< endl;
							closesocket(fd);
							vector<int>::iterator it=find(read_sockets.begin(),read_sockets.end(),fd);
							read_sockets.erase(it);
							break;
						}
						
						else {
							cout << "Received message form TCP client:\n"
								<< receiveBuf << endl;
							char sendBuf[100]="hello client,I am server!\n";
							send(fd, sendBuf, strlen(sendBuf) + 1, 0);
							
						}
						
					}
				}
					
			}
			
		}		
	}
	for(int i=0;i<read_sockets.size();i++){
		closesocket(read_sockets[i]);
	}
	WSACleanup();//释放资源的操作
	system("pause");
    return 0;
}