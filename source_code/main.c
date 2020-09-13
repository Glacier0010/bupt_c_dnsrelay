#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "header.h"

//全局变量
char filepath[50] = DEFAULT_FILEPATH;					//用户自己定义的配置文件地址
char dnsServerIP[16] = DEFAULT_DNS_SERVER_IPADDR;		//用户自己定义的dns服务器IP地址
int debugLevel = 0;										//调试等级，默认为0; -d为1, -dd为2

struct idProcessNode ipList[LIST_LENGTH];				//转发到外部dns的处理队列（伪队列
int ipBase = 0;											//当前偏移值

int main(int argc, char** argv) {
	WSADATA wsadata;
	SOCKET localSocket;
	SOCKADDR_IN localAddr;									//本地默认dns套接字地址
	SOCKADDR_IN dnsServerAddr;								//外部dns套接字地址
	SOCKADDR_IN clientAddr;									//用户端套接字地址

	char sendBuffer[512];									//发送缓冲区
	char recvBuffer[512];									//接收缓冲区
	struct HEADER* recvp = (struct HEADER*)malloc(sizeof(struct HEADER));
	struct QSF* recvd = (struct QSF*)malloc(sizeof(struct QSF));
	int sendLen, recvLen;									//发送/接收缓冲区长度
	int ret, sendNum;										//recvFrom/sendTo函数返回值
	unsigned short oldID, newID;							//转发到外部DNS服务器的原序号、新序号

	struct Domain_IP_Node* tableStart = (struct Domain_IP_Node*)malloc(sizeof(struct Domain_IP_Node));	//域名-IP地址对应表的表头（数据结构为链表）
	struct Domain_IP_Node* tableCurrent, * tableNew;		//域名-IP地址对应表的当前结点/新增结点
	char answerIP[16];										//查询得到的IP地址

	struct Domain_IP_Node* cache = (struct Domain_IP_Node*)malloc(sizeof(struct Domain_IP_Node));	//cache缓存
	struct Domain_IP_Node* cacheCurrent = cache;
	FILE* dpfile = fopen(CACHE_FILE, "w+");					//记录文件

	int i;													//一些辅助变量
	unsigned short temp;
	unsigned long temp2;
	enum Type t;

	time_t curtime;											//当前时间变量
	struct tm* timeinfo = (struct tm*)malloc(sizeof(struct tm));

	//基本信息输出
	printf("DNSRELAY version1.0, build in September 1st, 2020.\nUsage: dnsrelay [-d| -dd] [dns-server-ipaddr] [filename]\n");

	//根据用户输入记录更改各变量
	paraIns(argc, argv);

	if (WSAStartup(MAKEWORD(2, 2), &wsadata)) {
		printf("\nInit network protocol failed.\n");
		return -1;
	}
	else
		printf("Init socket DLL successfully.\n");

	//初始化服务器端的socket
	if ((localSocket = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
	{
		printf("Failed to create socket! Error code = %d", WSAGetLastError());
		closesocket(localSocket);
		WSACleanup();
		return -1;
	}
	else
		printf("Init local socket successfully.\n");

	localAddr.sin_family = AF_INET;
	localAddr.sin_port = htons(DEFAULT_PORT);
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);

	//绑定socket和address
	if (bind(localSocket, (SOCKADDR*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
		printf("Socket bind failed.\n");
		closesocket(localSocket);
		WSACleanup();
		return -1;
	}
	else
		printf("Socket bind successfully.\n");

	dnsServerAddr.sin_family = AF_INET;
	dnsServerAddr.sin_port = htons(DEFAULT_PORT);
	dnsServerAddr.sin_addr.s_addr = inet_addr(dnsServerIP);

	if (loadFile(tableStart) != 0) {				//如果加载文件有错误，记得断开（错误提示在函数内部）
		return -1;
	}

	if (debugLevel > 0) {
		time(&curtime);
#ifdef _WIN32
		localtime_s(timeinfo, &curtime);
#elif __unix__
		localtime_r(&curtime, timeinfo);
#endif
		printf("Current Time:%s", asctime(timeinfo));
		printf("Detailed Info in %s:\n", filepath);
		fileprint(tableStart);
	}


	//listening
	printf("\nDNS Server is listening...\n");
	while (1) {
		//清空缓冲区
		memset(recvBuffer, 0, sizeof(recvBuffer));
		memset(recvp, 0, sizeof(struct HEADER*));
		memset(recvd, 0, sizeof(struct QSF*));

		recvLen = (int)sizeof(clientAddr);
		ret = recvfrom(localSocket, recvBuffer, (int)sizeof(recvBuffer), 0, (SOCKADDR*)&clientAddr, &recvLen);
		//ret:收到的字节数
		if (ret == 0) {
			printf("Recvfrom: Disconnected!\n");
			break;
		}
		else if (ret == SOCKET_ERROR) {				//如果接收发生错误
			if (debugLevel > 0)						//且调试等级为-d及以上
				printf("Receive error!\n");
			continue;								//继续接收
		}
		else {										//无错误收到报文
			dealWithHeader(recvBuffer, recvp);			//分析报头
			dealWithContext(recvBuffer + 12, recvd, ret);	//分析报文正文中的Question Section，header占12字节			

			//输出调试信息
			switch (debugLevel) {
			case 0:						//无调试信息
				break;
			case 1:						//调试信息级别1(仅输出时间坐标，序号，客户端IP地址，查询的域名) 				
				printf("\n序号:%d\n客户端IP地址:%s\n查询的域名:%s\n", recvp->ID, inet_ntoa(localAddr.sin_addr), recvd->QNAME);
				break;
			case 2:						//调试信息级别2(输出冗长的调试信息) 
				printf("\n序号:%d\n客户端IP地址:%s\n查询的域名:%s\n", recvp->ID, inet_ntoa(localAddr.sin_addr), recvd->QNAME);
				printf("QTYPE=%d\nQCLASS=%d\n", recvd->QTYPE, recvd->QCLASS);
				printf("ID=%d\nQR=%d\nOPCODE=%d\nAA=%d\nTC=%d\nRD=%d\nRA=%d\nRCODE=%d\nQDCOUNT=%d\nANCOUNT=%d\nNSCOUNT=%d\nARCOUNT=%d\n", recvp->ID, recvp->QR, recvp->Opcode, recvp->AA, recvp->TC, recvp->RD, recvp->RA, recvp->RCODE, recvp->QDCOUNT, recvp->ANCOUNT, recvp->NSCOUNT, recvp->ARCOUNT);
				//可添加
			}

			//根据QR做出回应
			memcpy(sendBuffer, recvBuffer, ret);
			if (recvp->QR == 0) {		//如果是查询报文
				if (localFindIP(tableStart, recvd->QNAME, answerIP) == 1) {	//在本地文件中找到了
					printf("Domain found in local list.\n");										
					if (strcmp(answerIP, "0.0.0.0") == 0) {		//如果找到的结果是0.0.0.0
						printf("Error! Domain forbidden.\n");
						//更改报头第2~3字节
						temp = htons(0x8583);					//QR=1 RCODE=3
						memcpy(sendBuffer + 2, &temp, sizeof(unsigned short));

						temp = htons(0x0000);					//ANCOUNT=0
						memcpy(sendBuffer + 6, &temp, sizeof(unsigned short));
					}
					else {										//普通的正确的IP地址
						printf("%s Found.\n", answerIP);
						temp = htons(0x8580);					//QR=1					
						memcpy(sendBuffer + 2, &temp, sizeof(unsigned short));

						temp = htons(0x0001);					//ANCOUNT=1
						memcpy(sendBuffer + 6, &temp, sizeof(unsigned short));
					}
					//以上构造DNS报头

					//以下构造DNS响应RR
					//NAME：问题域的域名  
					temp = htons(0xc00c);//压缩存储，开头两个11代表指针，指向后面从报文开头的12个字节处，即域名
					memcpy(sendBuffer + ret, &temp, sizeof(unsigned short));
					sendLen = ret + 2;
					
					//TYPE=1，为IPV4
					if (judgeIPorPath(answerIP) == 0)//路径为数字和. 所以是ipv4
						t = A;
					else
						t = AAAA;
					temp = htons(t);
					memcpy(sendBuffer + sendLen, &temp, sizeof(unsigned short));
					sendLen += 2;

					//CLASS=1，为IN类型
					temp = htons(0x0001);
					memcpy(sendBuffer + sendLen, &temp, sizeof(unsigned short));
					sendLen += 2;

					//TTL不确定，保存一天, 86400s					
					temp2 = htonl(86400);
					memcpy(sendBuffer + sendLen, &temp2, sizeof(unsigned long));
					sendLen += 4;

					//RDLENGTH，到结束还需要4个字节(IPv4地址的长度) 对类型1，资源记录数是4字节的ip地址
					if (t == 1)
						temp = htons(4);
					else if (t == 28)
						temp = htons(16);
					memcpy(sendBuffer + sendLen, &temp, sizeof(unsigned short));
					sendLen += 2;

					//RDATA，inet_addr()把字符串形式的IP地址转换成unsigned long型的整数值
					if (t == 1) {
						temp2 = (unsigned long)inet_addr(answerIP);
						memcpy(sendBuffer + sendLen, &temp2, sizeof(unsigned long));
						sendLen += 4;
					}
					else if (t == 28) {
						temp2 = (unsigned long)inet_addr(answerIP);				//ipv6对应的函数好像不是这个??????
						memcpy(sendBuffer + sendLen, &temp2, 16);
						sendLen += 16;
					}
					//以上构造DNS响应RR
					//发送响应报文
					sendNum = sendto(localSocket, sendBuffer, sendLen, 0, (SOCKADDR*)&clientAddr, (int)sizeof(clientAddr));
					//若无错误发生，返回所发送数据的总数。否则的话，返回SOCKET_ERROR错误
					if (sendNum == SOCKET_ERROR) {
						if (debugLevel > 0)
							printf("Sendto: Failed to send to client! Error code = %d\n", WSAGetLastError());
						continue;
					}
					else if (sendNum == 0)
					{
						if (debugLevel > 0)
							printf("Sendto: Disconected!\n");
						break;
					}
					else if (debugLevel > 0)
						printf("Sendto: sent response to the client successfully.\n");
				}
				else {																//没有在本地文件中找到, 要转发到网上的dns服务器
					if (debugLevel > 0)												//给出relay提示
						printf("Domain NOT found in local list. Relaying...\n");

					memcpy(&oldID, recvBuffer, sizeof(unsigned short));				//获取旧ID
					
					newID = htons((unsigned short)(ipBase));						//申请新ID，确保中继DNS的id具有唯一性
					//变更中继DNS包的id，使之newID唯一,并记录oldID
					ipList[ipBase].oldID = ntohs(oldID);
					ipList[ipBase].formerClientAddr = clientAddr;
					ipList[ipBase].handled = 0;
					ipBase = (ipBase + 1) % LIST_LENGTH;							//如果超过数组长度就只能覆盖最前面的				

					//更新ID
					memcpy(recvBuffer, &newID, sizeof(unsigned short));

					//把recvBuffer转发到外部DNS服务器
					sendNum = sendto(localSocket, recvBuffer, ret, 0, (SOCKADDR*)&dnsServerAddr, sizeof(dnsServerAddr));
					
					//检查转发是否出错，并对错误进行处理
					if (sendNum == SOCKET_ERROR)
					{
						if (debugLevel > 0)
							printf("Sendto: Failed to reach DNS server! Error code = %d\n",WSAGetLastError());
						continue;
					}
					else if (sendNum == 0)
					{
						if (debugLevel > 0)
							printf("Sendto: Disconected!\n");
						break;
					}

					//完成转发，给出提示
					if (debugLevel > 0)
						printf("Sendto: Relay request to external DNS server successfully.\n");
				}
			}
			else {						//如果是从外部dns发来的响应报文
				memcpy(&newID, recvBuffer, sizeof(unsigned short));
				//i指向队列中对应序号
				i = (int)ntohs(newID) % LIST_LENGTH;
				recordCache(recvBuffer, cache, cacheCurrent, dpfile);
				//若当该query已处理，则直接跳过
				if (ipList[i].handled) {					
					continue;
				}
				else {					//若当该query未处理，获取旧ID，htons = host to net short，主机顺序转成网络顺序
					oldID = htons(ipList[i].oldID);
					ipList[i].handled = 1;
				}

				//更改响应报文头ID，发送回客户端
				memcpy(recvBuffer, &oldID, 2);

				sendNum = sendto(localSocket, recvBuffer, ret, 0, (SOCKADDR*)&ipList[i].formerClientAddr, sizeof(ipList[i].formerClientAddr));
				//检查转发是否出错，并对错误进行处理
				if (sendNum == SOCKET_ERROR)
				{
					if (debugLevel > 0)
						printf("Sendto: Failed to reach client! Error code = %d\n", WSAGetLastError());
					continue;
				}
				else if (sendNum == 0)
				{
					if (debugLevel > 0)
						printf("Sendto: Disconected!\n");
					break;
				}
				//完成转发，给出提示
				if (debugLevel > 0)
					printf("Sendto: Relay request from external DNS server to client successfully.\n");
			}
		}
	}
	fclose(dpfile);
	free(tableStart);
	free(recvd);
	free(recvp);
	free(cache);
	free(timeinfo);
	tableCurrent = tableStart;
	while (tableCurrent != NULL) {
		tableNew = tableCurrent->next;
		free(tableCurrent);
		tableCurrent = tableNew;
	}
	//关闭套接字
	closesocket(localSocket);
	WSACleanup();
	return 0;
}