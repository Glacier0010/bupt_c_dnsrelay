#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "header.h"

//ȫ�ֱ���
char filepath[50] = DEFAULT_FILEPATH;					//�û��Լ�����������ļ���ַ
char dnsServerIP[16] = DEFAULT_DNS_SERVER_IPADDR;		//�û��Լ������dns������IP��ַ
int debugLevel = 0;										//���Եȼ���Ĭ��Ϊ0; -dΪ1, -ddΪ2

struct idProcessNode ipList[LIST_LENGTH];				//ת�����ⲿdns�Ĵ�����У�α����
int ipBase = 0;											//��ǰƫ��ֵ

int main(int argc, char** argv) {
	WSADATA wsadata;
	SOCKET localSocket;
	SOCKADDR_IN localAddr;									//����Ĭ��dns�׽��ֵ�ַ
	SOCKADDR_IN dnsServerAddr;								//�ⲿdns�׽��ֵ�ַ
	SOCKADDR_IN clientAddr;									//�û����׽��ֵ�ַ

	char sendBuffer[512];									//���ͻ�����
	char recvBuffer[512];									//���ջ�����
	struct HEADER* recvp = (struct HEADER*)malloc(sizeof(struct HEADER));
	struct QSF* recvd = (struct QSF*)malloc(sizeof(struct QSF));
	int sendLen, recvLen;									//����/���ջ���������
	int ret, sendNum;										//recvFrom/sendTo��������ֵ
	unsigned short oldID, newID;							//ת�����ⲿDNS��������ԭ��š������

	struct Domain_IP_Node* tableStart = (struct Domain_IP_Node*)malloc(sizeof(struct Domain_IP_Node));	//����-IP��ַ��Ӧ��ı�ͷ�����ݽṹΪ����
	struct Domain_IP_Node* tableCurrent, * tableNew;		//����-IP��ַ��Ӧ��ĵ�ǰ���/�������
	char answerIP[16];										//��ѯ�õ���IP��ַ

	struct Domain_IP_Node* cache = (struct Domain_IP_Node*)malloc(sizeof(struct Domain_IP_Node));	//cache����
	struct Domain_IP_Node* cacheCurrent = cache;
	FILE* dpfile = fopen(CACHE_FILE, "w+");					//��¼�ļ�

	int i;													//һЩ��������
	unsigned short temp;
	unsigned long temp2;
	enum Type t;

	time_t curtime;											//��ǰʱ�����
	struct tm* timeinfo = (struct tm*)malloc(sizeof(struct tm));

	//������Ϣ���
	printf("DNSRELAY version1.0, build in September 1st, 2020.\nUsage: dnsrelay [-d| -dd] [dns-server-ipaddr] [filename]\n");

	//�����û������¼���ĸ�����
	paraIns(argc, argv);

	if (WSAStartup(MAKEWORD(2, 2), &wsadata)) {
		printf("\nInit network protocol failed.\n");
		return -1;
	}
	else
		printf("Init socket DLL successfully.\n");

	//��ʼ���������˵�socket
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

	//��socket��address
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

	if (loadFile(tableStart) != 0) {				//��������ļ��д��󣬼ǵöϿ���������ʾ�ں����ڲ���
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
		//��ջ�����
		memset(recvBuffer, 0, sizeof(recvBuffer));
		memset(recvp, 0, sizeof(struct HEADER*));
		memset(recvd, 0, sizeof(struct QSF*));

		recvLen = (int)sizeof(clientAddr);
		ret = recvfrom(localSocket, recvBuffer, (int)sizeof(recvBuffer), 0, (SOCKADDR*)&clientAddr, &recvLen);
		//ret:�յ����ֽ���
		if (ret == 0) {
			printf("Recvfrom: Disconnected!\n");
			break;
		}
		else if (ret == SOCKET_ERROR) {				//������շ�������
			if (debugLevel > 0)						//�ҵ��Եȼ�Ϊ-d������
				printf("Receive error!\n");
			continue;								//��������
		}
		else {										//�޴����յ�����
			dealWithHeader(recvBuffer, recvp);			//������ͷ
			dealWithContext(recvBuffer + 12, recvd, ret);	//�������������е�Question Section��headerռ12�ֽ�			

			//���������Ϣ
			switch (debugLevel) {
			case 0:						//�޵�����Ϣ
				break;
			case 1:						//������Ϣ����1(�����ʱ�����꣬��ţ��ͻ���IP��ַ����ѯ������) 				
				printf("\n���:%d\n�ͻ���IP��ַ:%s\n��ѯ������:%s\n", recvp->ID, inet_ntoa(localAddr.sin_addr), recvd->QNAME);
				break;
			case 2:						//������Ϣ����2(����߳��ĵ�����Ϣ) 
				printf("\n���:%d\n�ͻ���IP��ַ:%s\n��ѯ������:%s\n", recvp->ID, inet_ntoa(localAddr.sin_addr), recvd->QNAME);
				printf("QTYPE=%d\nQCLASS=%d\n", recvd->QTYPE, recvd->QCLASS);
				printf("ID=%d\nQR=%d\nOPCODE=%d\nAA=%d\nTC=%d\nRD=%d\nRA=%d\nRCODE=%d\nQDCOUNT=%d\nANCOUNT=%d\nNSCOUNT=%d\nARCOUNT=%d\n", recvp->ID, recvp->QR, recvp->Opcode, recvp->AA, recvp->TC, recvp->RD, recvp->RA, recvp->RCODE, recvp->QDCOUNT, recvp->ANCOUNT, recvp->NSCOUNT, recvp->ARCOUNT);
				//�����
			}

			//����QR������Ӧ
			memcpy(sendBuffer, recvBuffer, ret);
			if (recvp->QR == 0) {		//����ǲ�ѯ����
				if (localFindIP(tableStart, recvd->QNAME, answerIP) == 1) {	//�ڱ����ļ����ҵ���
					printf("Domain found in local list.\n");										
					if (strcmp(answerIP, "0.0.0.0") == 0) {		//����ҵ��Ľ����0.0.0.0
						printf("Error! Domain forbidden.\n");
						//���ı�ͷ��2~3�ֽ�
						temp = htons(0x8583);					//QR=1 RCODE=3
						memcpy(sendBuffer + 2, &temp, sizeof(unsigned short));

						temp = htons(0x0000);					//ANCOUNT=0
						memcpy(sendBuffer + 6, &temp, sizeof(unsigned short));
					}
					else {										//��ͨ����ȷ��IP��ַ
						printf("%s Found.\n", answerIP);
						temp = htons(0x8580);					//QR=1					
						memcpy(sendBuffer + 2, &temp, sizeof(unsigned short));

						temp = htons(0x0001);					//ANCOUNT=1
						memcpy(sendBuffer + 6, &temp, sizeof(unsigned short));
					}
					//���Ϲ���DNS��ͷ

					//���¹���DNS��ӦRR
					//NAME�������������  
					temp = htons(0xc00c);//ѹ���洢����ͷ����11����ָ�룬ָ�����ӱ��Ŀ�ͷ��12���ֽڴ���������
					memcpy(sendBuffer + ret, &temp, sizeof(unsigned short));
					sendLen = ret + 2;
					
					//TYPE=1��ΪIPV4
					if (judgeIPorPath(answerIP) == 0)//·��Ϊ���ֺ�. ������ipv4
						t = A;
					else
						t = AAAA;
					temp = htons(t);
					memcpy(sendBuffer + sendLen, &temp, sizeof(unsigned short));
					sendLen += 2;

					//CLASS=1��ΪIN����
					temp = htons(0x0001);
					memcpy(sendBuffer + sendLen, &temp, sizeof(unsigned short));
					sendLen += 2;

					//TTL��ȷ��������һ��, 86400s					
					temp2 = htonl(86400);
					memcpy(sendBuffer + sendLen, &temp2, sizeof(unsigned long));
					sendLen += 4;

					//RDLENGTH������������Ҫ4���ֽ�(IPv4��ַ�ĳ���) ������1����Դ��¼����4�ֽڵ�ip��ַ
					if (t == 1)
						temp = htons(4);
					else if (t == 28)
						temp = htons(16);
					memcpy(sendBuffer + sendLen, &temp, sizeof(unsigned short));
					sendLen += 2;

					//RDATA��inet_addr()���ַ�����ʽ��IP��ַת����unsigned long�͵�����ֵ
					if (t == 1) {
						temp2 = (unsigned long)inet_addr(answerIP);
						memcpy(sendBuffer + sendLen, &temp2, sizeof(unsigned long));
						sendLen += 4;
					}
					else if (t == 28) {
						temp2 = (unsigned long)inet_addr(answerIP);				//ipv6��Ӧ�ĺ������������??????
						memcpy(sendBuffer + sendLen, &temp2, 16);
						sendLen += 16;
					}
					//���Ϲ���DNS��ӦRR
					//������Ӧ����
					sendNum = sendto(localSocket, sendBuffer, sendLen, 0, (SOCKADDR*)&clientAddr, (int)sizeof(clientAddr));
					//���޴��������������������ݵ�����������Ļ�������SOCKET_ERROR����
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
				else {																//û���ڱ����ļ����ҵ�, Ҫת�������ϵ�dns������
					if (debugLevel > 0)												//����relay��ʾ
						printf("Domain NOT found in local list. Relaying...\n");

					memcpy(&oldID, recvBuffer, sizeof(unsigned short));				//��ȡ��ID
					
					newID = htons((unsigned short)(ipBase));						//������ID��ȷ���м�DNS��id����Ψһ��
					//����м�DNS����id��ʹ֮newIDΨһ,����¼oldID
					ipList[ipBase].oldID = ntohs(oldID);
					ipList[ipBase].formerClientAddr = clientAddr;
					ipList[ipBase].handled = 0;
					ipBase = (ipBase + 1) % LIST_LENGTH;							//����������鳤�Ⱦ�ֻ�ܸ�����ǰ���				

					//����ID
					memcpy(recvBuffer, &newID, sizeof(unsigned short));

					//��recvBufferת�����ⲿDNS������
					sendNum = sendto(localSocket, recvBuffer, ret, 0, (SOCKADDR*)&dnsServerAddr, sizeof(dnsServerAddr));
					
					//���ת���Ƿ�������Դ�����д���
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

					//���ת����������ʾ
					if (debugLevel > 0)
						printf("Sendto: Relay request to external DNS server successfully.\n");
				}
			}
			else {						//����Ǵ��ⲿdns��������Ӧ����
				memcpy(&newID, recvBuffer, sizeof(unsigned short));
				//iָ������ж�Ӧ���
				i = (int)ntohs(newID) % LIST_LENGTH;
				recordCache(recvBuffer, cache, cacheCurrent, dpfile);
				//������query�Ѵ�����ֱ������
				if (ipList[i].handled) {					
					continue;
				}
				else {					//������queryδ������ȡ��ID��htons = host to net short������˳��ת������˳��
					oldID = htons(ipList[i].oldID);
					ipList[i].handled = 1;
				}

				//������Ӧ����ͷID�����ͻؿͻ���
				memcpy(recvBuffer, &oldID, 2);

				sendNum = sendto(localSocket, recvBuffer, ret, 0, (SOCKADDR*)&ipList[i].formerClientAddr, sizeof(ipList[i].formerClientAddr));
				//���ת���Ƿ�������Դ�����д���
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
				//���ת����������ʾ
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
	//�ر��׽���
	closesocket(localSocket);
	WSACleanup();
	return 0;
}