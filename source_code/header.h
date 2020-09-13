#pragma once
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")		//socket���

//#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)			//ʹ����������޷����error 4996(vs����strcpy_s)��ֱ�ӹص�

#define DEFAULT_DNS_SERVER_IPADDR "10.3.9.4"		//Ĭ���ⲿdns��ַ
#define DEFAULT_FILEPATH		  "dnsrelay.txt"	//Ĭ��dnsrelay�ļ���ַ
#define CACHE_FILE				  "dpcache.txt"		//Ĭ��cache�ļ���ַ
#define DEFAULT_PORT 53								//DNS�˿�
#define LIST_LENGTH 4096							//ת�����г���

struct HEADER {
	unsigned ID : 16;							//���
	unsigned QR : 1;							//0:��ѯ 1:��Ӧ
	unsigned Opcode : 4;
	unsigned AA : 1;							//Ȩ����
	unsigned TC : 1;							//1:�ض�
	unsigned RD : 1;
	unsigned RA : 1;
	unsigned Z : 3;
	unsigned RCODE : 4;
	unsigned QDCOUNT : 16;						//question����
	unsigned ANCOUNT : 16;						//answer����
	unsigned NSCOUNT : 16;
	unsigned ARCOUNT : 16;
};

struct QSF {
	unsigned char QNAME[50];					//�����ַ���
	unsigned QTYPE : 16;
	unsigned QCLASS : 16;
};

struct idProcessNode {
	short oldID;							//��ID��ֻ��16λ
	unsigned handled : 1;					//�Ƿ�����ɣ�ֻ��1λ
	SOCKADDR_IN formerClientAddr;			//ԭ�ͻ��˵�ַ
};

struct Domain_IP_Node {						//����-IP��ַ��Ӧ����Ľ��
	char domain[50];
	char ip[16];
	struct Domain_IP_Node* next;
};

enum Type {									//ö��type����
	A = 1, AAAA = 28, PTR = 12, CNAME = 5, HINFO = 13, MX = 15, NS = 2
};

//��������(ʵ����functions.c)
int judgeIPorPath(const char* temp);
void paraIns(int argc, char** argv);
int loadFile(struct Domain_IP_Node* tableStart);
void dealWithContext(char* recvContext, struct QSF* recvd, int ret);
void dealWithHeader(char* recvBuffer, struct HEADER* recvp);
int localFindIP(const struct Domain_IP_Node* tablestart, const char* domainQuery, char* answer);
void fileprint(const struct Domain_IP_Node* tablestart);
void recordCache(char* recvBuffer, struct Domain_IP_Node* cache, struct Domain_IP_Node* cacheCurrent, FILE* dpfile);
