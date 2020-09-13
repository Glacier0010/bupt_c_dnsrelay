#pragma once
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")		//socket编程

//#define _CRT_SECURE_NO_WARNINGS
#pragma warning(disable:4996)			//使用上述语句无法解决error 4996(vs推销strcpy_s)，直接关掉

#define DEFAULT_DNS_SERVER_IPADDR "10.3.9.4"		//默认外部dns地址
#define DEFAULT_FILEPATH		  "dnsrelay.txt"	//默认dnsrelay文件地址
#define CACHE_FILE				  "dpcache.txt"		//默认cache文件地址
#define DEFAULT_PORT 53								//DNS端口
#define LIST_LENGTH 4096							//转发队列长度

struct HEADER {
	unsigned ID : 16;							//序号
	unsigned QR : 1;							//0:查询 1:响应
	unsigned Opcode : 4;
	unsigned AA : 1;							//权威答案
	unsigned TC : 1;							//1:截断
	unsigned RD : 1;
	unsigned RA : 1;
	unsigned Z : 3;
	unsigned RCODE : 4;
	unsigned QDCOUNT : 16;						//question个数
	unsigned ANCOUNT : 16;						//answer个数
	unsigned NSCOUNT : 16;
	unsigned ARCOUNT : 16;
};

struct QSF {
	unsigned char QNAME[50];					//域名字符串
	unsigned QTYPE : 16;
	unsigned QCLASS : 16;
};

struct idProcessNode {
	short oldID;							//旧ID，只有16位
	unsigned handled : 1;					//是否处理完成，只有1位
	SOCKADDR_IN formerClientAddr;			//原客户端地址
};

struct Domain_IP_Node {						//域名-IP地址对应链表的结点
	char domain[50];
	char ip[16];
	struct Domain_IP_Node* next;
};

enum Type {									//枚举type类型
	A = 1, AAAA = 28, PTR = 12, CNAME = 5, HINFO = 13, MX = 15, NS = 2
};

//函数定义(实现在functions.c)
int judgeIPorPath(const char* temp);
void paraIns(int argc, char** argv);
int loadFile(struct Domain_IP_Node* tableStart);
void dealWithContext(char* recvContext, struct QSF* recvd, int ret);
void dealWithHeader(char* recvBuffer, struct HEADER* recvp);
int localFindIP(const struct Domain_IP_Node* tablestart, const char* domainQuery, char* answer);
void fileprint(const struct Domain_IP_Node* tablestart);
void recordCache(char* recvBuffer, struct Domain_IP_Node* cache, struct Domain_IP_Node* cacheCurrent, FILE* dpfile);
