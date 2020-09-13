#include <stdio.h>
#include <string.h>
#include "header.h"

//引用main.c的全局变量
extern char filepath[50];					
extern char dnsServerIP[16];		
extern int debugLevel;					//调试等级，默认为0; -d为1, -dd为2

int judgeIPorPath(const char* temp) {	//判断字符串是dns服务器IP地址还是配置文件路径
	int i = 0;
	int len = strlen(temp);
	while (i < len) {					//如果全是数字和'.'就是IP地址, 否则为文件路径
		if (temp[i] == '.' || (temp[i] >= '0' && temp[i] <= '9'))
			i++;
		else return 1;					//1表示是文件路径
	}
	return 0;							//0表示是IP地址
}
void paraIns(int argc, char** argv) {	//分析指令，更改参数
	switch (argc) {
	case 1:				//dnsrelay
		break;

	case 2:				//dnsrelay [-d| -dd]/[dns-server-ipaddr]/[filename] //3选1
		if (strcmp(argv[1], "-d") == 0)						//更改调试等级
			debugLevel = 1;
		else if (strcmp(argv[1], "-dd") == 0)
			debugLevel = 2;
		else if (judgeIPorPath(argv[1]) == 0)				//0表示是IP地址, 则使用用户自定义的dns服务器IP
			strcpy(dnsServerIP, argv[1]);
		else
			strcpy(filepath, argv[1]);						//否则为文件路径
		break;

	case 3:				//dnsrelay [-d| -dd] [dns-server-ipaddr] [filename] //3选2
		if (strcmp(argv[1], "-d") == 0)						//更改调试等级
			debugLevel = 1;
		else if (strcmp(argv[1], "-dd") == 0)
			debugLevel = 2;
		else												//第2个参数不是[-d| -dd]就是[dns-server-ipaddr], 现在排除了前者
			strcpy(dnsServerIP, argv[1]);
		if (judgeIPorPath(argv[2]) == 0)					//第3个参数不是[dns-server-ipaddr]就是[filename], 现在判断一下
			strcpy(dnsServerIP, argv[2]);
		else
			strcpy(filepath, argv[2]);
		break;

	case 4:				//dnsrelay [-d| -dd] [dns-server-ipaddr] [filename] //全选
		if (strcmp(argv[1], "-d") == 0)						//更改调试等级
			debugLevel = 1;
		else if (strcmp(argv[1], "-dd") == 0)
			debugLevel = 2;
		strcpy(dnsServerIP, argv[2]);						//使用用户自定义的dns服务器IP
		strcpy(filepath, argv[3]);							//使用用户自定义的配置文件路径
		break;

	default:
		printf("Wrong instruction!\n");
	}
}
int loadFile(struct Domain_IP_Node* tableStart) {			//加载本地dnsrelay文件，成功则返回0，失败返回-1
	struct Domain_IP_Node* tableCurrent = tableStart;		//域名-IP地址对应表的当前结点
	struct Domain_IP_Node* tableNew;
	
	FILE* difile = fopen(filepath, "r");					//加载IP-域名对应文件
	if (difile == NULL) {									//如果文件打开失败
		printf("File open error!\n");
		return -1;
	}
	if (fscanf(difile, "%s %s", tableCurrent->ip, tableCurrent->domain) == -1) {	//如果头结点读取失败
		printf("File read error!\n");
		return -1;
	}

	while (!feof(difile)) {
		tableNew = (struct Domain_IP_Node*)malloc(sizeof(struct Domain_IP_Node));
		tableCurrent->next = tableNew;
		tableCurrent = tableNew;
		if (fscanf(difile, "%s %s", tableCurrent->ip, tableCurrent->domain) == -1) {	//如果读取失败, 说明文件读到结尾了
			break;
		}
	}
	tableCurrent->next = NULL;
	fclose(difile);
	printf("File load successfully.\n");
	return 0;
}
void dealWithContext(char* recvContext, struct QSF* recvd, int ret) {		//处理QSF
	char tempchar = 0;
	int i = 0, j = 0;
	unsigned short temp;
	//以下开始分析报文内容:
	//拼装域名, e.g. 3www5baidu3com0   ---->   www.baidu.com	
	while (i < ret - 12) {										//当i小于报文内容长度时
		if (recvContext[i] > 0 && recvContext[i] < 64) {		//如果是数字
			tempchar = recvContext[i];
			i++;
			while (tempchar != 0) {
				recvd->QNAME[j] = recvContext[i];
				i++;
				j++;
				tempchar--;
			}
		}
		if (recvContext[i] != 0)		//如果接下来不是0, 表示域名读取还没有结束							
			recvd->QNAME[j++] = '.';
		else {							//如果某一位是0, 表示域名读取结束
			i++;
			recvd->QNAME[j++] = '\0';
			break;
		}
	}
	memcpy(&temp, recvContext + i, sizeof(unsigned short));			//QTYPE
	recvd->QTYPE = ntohs(temp);
	memcpy(&temp, recvContext + i + 2, sizeof(unsigned short));		//QCLASS
	recvd->QCLASS = ntohs(temp);
}
void dealWithHeader(char* recvBuffer, struct HEADER* recvp) {		//分析报头
	unsigned short temp;
	//0~1字节:ID
	memcpy(&temp, recvBuffer, sizeof(unsigned short));
	recvp->ID = ntohs(temp);

	//2字节:QR+OPCODE+AA+TC+RD, 3字节:RA+Z+RCODE, 注意小端顺序
	memcpy(&temp, recvBuffer + 2, sizeof(unsigned short));
	temp = ntohs(temp);
	recvp->RCODE = (temp & 0x01) + ((temp >> 1) & 0x01) * 2 + ((temp >> 2) & 0x01) * 4 + ((temp >> 3) & 0x01) * 8;
	recvp->Z = ((temp >> 4) & 0x01) + ((temp >> 5) & 0x01) * 2 + ((temp >> 6) & 0x01) * 4;		//Z总是为0，但计算验证一下
	recvp->RA = (temp >> 7) & 0x01;

	recvp->RD = (temp >> 8) & 0x01;
	recvp->TC = (temp >> 9) & 0x01;
	recvp->AA = (temp >> 10) & 0x01;
	recvp->Opcode = ((temp >> 11) & 0x01) + ((temp >> 12) & 0x01) * 2 + ((temp >> 13) & 0x01) * 4 + ((temp >> 14) & 0x01) * 8;
	recvp->QR = (temp >> 15) & 0x01;

	//4~5字节:QDCOUNT
	memcpy(&temp, recvBuffer + 4, sizeof(unsigned short));
	recvp->QDCOUNT = ntohs(temp);
	//6~7字节:ANCOUNT
	memcpy(&temp, recvBuffer + 6, sizeof(unsigned short));
	recvp->ANCOUNT = ntohs(temp);
	//8~9字节:NSCOUNT
	memcpy(&temp, recvBuffer + 8, sizeof(unsigned short));
	recvp->NSCOUNT = ntohs(temp);
	//10~11字节:ARCOUNT
	memcpy(&temp, recvBuffer + 10, sizeof(unsigned short));
	recvp->ARCOUNT = ntohs(temp);
}
//本地文件中寻找domainQuery对应的IP地址, 成功找到返回1, IP放在answer参数里; 不成功则返回0
int localFindIP(const struct Domain_IP_Node* tablestart, const char* domainQuery, char* answer) {
	struct Domain_IP_Node* temp = tablestart;
	while (temp != NULL) {
		if (strcmp(temp->domain, domainQuery) == 0) {
			strcpy(answer, temp->ip);
			return 1;
		}
		else
			temp = temp->next;
	}
	return 0;
}
void fileprint(struct Domain_IP_Node* tablestart) {			//输出加载的dnsrelay文件
	struct Domain_IP_Node* temp = tablestart;
	int count = 0;
	
	while (temp != NULL) {
		printf("%d: %s %s\n", count, temp->domain, temp->ip);
		temp = temp->next;
		count++;
	}
}
//将新响应报文的内容记录到cache文件里
void recordCache(char* recvBuffer, struct Domain_IP_Node* cache, struct Domain_IP_Node* cacheCurrent, FILE* dpfile) {
	int nquery = ntohs(*((unsigned short*)(recvBuffer + 4))), nresponse = ntohs(*((unsigned short*)(recvBuffer + 6)));    //问题个数；回答个数
	char* p = recvBuffer + 12; //跳过DNS包头的指针
	char ip[16], url[65];
	int ip1, ip2, ip3, ip4;

	//读取每个问题里的查询url
	for (int i = 0; i < nquery; i++) {
		int len = strlen(p);
		int ii = 0, jj = 0, kk = 0;
		while (ii < len) {
			if (p[ii] > 0 && p[ii] <= 63) {//如果是个计数
				for (jj = p[ii], ii++; jj > 0; jj--, ii++, kk++) //j是计数是几，k是目标位置下标，i是报文里的下标
					url[kk] = p[ii];
			}

			if (p[ii] != 0) {   //如果没结束就在dest里加个'.'			
				url[kk] = '.';
				kk++;
			}
		}
		url[kk] = '\0';
		while (*p > 0)  //读取标识符前的计数跳过这个url
			p += (*p) + 1;
		p += 5; //跳过url后的信息，指向下一个报文
	}

	if (nresponse > 0 && debugLevel >= 1)
		printf("Receive outside %s\n", url);
	//分析回复
	//具体参考DNS回复报文格式
	for (int i = 0; i < nresponse; i++)	{
		if ((unsigned char)*p == 0xc0) //是指针就跳过
			p += 2;
		else {
			//根据计数跳过url
			while (*p > 0)
				p += (*p) + 1;
			++p;    //指向后面的内容
		}
		unsigned short resp_type = ntohs(*(unsigned short*)p);  //回复类型
		p += 2;
		unsigned short resp_class = ntohs(*(unsigned short*)p); //回复类
		p += 2;
		unsigned short high = ntohs(*(unsigned short*)p);   //生存时间高位
		p += 2;
		unsigned short low = ntohs(*(unsigned short*)p);    //生存时间低位
		p += 2;
		int ttl = (((int)high) << 16) | low;    //高低位组合成生存时间
		int datalen = ntohs(*(unsigned short*)p);   //后面数据长度
		p += 2;
		if (debugLevel == 2)
			printf("Type %d Class %d TTL %d\n", resp_type, resp_class, ttl);

		if (resp_type == 1) {//是A类型，回复的是url的ip
			memset(ip, 0, sizeof(ip));
			//读取4个ip部分
			ip1 = (unsigned char)*p++;
			ip2 = (unsigned char)*p++;
			ip3 = (unsigned char)*p++;
			ip4 = (unsigned char)*p++;

			sprintf(ip, "%d.%d.%d.%d", ip1, ip2, ip3, ip4);
			if (debugLevel >= 2)
				printf("ip %d.%d.%d.%d\n", ip1, ip2, ip3, ip4);

			strcpy(cacheCurrent->ip, ip);
			strcpy(cacheCurrent->domain, url);
			fprintf(dpfile, "%s %s\n", ip, url);
			struct Domain_IP_Node* cacheNew = (struct Domain_IP_Node*)malloc(sizeof(struct Domain_IP_Node));
			cacheCurrent->next = cacheNew;
			cacheCurrent = cacheNew;				

			break;
		}
		else p += datalen;  //直接跳过
	}
}