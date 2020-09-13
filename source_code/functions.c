#include <stdio.h>
#include <string.h>
#include "header.h"

//����main.c��ȫ�ֱ���
extern char filepath[50];					
extern char dnsServerIP[16];		
extern int debugLevel;					//���Եȼ���Ĭ��Ϊ0; -dΪ1, -ddΪ2

int judgeIPorPath(const char* temp) {	//�ж��ַ�����dns������IP��ַ���������ļ�·��
	int i = 0;
	int len = strlen(temp);
	while (i < len) {					//���ȫ�����ֺ�'.'����IP��ַ, ����Ϊ�ļ�·��
		if (temp[i] == '.' || (temp[i] >= '0' && temp[i] <= '9'))
			i++;
		else return 1;					//1��ʾ���ļ�·��
	}
	return 0;							//0��ʾ��IP��ַ
}
void paraIns(int argc, char** argv) {	//����ָ����Ĳ���
	switch (argc) {
	case 1:				//dnsrelay
		break;

	case 2:				//dnsrelay [-d| -dd]/[dns-server-ipaddr]/[filename] //3ѡ1
		if (strcmp(argv[1], "-d") == 0)						//���ĵ��Եȼ�
			debugLevel = 1;
		else if (strcmp(argv[1], "-dd") == 0)
			debugLevel = 2;
		else if (judgeIPorPath(argv[1]) == 0)				//0��ʾ��IP��ַ, ��ʹ���û��Զ����dns������IP
			strcpy(dnsServerIP, argv[1]);
		else
			strcpy(filepath, argv[1]);						//����Ϊ�ļ�·��
		break;

	case 3:				//dnsrelay [-d| -dd] [dns-server-ipaddr] [filename] //3ѡ2
		if (strcmp(argv[1], "-d") == 0)						//���ĵ��Եȼ�
			debugLevel = 1;
		else if (strcmp(argv[1], "-dd") == 0)
			debugLevel = 2;
		else												//��2����������[-d| -dd]����[dns-server-ipaddr], �����ų���ǰ��
			strcpy(dnsServerIP, argv[1]);
		if (judgeIPorPath(argv[2]) == 0)					//��3����������[dns-server-ipaddr]����[filename], �����ж�һ��
			strcpy(dnsServerIP, argv[2]);
		else
			strcpy(filepath, argv[2]);
		break;

	case 4:				//dnsrelay [-d| -dd] [dns-server-ipaddr] [filename] //ȫѡ
		if (strcmp(argv[1], "-d") == 0)						//���ĵ��Եȼ�
			debugLevel = 1;
		else if (strcmp(argv[1], "-dd") == 0)
			debugLevel = 2;
		strcpy(dnsServerIP, argv[2]);						//ʹ���û��Զ����dns������IP
		strcpy(filepath, argv[3]);							//ʹ���û��Զ���������ļ�·��
		break;

	default:
		printf("Wrong instruction!\n");
	}
}
int loadFile(struct Domain_IP_Node* tableStart) {			//���ر���dnsrelay�ļ����ɹ��򷵻�0��ʧ�ܷ���-1
	struct Domain_IP_Node* tableCurrent = tableStart;		//����-IP��ַ��Ӧ��ĵ�ǰ���
	struct Domain_IP_Node* tableNew;
	
	FILE* difile = fopen(filepath, "r");					//����IP-������Ӧ�ļ�
	if (difile == NULL) {									//����ļ���ʧ��
		printf("File open error!\n");
		return -1;
	}
	if (fscanf(difile, "%s %s", tableCurrent->ip, tableCurrent->domain) == -1) {	//���ͷ����ȡʧ��
		printf("File read error!\n");
		return -1;
	}

	while (!feof(difile)) {
		tableNew = (struct Domain_IP_Node*)malloc(sizeof(struct Domain_IP_Node));
		tableCurrent->next = tableNew;
		tableCurrent = tableNew;
		if (fscanf(difile, "%s %s", tableCurrent->ip, tableCurrent->domain) == -1) {	//�����ȡʧ��, ˵���ļ�������β��
			break;
		}
	}
	tableCurrent->next = NULL;
	fclose(difile);
	printf("File load successfully.\n");
	return 0;
}
void dealWithContext(char* recvContext, struct QSF* recvd, int ret) {		//����QSF
	char tempchar = 0;
	int i = 0, j = 0;
	unsigned short temp;
	//���¿�ʼ������������:
	//ƴװ����, e.g. 3www5baidu3com0   ---->   www.baidu.com	
	while (i < ret - 12) {										//��iС�ڱ������ݳ���ʱ
		if (recvContext[i] > 0 && recvContext[i] < 64) {		//���������
			tempchar = recvContext[i];
			i++;
			while (tempchar != 0) {
				recvd->QNAME[j] = recvContext[i];
				i++;
				j++;
				tempchar--;
			}
		}
		if (recvContext[i] != 0)		//�������������0, ��ʾ������ȡ��û�н���							
			recvd->QNAME[j++] = '.';
		else {							//���ĳһλ��0, ��ʾ������ȡ����
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
void dealWithHeader(char* recvBuffer, struct HEADER* recvp) {		//������ͷ
	unsigned short temp;
	//0~1�ֽ�:ID
	memcpy(&temp, recvBuffer, sizeof(unsigned short));
	recvp->ID = ntohs(temp);

	//2�ֽ�:QR+OPCODE+AA+TC+RD, 3�ֽ�:RA+Z+RCODE, ע��С��˳��
	memcpy(&temp, recvBuffer + 2, sizeof(unsigned short));
	temp = ntohs(temp);
	recvp->RCODE = (temp & 0x01) + ((temp >> 1) & 0x01) * 2 + ((temp >> 2) & 0x01) * 4 + ((temp >> 3) & 0x01) * 8;
	recvp->Z = ((temp >> 4) & 0x01) + ((temp >> 5) & 0x01) * 2 + ((temp >> 6) & 0x01) * 4;		//Z����Ϊ0����������֤һ��
	recvp->RA = (temp >> 7) & 0x01;

	recvp->RD = (temp >> 8) & 0x01;
	recvp->TC = (temp >> 9) & 0x01;
	recvp->AA = (temp >> 10) & 0x01;
	recvp->Opcode = ((temp >> 11) & 0x01) + ((temp >> 12) & 0x01) * 2 + ((temp >> 13) & 0x01) * 4 + ((temp >> 14) & 0x01) * 8;
	recvp->QR = (temp >> 15) & 0x01;

	//4~5�ֽ�:QDCOUNT
	memcpy(&temp, recvBuffer + 4, sizeof(unsigned short));
	recvp->QDCOUNT = ntohs(temp);
	//6~7�ֽ�:ANCOUNT
	memcpy(&temp, recvBuffer + 6, sizeof(unsigned short));
	recvp->ANCOUNT = ntohs(temp);
	//8~9�ֽ�:NSCOUNT
	memcpy(&temp, recvBuffer + 8, sizeof(unsigned short));
	recvp->NSCOUNT = ntohs(temp);
	//10~11�ֽ�:ARCOUNT
	memcpy(&temp, recvBuffer + 10, sizeof(unsigned short));
	recvp->ARCOUNT = ntohs(temp);
}
//�����ļ���Ѱ��domainQuery��Ӧ��IP��ַ, �ɹ��ҵ�����1, IP����answer������; ���ɹ��򷵻�0
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
void fileprint(struct Domain_IP_Node* tablestart) {			//������ص�dnsrelay�ļ�
	struct Domain_IP_Node* temp = tablestart;
	int count = 0;
	
	while (temp != NULL) {
		printf("%d: %s %s\n", count, temp->domain, temp->ip);
		temp = temp->next;
		count++;
	}
}
//������Ӧ���ĵ����ݼ�¼��cache�ļ���
void recordCache(char* recvBuffer, struct Domain_IP_Node* cache, struct Domain_IP_Node* cacheCurrent, FILE* dpfile) {
	int nquery = ntohs(*((unsigned short*)(recvBuffer + 4))), nresponse = ntohs(*((unsigned short*)(recvBuffer + 6)));    //����������ش����
	char* p = recvBuffer + 12; //����DNS��ͷ��ָ��
	char ip[16], url[65];
	int ip1, ip2, ip3, ip4;

	//��ȡÿ��������Ĳ�ѯurl
	for (int i = 0; i < nquery; i++) {
		int len = strlen(p);
		int ii = 0, jj = 0, kk = 0;
		while (ii < len) {
			if (p[ii] > 0 && p[ii] <= 63) {//����Ǹ�����
				for (jj = p[ii], ii++; jj > 0; jj--, ii++, kk++) //j�Ǽ����Ǽ���k��Ŀ��λ���±꣬i�Ǳ�������±�
					url[kk] = p[ii];
			}

			if (p[ii] != 0) {   //���û��������dest��Ӹ�'.'			
				url[kk] = '.';
				kk++;
			}
		}
		url[kk] = '\0';
		while (*p > 0)  //��ȡ��ʶ��ǰ�ļ����������url
			p += (*p) + 1;
		p += 5; //����url�����Ϣ��ָ����һ������
	}

	if (nresponse > 0 && debugLevel >= 1)
		printf("Receive outside %s\n", url);
	//�����ظ�
	//����ο�DNS�ظ����ĸ�ʽ
	for (int i = 0; i < nresponse; i++)	{
		if ((unsigned char)*p == 0xc0) //��ָ�������
			p += 2;
		else {
			//���ݼ�������url
			while (*p > 0)
				p += (*p) + 1;
			++p;    //ָ����������
		}
		unsigned short resp_type = ntohs(*(unsigned short*)p);  //�ظ�����
		p += 2;
		unsigned short resp_class = ntohs(*(unsigned short*)p); //�ظ���
		p += 2;
		unsigned short high = ntohs(*(unsigned short*)p);   //����ʱ���λ
		p += 2;
		unsigned short low = ntohs(*(unsigned short*)p);    //����ʱ���λ
		p += 2;
		int ttl = (((int)high) << 16) | low;    //�ߵ�λ��ϳ�����ʱ��
		int datalen = ntohs(*(unsigned short*)p);   //�������ݳ���
		p += 2;
		if (debugLevel == 2)
			printf("Type %d Class %d TTL %d\n", resp_type, resp_class, ttl);

		if (resp_type == 1) {//��A���ͣ��ظ�����url��ip
			memset(ip, 0, sizeof(ip));
			//��ȡ4��ip����
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
		else p += datalen;  //ֱ������
	}
}