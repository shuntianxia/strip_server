#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h> 
#include <fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <errno.h>
#include <time.h>

#define PORT			(25)
#define SD_BOTH 		(2)
#define SOCKET_ERROR 	(-1)
#define INVALID_SOCKET 	(-1)


int sock_fd = INVALID_SOCKET;

struct hostent *ht;
#if 0
void base64_decode(unsigned char *chsrc, unsigned char *chdes)
{
	 unsigned char temp[4],t;
	 int len,i;
	 len = strlen((char *)chdes);
	 while(len>=4)
	 {
		for(i=0;i<4;i++)
	 	{
			if(*(chdes+i)>=65 && *(chdes+i)<=90) 
				temp[i] = *(chdes+i)-65;
			if(*(chdes+i)>=97 && *(chdes+i)<=122) 
				temp[i] = *(chdes+i)-71;
			if(*(chdes+i)>=48 && *(chdes+i)<=57) 
				temp[i] = *(chdes+i)+4;
			if(*(chdes+i)==43) 
				temp[i] = 62;
			if(*(chdes+i)==47) 
				temp[i] = 63;
			if(*(chdes+i)==61)
				temp[i] = 0;
		}
		t = (temp[1]>>4)&0x03;
        *chsrc = (temp[0]<<2)|t;
		t = (temp[2]>>2)&0x0f;
		*(chsrc+1) = (temp[1]<<4)|t;
		t = temp[3];
		*(chsrc+2) = (temp[2]<<6)|t;

		chsrc += 3;
		chdes += 4;
  		len   -= 4;
 	}
	chsrc -= 3;
	for(i=0;i<3;i++)
	{
		if(*(chsrc+i) == 0)
		{
			*(chsrc+i) = '\0';
			break;
		}
	}
	if(i>=2)
		*(chsrc+3) = '\0';
}
#endif


static int base64_encode(unsigned char *src,unsigned char *des)
{
	char *des_t = NULL;
	char charset[64]=
	{
                'A','B','C','D','E','F','G','H',
                'I','J','K','L','M','N','O','P',
                'Q','R','S','T','U','V','W','X',
                'Y','Z','a','b','c','d','e','f',
                'g','h','i','j','k','l','m','n',
                'o','p','q','r','s','t','u','v',
                'w','x','y','z','0','1','2','3',
                '4','5','6','7','8','9','+','/'
	};
	
	unsigned char In[3];
	unsigned char Out[4];
	int cnt = 0;
	if(!src||!des) 
		return 0;
	else
		des_t = (char *)des;
	
	for(; *src != 0; )
	{
		if(cnt+4 > 76){
			*des_t++ = '\n';
			cnt=0;
		}
		 
		 if(strlen((char*)src) >= 3)
		{
			In[0] = *src;
			In[1] = *(src+1);
			In[2] = *(src+2);
			Out[0] = In[0]>>2;
			Out[1] = (In[0]&0x03)<<4|(In[1]&0xf0)>>4;
			Out[2] = (In[1]&0x0f)<<2|(In[2]&0xc0)>>6;
			Out[3] = In[2]&0x3f;
			*des_t = charset[Out[0]];
			*(des_t+1) = charset[Out[1]];
			*(des_t+2) = charset[Out[2]];
			*(des_t+3) = charset[Out[3]];
			src += 3;
			des_t += 4;
		}
		else if(strlen((char*)src) == 1)
		{
			In[0]= *src;
			Out[0] = In[0]>>2;
			Out[1] = (In[0]&0x03)<<4|0;
			*des_t = charset[Out[0]];
			*(des_t+1) = charset[Out[1]];
			*(des_t+2) = '=';
			*(des_t+3) = '=';
			src += 1;
			des_t += 4;
		}
		else if(strlen((char*)src)==2)
		{
			In[0] = *src;
			In[1] = *(src+1);
			Out[0] = In[0]>>2;
			Out[1] = (In[0]&0x03)<<4|(In[1]&0xf0)>>4;
			Out[2] = (In[1]&0x0f)<<2|0;
			*des_t = charset[Out[0]];
			*(des_t+1) = charset[Out[1]];
			*(des_t+2) = charset[Out[2]];
			*(des_t+3)='=';
			src += 2;
			des_t += 4;
		}
		cnt+=4;
	}
	*des_t='\0';
	
	return 1;
}

static int get_response(void)
{
	int rt = -1;
	char recv_data[200] = {0};
	 rt = recv(sock_fd,recv_data, 1024, 0);
	 if(rt == SOCKET_ERROR)
	 {
		printf("receive nothing\n");
	  	return 0;
	 }
	recv_data[rt]='\0';

	 if(*recv_data == '5')
	{
		printf("the order is not support smtp host\n ");
	  	return 0;
	}
	printf("GetResponse: %s\n",recv_data);
	return 1;
}

static int create_socket(void)
{
	sock_fd = socket(AF_INET, SOCK_STREAM, 0);
	if(sock_fd == SOCKET_ERROR){
		printf("socket init error\n");
		return(0);
	}
	return 1;
}

static int conn_host(const char *host_name)
{
	int rt = -1;
	struct sockaddr_in remote;
	
	if(host_name == NULL)
		return(0);
		
	 while((ht=gethostbyname(host_name))==NULL)
	 {
		 printf("gethostbyname error");
		 return(0);
	 }
	 memset(&remote, 0, sizeof(struct sockaddr));
	 remote.sin_family = AF_INET;
	 remote.sin_port   = htons(PORT);
	 remote.sin_addr = *((struct in_addr *)ht->h_addr); 
	 bzero(&(remote.sin_zero), 8);
	 rt = connect(sock_fd, (struct sockaddr *)&remote,sizeof(struct sockaddr));
	 if(rt == SOCKET_ERROR)
	 {
		printf("connect error\n");
	  	return(0);
	 }
	 if(!get_response())
		return(0);
		
	 return 1;
}

static int log_in(char *username,char *password)
{
	 char ch[100] = {0};
	 char userdes[40] = {0}, passdes[40] = {0};
	 char *u_name, *u_pas;
	 int rt;
	 if(username == NULL || password == NULL)
		return(0);
		
	u_name = username; u_pas = password;
	base64_encode((unsigned char *)u_name, (unsigned char *)userdes);
	base64_encode((unsigned char *)u_pas, (unsigned char *)passdes);
	
	memset (ch, 0, sizeof(ch));
	sprintf(ch,"EHLO Localhost\r\n");
	rt = send(sock_fd, ch, strlen(ch), 0);
	 if(rt == SOCKET_ERROR)
		return(0);
	 if(!get_response())
		return(0);
		
	memset (ch, 0, sizeof(ch));
	sprintf(ch, "AUTH LOGIN\r\n");
	rt = send(sock_fd, ch, strlen(ch), 0);
	 if(rt == SOCKET_ERROR)
		return(0);
	 if(!get_response())
		return(0);
		
	memset (ch, 0, sizeof(ch));
	sprintf(ch, "%s\r\n", userdes);
	rt = send(sock_fd, ch, strlen(ch), 0);
	 if(rt == SOCKET_ERROR)
		return(0);
	 if(!get_response())
		return(0);
		
	memset (ch, 0, sizeof(ch));
	sprintf(ch, "%s\r\n", passdes);
	rt = send(sock_fd, ch, strlen(ch), 0);
	 if(rt == SOCKET_ERROR)
		return(0);
	 if(!get_response())
		return(0);
	
	return(1);
}


static int send_mail(const char *from, const char *to, const char *date, const char *subject, const char *content)
{
	int ret;
	char tmp_buf[200];
	if(from == NULL || to == NULL || date == NULL || subject == NULL)
  		return 0;
  		
  	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "MAIL FROM: <%s>\r\n", from);
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
	 if(!get_response())
		return(0);
		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "RCPT TO: <%s>\r\n", to);
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
	 if(!get_response())
		return(0);
		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "DATA\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
	 if(!get_response())
		return(0);
		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "From: %s\r\n", from);
	//sprintf(tmp_buf, "From: Service@PTPlug.com\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "To: %s\r\n", to);
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
/*		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "Date: %s\r\n", date);
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
*/		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "Subject: %s\r\n", subject);
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
#if 0		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "MIME-Version: 1.0\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "Content-Type: multipart/mixed;boundary=\"boundary=_zx\"\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
/*		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
*/	
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "Content-Transfer-Encoding: 7bit\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
	
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "This is a MIME Encoded Message\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
/*		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
*/		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "--boundary=_zx\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "Content-Type: text/plain; charset=us-ascii\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "Content-Transfer-Encoding: 7bit\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
#endif		
	memset (tmp_buf, 0, sizeof(tmp_buf));
	sprintf(tmp_buf, "\r\n");
	ret = send(sock_fd, tmp_buf, strlen(tmp_buf), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
	
			
	ret = send(sock_fd, (char *)content, strlen(content), 0);
	 if(ret == SOCKET_ERROR)
		return(0);

	return(1);
}

static int send_end(void)
{
	char tmp[40];
	int ret = -1;
	
	memset (tmp, 0, sizeof(tmp));
	sprintf(tmp, "\r\n");
	ret = send(sock_fd, tmp, strlen(tmp), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
		
	memset (tmp, 0, sizeof(tmp));
	sprintf(tmp, "\r\n.\r\n");
	ret = send(sock_fd, tmp, strlen(tmp), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
	if(!get_response())
		return(0);
		
	memset (tmp, 0, sizeof(tmp));
	sprintf(tmp, "QUIT\r\n");
	ret = send(sock_fd, tmp, strlen(tmp), 0);
	 if(ret == SOCKET_ERROR)
		return(0);
	if(!get_response())
		return(0);
		
	return(1);
}


int main(void)
{
	time_t timep;
	struct tm *p;
/*
 *	host：		SMTP主机，如：smtp.126.com,  mail.bestidear.net
 * 	username:	登录邮箱帐号，如：service@126.com，则 username = "service"
 *  	password:	登录邮箱的密码
 * 	m_From:	发送邮箱地址，与SMTP对应，如: host = "smtp.126.com"，则 m_From = "service@126.com"
 * 	m_To:		接收邮箱地址，如：m_To = "xxxx@163.com"
 * 	m_Subject:	邮件主题
 * 	m_txt:		邮件内容
 */
	char m_date[20] = {0};
	char *host      		= "smtp.126.com";
	char *username  	= "XXXX";
	char *password  		= "123456";
	char *m_From    		= "XXXX@126.com";
	char *m_To      		= "XXXX@163.com";
	char *m_Subject  	= "找回美排注册帐号,密码";
	char *m_txt 			= "Dear:\r\n     USER: XuPao_fu\r     PASS: fu&456789\r";
	//char *m_date 		= NULL;
	//char *m_date		= "2014-11-27 12:25:24";
	time (&timep);
	//m_date = ctime(&timep);
	p = gmtime(&timep);
	sprintf(m_date, "%d:%d:%d %d:%d:%d", (1900+p->tm_year), (1+p->tm_mon),p->tm_mday, (8+p->tm_hour), p->tm_min, p->tm_sec);
	m_date[strlen(m_date)] = '\0';
		
	if(!create_socket())
	{
		printf("socket create error\n");
		goto CLOSE_SOCKET;
	}
	printf("create the socket\n");
	
	if(!conn_host(host))
	{
		printf("can not connect the host\n");
		goto CLOSE_SOCKET;
	}
	printf("connect the smtp host\n");
	
	if(!log_in(username, password))
	{
		printf("login error\n");
		goto CLOSE_SOCKET;
	}
	printf("login OK\n");
	
	if(!send_mail(m_From, m_To, m_date, m_Subject, m_txt))
	{
		printf("send mail error\n");
		goto CLOSE_SOCKET;
	}
	printf("send mail \n");
	
	if(!send_end())
	{
		printf("End error\n");
		goto CLOSE_SOCKET;
	}
	printf("send over\n");
	
CLOSE_SOCKET:
	if(sock_fd != INVALID_SOCKET)
 	{
  		shutdown(sock_fd, SD_BOTH);
  		close(sock_fd);
  		printf("close socket\n");
 	}
 	
 	return(0);
}
