#ifndef _SEND_MAIL_H_
#define _SEND_MAIL_H_

#define SMTP_SERVER "127.0.0.1"
#define SMTP_NAME ""
#define SMTP_USER ""
#define SMTP_PWD  ""

struct mail {
	char m_date[20];
	char m_From[30];
	char m_To[30];
	char m_Subject[40];
	char m_context[80];
};

#endif /* _SEND_MAIL_H_ */