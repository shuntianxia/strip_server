#ifndef _SMART_STRIP_H_
#define _SMART_STRIP_H_

#include <stdbool.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include "list.h"

#define BACKLOG 5
#define MAXDATASIZE 1000
#define MAXEVENTS 64

#define THREAD_POOL_SIZE 5

#define BEACON_TIME 50

#define HASH_BITS 6
#define HASH_SIZE (1UL << HASH_BITS)
#define HASH_MASK (HASH_SIZE-1)

#define DEVID_LEN 8
#define DEVID_STR_LEN (DEVID_LEN*2 + 1)
#define MAX_BIND_DEV 10
#define IPSTR_LEN 16
#define USER_NAME_SIZE 30
#define USER_PASSWD_SIZE 30
#define MSG_BUF_SIZE 128

#define MAC2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5]
#define MACSTR "%02x:%02x:%02x:%02x:%02x:%02x"

#define DEV2STR(a) (a)[0], (a)[1], (a)[2], (a)[3], (a)[4], (a)[5], (a)[6], (a)[7]
#define DEVSTR "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x"

typedef char macaddr_t[6];
typedef unsigned char dev_id_t[DEVID_LEN];

enum user_cmd{
    CMD_USER_REG = 0xb001,
    CMD_USER_LOGIN = 0xb002,
    CMD_USER_LOGOUT = 0xb003,
    CMD_USER_BIND_DEV = 0xb004,
	CMD_USER_UNBIND_DEV = 0xb005,
    CMD_USER_LIST_DEV = 0xb006,
    CMD_USER_SELECT_DEV = 0xb007,
};

enum dev_cmd{
    CMD_DEV_ACTIVATE = 0xb101,
    CMD_DEV_LOGIN = 0xb102,
    CMD_DEV_BEACON = 0xb103,
};

typedef struct {
	int dev_num;
	int usr_num;
    struct list_head dev_list;
	struct list_head usr_list;
	pthread_mutex_t usr_list_mutex;
	pthread_mutex_t dev_list_mutex;
} glob_info_t;

typedef struct msg_s {
	int fd;
	char buf[MSG_BUF_SIZE];
	int len;
}msg_t;

typedef struct user_info_s {
	struct list_head list;
	char username[USER_NAME_SIZE];
	char passwd[USER_PASSWD_SIZE];
	int sockfd;
	bool islogin;
	int offline;
	time_t last_time;
	dev_id_t cur_dev_id;
	//struct sockaddr_in client;
	char ipaddr[IPSTR_LEN];
	msg_t msg;
	pthread_mutex_t mutex;
} user_info_t;

typedef struct dev_info_s {
    struct list_head list;
    dev_id_t dev_id;
	int sockfd;
	int offline;
	time_t last_time;
	//struct sockaddr_in client;
	char ipaddr[IPSTR_LEN];
	int cur_usr_sock;
	msg_t msg;
	pthread_mutex_t mutex;
} dev_info_t;

#endif /* _SMART_STRIP_H_ */