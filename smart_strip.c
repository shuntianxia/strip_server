#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/types.h>
#include <pthread.h>
#include <assert.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>

#include "list.h"
#include "work_queue.h"
#include "net_interface.h"
#include "db_interface.h"
#include "daemon.h"
#include "smart_strip.h"

//static struct list_head dev_hashtable[HASH_SIZE];
static struct list_head dev_list;
static struct list_head user_list;
static pthread_mutex_t dev_list_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t user_list_lock = PTHREAD_MUTEX_INITIALIZER;
static int exit_flag;

static int usr_efd, dev_efd;
static int pfd[2];
static work_queue_t *work_queue;

#ifdef USE_MACADDR
static bool mac_addr_cmp(macaddr_t addr1, macaddr_t addr2)
{
	int i;
	char *p = (char *)addr1;
	char *q = (char *)addr2;
	for(i=0; i<6; i++){
		if(*p++ != *q++)
			return false;
		}
	return true;
}
#endif

static bool dev_id_cmp(dev_id_t devid1, dev_id_t devid2)
{
	int i;
	char *p = (char *)devid1;
	char *q = (char *)devid2;
	for(i=0; i<DEVID_LEN; i++){
		if(*p++ != *q++)
			return false;
		}
	return true;
}

static user_info_t *find_user_by_sock(int sockfd)
{
    user_info_t *pos;
	//pthread_mutex_lock(&user_list_lock);
    list_for_each_entry(pos, &user_list, list) {
        if (sockfd == pos->sockfd) {
			//pthread_mutex_unlock(&user_list_lock);
            return pos;
        }
    }
	//pthread_mutex_unlock(&user_list_lock);
    return NULL;
}

static dev_info_t *find_dev_by_sock(int sockfd)
{
    dev_info_t *pos;
	//pthread_mutex_lock(&dev_list_lock);
    list_for_each_entry(pos, &dev_list, list) {
        if (sockfd == pos->sockfd) {
			//pthread_mutex_unlock(&dev_list_lock);
            return pos;
        }
    }
	//pthread_mutex_unlock(&dev_list_lock);
    return NULL;
}

static dev_info_t *find_dev_by_id(dev_id_t dev_id)
{
    dev_info_t *pos;
	//pthread_mutex_lock(&dev_list_lock);
    list_for_each_entry(pos, &dev_list, list) {
        if (dev_id_cmp(dev_id, pos->dev_id)) {
			//pthread_mutex_unlock(&dev_list_lock);
            return pos;
        }
    }
	//pthread_mutex_unlock(&dev_list_lock);
    return NULL;
}

static int get_dev_status(dev_id_t dev_id)
{
    dev_info_t *pos;
	int online_flag;
	pthread_mutex_lock(&dev_list_lock);
    list_for_each_entry(pos, &dev_list, list) {
        if (dev_id_cmp(dev_id, pos->dev_id)) {
			if(pos->offline == 0) {
				online_flag = 1;
			}
			else {
				online_flag = 0;
			}
			pthread_mutex_unlock(&dev_list_lock);
            return online_flag;
        }
    }
	online_flag = 0;
	pthread_mutex_unlock(&dev_list_lock);
    return online_flag;
}

static void *dev_session_destroy(dev_info_t *dev)
{
	if(dev != NULL) {
		pthread_mutex_lock(&dev->mutex);
		printf ("Closed dev connon descriptor %d\n", dev->sockfd);
		close(dev->sockfd);
		dev_logout_verify(dev->dev_id);
		list_del_init(&dev->list);
		pthread_mutex_unlock(&dev->mutex);
		pthread_mutex_destroy(&dev->mutex);
		free(dev);
	}
	return NULL;
}

static void *user_session_destroy(user_info_t *user)
{
	if(user != NULL) {
		pthread_mutex_lock(&user->mutex);
		printf ("Closed user conn on descriptor %d\n", user->sockfd);
		close(user->sockfd);
		list_del_init(&user->list);
		pthread_mutex_unlock(&user->mutex);
		pthread_mutex_destroy(&user->mutex);
		free(user);
	}
	return NULL;
}

static void check_dev_online(void)
{
    dev_info_t *pos, *n;
	printf("in check_dev_online function\n");
	pthread_mutex_lock(&dev_list_lock);
    list_for_each_entry_safe(pos, n, &dev_list, list) {
		//pthread_mutex_lock(&pos->mutex);
		if (pos->offline >= 3) {
			printf("device "DEVSTR" is offline too long, destroy it now.\n", DEV2STR(pos->dev_id));
			dev_session_destroy(pos);
		}
		else if (pos->offline > 0) {
			pthread_mutex_lock(&pos->mutex);
			printf("device "DEVSTR" maybe is offline, offline=%d .\n", DEV2STR(pos->dev_id), pos->offline);
			pos->offline++;
			pthread_mutex_unlock(&pos->mutex);
		}
		else if (pos->offline == 0) {
			pthread_mutex_lock(&pos->mutex);
			printf("device "DEVSTR" is online.\n", DEV2STR(pos->dev_id));
			pos->offline++;
			pthread_mutex_unlock(&pos->mutex);
		}
		//pthread_mutex_unlock(&pos->mutex);
    }
	pthread_mutex_unlock(&dev_list_lock);
}

static void check_user_online(void)
{
    user_info_t *pos, *n;
	printf("in check_user_online function\n");
	pthread_mutex_lock(&user_list_lock);
    list_for_each_entry_safe(pos, n, &user_list, list) {
		if (pos->offline >= 3) {
			printf("user is offline too long, destroy it now. descriptor %d\n", pos->sockfd);
			user_session_destroy(pos);
		}
		else if (pos->offline > 0) {
			pthread_mutex_lock(&pos->mutex);
			printf("user maybe is offline, descriptor %d, offline=%d .\n", pos->sockfd, pos->offline);
			pos->offline++;
			pthread_mutex_unlock(&pos->mutex);
		}
		else if (pos->offline == 0) {
			pthread_mutex_lock(&pos->mutex);
			printf("user is online. descriptor %d.\n", pos->sockfd);
			pos->offline++;
			pthread_mutex_unlock(&pos->mutex);
		}
    }
	pthread_mutex_unlock(&user_list_lock);
}

static void *online_check(void *arg)
{
	int i;
	while(!exit_flag)
	{
		for(i = 0; i < 3; i++) {
			sleep(BEACON_TIME);
			if(exit_flag)
				break;
			check_dev_online();
		}
		check_user_online();		
	}
	return NULL;
}

static void destroy_user_list()
{
	user_info_t *pos, *n;
	
	printf("release all user session resource.\n");
	pthread_mutex_lock(&user_list_lock);
    list_for_each_entry_safe(pos, n, &user_list, list) {
		user_session_destroy(pos);
    }
	pthread_mutex_unlock(&user_list_lock);
}

static void destroy_dev_list()
{
	dev_info_t *pos, *n;
	
	printf("release all device session resource.\n");
	pthread_mutex_lock(&dev_list_lock);
    list_for_each_entry_safe(pos, n, &dev_list, list) {
		dev_session_destroy(pos);
    }
	pthread_mutex_unlock(&dev_list_lock);
}

typedef struct new_conn_s {
	struct sockaddr in_addr;
	int sockfd;
}new_conn_t;

static void* dev_conn_process(void *arg)
{
	int ret;
	struct epoll_event event;
	dev_info_t *new_dev;
	new_conn_t *new_conn = (new_conn_t *)arg;
	socklen_t in_len = sizeof(struct sockaddr);
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	
	ret = getnameinfo (&new_conn->in_addr, in_len,
				   hbuf, sizeof hbuf,
				   sbuf, sizeof sbuf,
				   NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret == 0)
	{
		printf("Accepted connection on descriptor %d "
				"(host=%s, port=%s)\n", new_conn->sockfd, hbuf, sbuf);
	}
	if((new_dev = malloc(sizeof(dev_info_t))) == NULL) {
		close(new_conn->sockfd);
		free(new_conn);
		return NULL;
	}
	new_dev->sockfd = new_conn->sockfd;
	new_dev->cur_usr_sock = -1;
	new_dev->offline = 0;
	memset(new_dev->dev_id, 0, sizeof(new_dev->dev_id));
	memcpy(new_dev->ipaddr, hbuf, IPSTR_LEN);
	pthread_mutex_init(&new_dev->mutex, NULL);
	
	pthread_mutex_lock(&dev_list_lock);
	list_add_tail(&new_dev->list, &dev_list);
	pthread_mutex_unlock(&dev_list_lock);
	
	/* Make the incoming socket non-blocking and add it to the
		list of fds to monitor. */
	ret = set_non_blocking(new_conn->sockfd);
	if (ret == -1)
		abort ();
	event.data.fd = new_conn->sockfd;
	event.events = EPOLLIN | EPOLLET;
	ret = epoll_ctl(dev_efd, EPOLL_CTL_ADD, new_conn->sockfd, &event);
	if (ret == -1)
	{
		perror ("epoll_ctl");
		abort ();
	}
	free(new_conn);
	return NULL;
}

static void *dev_disconn_process(void *arg)
{
	int sockfd = *((int *)arg);
	free(arg);
	pthread_mutex_lock(&dev_list_lock);
	dev_info_t *dev = find_dev_by_sock(sockfd);
	if(dev != NULL) {
		dev_session_destroy(dev);
	}
	else {
		close(sockfd);
	}
	pthread_mutex_unlock(&dev_list_lock);
	return NULL;
}

static void *user_conn_process(void *arg)
{
	int ret;
	struct epoll_event event;
	user_info_t *new_user;
	new_conn_t *new_conn = (new_conn_t *)arg;
	socklen_t in_len = sizeof(struct sockaddr);
	char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
	
	ret = getnameinfo (&new_conn->in_addr, in_len,
				   hbuf, sizeof hbuf,
				   sbuf, sizeof sbuf,
				   NI_NUMERICHOST | NI_NUMERICSERV);
	if (ret == 0)
	{
		printf("Accepted connection on descriptor %d "
				"(host=%s, port=%s)\n", new_conn->sockfd, hbuf, sbuf);
	}
	if((new_user = malloc(sizeof(user_info_t))) == NULL) {
		close(new_conn->sockfd);
		free(new_conn);
		return NULL;
	}
	new_user->sockfd = new_conn->sockfd;
	new_user->offline = 0;
	new_user->islogin = false;
	memset(new_user->username, 0, sizeof(new_user->username));
	memset(new_user->passwd, 0, sizeof(new_user->passwd));
	memcpy(new_user->ipaddr, hbuf, IPSTR_LEN);
	pthread_mutex_init(&new_user->mutex, NULL);
	
	pthread_mutex_lock(&user_list_lock);
	list_add_tail(&new_user->list, &user_list);
	pthread_mutex_unlock(&user_list_lock);
	
	/* Make the incoming socket non-blocking and add it to the
		list of fds to monitor. */
	ret = set_non_blocking(new_conn->sockfd);
	if (ret == -1)
		abort ();
	event.data.fd = new_conn->sockfd;
	event.events = EPOLLIN | EPOLLET;
	ret = epoll_ctl(usr_efd, EPOLL_CTL_ADD, new_conn->sockfd, &event);
	if (ret == -1)
	{
		perror ("epoll_ctl");
		abort ();
	}
	free(new_conn);
	return NULL;
}

static void *user_disconn_process(void *arg)
{
	int sockfd = *((int *)arg);
	free(arg);
	pthread_mutex_lock(&user_list_lock);
	user_info_t *user = find_user_by_sock(sockfd);
	if(user != NULL) {
		user_session_destroy(user);
	}
	else {
		close(sockfd);
	}
	pthread_mutex_unlock(&user_list_lock);
	return NULL;
}

static void *dev_msg_parse(void *device)
{
	dev_info_t *dev = (dev_info_t *)device;
	struct epoll_event event;
	char sendbuf[256] = {0};
	int ret;
	dev_id_t dev_id = {0};
	msg_t *msg = &(dev->msg);
	char *p = msg->buf;
	char *q = sendbuf;
	unsigned short cmd_head = (*p << 8) | *(p+1);
	int len = 0;
	memcpy(sendbuf, p, 2);
					
	if((cmd_head >> 8) == 0xb1)
	{
		printf("cmd is %4x \n", cmd_head);
		switch(cmd_head)
		{
			case CMD_DEV_ACTIVATE:
				memcpy(dev_id, p+2, 8);
				printf("dev_id is "DEVSTR"\n", DEV2STR(dev_id));
				if((ret = dev_activate(dev_id)) == 0)
				{
					*(q+2) = 0;
				}else{
					*(q+2) = 1;
				}
				len = 3;
				memcpy(msg->buf, sendbuf, len);
				msg->len = len;
				event.data.ptr = msg;
				event.events = EPOLLOUT | EPOLLET;  
				epoll_ctl(dev_efd, EPOLL_CTL_MOD, msg->fd, &event);
				
				break;

			case CMD_DEV_LOGIN:
				memcpy(dev_id, p+2, 8);
				//printf("cmd is %4x \n", cmd_head);
				printf("dev_id is "DEVSTR"\n", DEV2STR(dev_id));
				memcpy(dev->dev_id, dev_id, 8);
				pthread_mutex_lock(&dev_list_lock);
				dev_info_t *old_dev = find_dev_by_id(dev_id);
				if(old_dev != NULL && old_dev->sockfd != dev->sockfd) {
					dev_session_destroy(old_dev);
				}
				pthread_mutex_unlock(&dev_list_lock);
				if((ret = dev_login_verify(dev)) == 0)
				{
					*(q+2) = 0;
				} else {
					*(q+2) = 1;
				}
				len = 3;
				memcpy(msg->buf, sendbuf, len);
				msg->len = len;
				event.data.ptr = msg;
				event.events = EPOLLOUT | EPOLLET;  
				epoll_ctl(dev_efd, EPOLL_CTL_MOD, msg->fd, &event);
				
				break;

			case CMD_DEV_BEACON:
				printf("dev_beacon_msg\n");
				len = 2;
				memcpy(msg->buf, sendbuf, len);
				msg->len = len;
				event.data.ptr = msg;
				event.events = EPOLLOUT | EPOLLET;  
				epoll_ctl(dev_efd, EPOLL_CTL_MOD, msg->fd, &event);

				break;			

			default:
				break;
		}
	}
	else if((cmd_head >> 8) == 0xbd || (cmd_head >> 8) == 0xbe)
	{
		pthread_mutex_lock(&user_list_lock);
		user_info_t *user = find_user_by_sock(dev->cur_usr_sock);
		if(user != NULL)
		{
			printf("msg is reply to user, src_dev_sock is %d, dst_usr_sock is %d.\n", dev->sockfd, user->sockfd);
			pthread_mutex_lock(&user->mutex);
			msg->fd = user->sockfd;
			pthread_mutex_unlock(&user->mutex);
			event.data.ptr = msg;
			event.events = EPOLLOUT | EPOLLET;  
			epoll_ctl(usr_efd, EPOLL_CTL_MOD, msg->fd, &event);
		}
		else {
			printf("can not find user whos sockfd is %d, maybe he is offline", dev->cur_usr_sock);
		}
		pthread_mutex_unlock(&user_list_lock);
	}
	return NULL;
}



static void *dev_event_loop(void *arg)
{
	int lis_dev_fd;
	int ret;
	struct epoll_event event;
	struct epoll_event *events;

	lis_dev_fd = create_and_bind(DEV_PORT);
	if(lis_dev_fd == -1)
		abort();
	ret = set_non_blocking(lis_dev_fd);
	if(ret == -1)
		abort();
	ret = listen(lis_dev_fd, BACKLOG);
	if (ret == -1)
    {
		perror ("listen");
		abort ();
	}
	dev_efd = epoll_create(256);
	if (dev_efd == -1)
    {
		perror ("epoll_create");
		abort ();
    }
	event.data.fd = pfd[0];
	event.events = EPOLLIN | EPOLLET;
	ret = epoll_ctl(dev_efd, EPOLL_CTL_ADD, pfd[0], &event);
	if (ret == -1)
    {
		perror ("epoll_ctl");
		abort ();
    }
	event.data.fd = lis_dev_fd;
	event.events = EPOLLIN | EPOLLET;
	ret = epoll_ctl(dev_efd, EPOLL_CTL_ADD, lis_dev_fd, &event);
	if (ret == -1)
    {
		perror ("epoll_ctl");
		abort ();
    }
	/* Buffer where events are returned */
	events = calloc(MAXEVENTS, sizeof(event));

	/* The event loop */
	while (!exit_flag)
    {
		int n, i;
		n = epoll_wait(dev_efd, events, MAXEVENTS, -1);
		for (i = 0; i < n; i++)
		{
			if (pfd[0] == events[i].data.fd) {
				printf("dev_event_loop: pfd[0] event\n");
				break;
			}/*
			else if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP))
			{
				// An error has occured on this fd, or the socket is not
				//ready for reading (why were we notified then?) 
				fprintf(stderr, "epoll error\n");
				//close(events[i].data.fd);
				int *sockptr = malloc(sizeof(int));
				*sockptr = events[i].data.fd;
				queue_add_work(work_queue, dev_disconn_process,(void *)sockptr);
				continue;
			}*/
			else if (lis_dev_fd == events[i].data.fd)
        	{
				/* We have a notification on the listening socket, which
				means one or more incoming connections. */
				while (1)
                {
					struct sockaddr in_addr;
					socklen_t in_len;
					int infd;
					new_conn_t *new_conn;
					//char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];

					in_len = sizeof(in_addr);
					infd = accept(lis_dev_fd, &in_addr, &in_len);
						   //accept(listenfd, (struct sockaddr *)&client, (socklen_t*)&sin_size));
					if (infd == -1)
                    {
						if ((errno == EAGAIN) ||
							(errno == EWOULDBLOCK))
						{
							/* We have processed all incoming
							connections. */
							break;
						}
						else
						{
							perror ("accept");
							break;
						}
					}
					if((new_conn = malloc(sizeof(new_conn_t))) != NULL) {
						memcpy(&new_conn->in_addr, &in_addr, sizeof(in_addr));
						new_conn->sockfd = infd;
						queue_add_work(work_queue, dev_conn_process, (void *)new_conn);
					}
				}
				continue;
			}
			else if (events[i].events & EPOLLIN)
			{
				/* We have data on the fd waiting to be read. Read and 
				display it. We must read whatever data is available 
				completely, as we are running in edge-triggered mode 
				and won't get a notification again for the same 
				data. */  
				int done = 0;  
  
				while (1)  
                {  
					ssize_t count;  
					char buf[512];
					dev_info_t *dev;
  
					count = read (events[i].data.fd, buf, sizeof(buf));  
					if (count == -1)  
                    {  
						/* If errno == EAGAIN, that means we have read all 
							data. So go back to the main loop. */  
                      if (errno != EAGAIN)  
                        {  
                          perror ("read");  
                          done = 1;  
                        }  
						break;  
					}  
					else if (count == 0)  
                    {  
						/* End of file. The remote has closed the 
						connection. */  
						done = 1;  
						break;  
                    }
					int fd = events[i].data.fd;
					if((dev = find_dev_by_sock(fd)) != NULL) {
						pthread_mutex_lock(&dev->mutex);
						dev->offline = 0;
						pthread_mutex_unlock(&dev->mutex);
						msg_t *msg = &(dev->msg);
						//msg_t *msg = malloc(sizeof(msg_t));
						memcpy(msg->buf, buf, (count > sizeof(msg->buf))?sizeof(msg->buf):count);
						msg->fd = fd;
						msg->len = count;
						event.data.ptr = msg;
						//dev_msg_parse(dev);
						queue_add_work(work_queue, dev_msg_parse, (void *)dev);
					}					
					//event.events = EPOLLOUT | EPOLLET;  
					//epoll_ctl(dev_efd, EPOLL_CTL_MOD, fd, &event);
                }  
  
				if (done)  
                {
					int *sockptr = malloc(sizeof(int));
					*sockptr = events[i].data.fd;
					queue_add_work(work_queue, dev_disconn_process,(void *)sockptr);
                }
            }
			else if(events[i].events & EPOLLOUT)
			{
				msg_t *msg = (msg_t *)events[i].data.ptr;
				int fd = msg->fd;
				send(fd, msg->buf, msg->len, 0);
				//free(msg);
				event.data.fd = fd;
				event.events = EPOLLIN | EPOLLET;  
				epoll_ctl(dev_efd, EPOLL_CTL_MOD, fd, &event);
				break;
			}
			else
			{
			
			}
        }
    }
	destroy_dev_list();
	free(events);
	close(lis_dev_fd);
	return NULL;
}

static void *user_msg_parse(void *usr)
{
#if 0
	user_info_t *user = (user_info_t *)usr;
	char buf[200] = {0};
	sprintf(buf,"HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\n%s","Hello world!\n");
	send(user->sockfd, buf, strlen(buf), 0);
#endif
	user_info_t *user = (user_info_t *)usr;
	struct epoll_event event;
	char sendbuf[128];
	char buf[(DEVID_LEN + 1) * MAX_BIND_DEV];
	char email[30] = {0};
	int ret;
	int i;
	dev_id_t dev_id;
	msg_t *msg = &(user->msg);
	//char *p = recvbuf;
	char *p = msg->buf;
	char *q = sendbuf;
	unsigned short cmd_head = (*p << 8) | *(p+1);
	int len = 0;
	memcpy(sendbuf, p, 2);
	
	if((cmd_head >> 8) == 0xb0)
	{
		switch(cmd_head)
		{
			case CMD_USER_REG:
				memset(user->username, 0, sizeof(user->username));
				memset(user->passwd, 0, sizeof(user->passwd));
				memcpy(user->username, p+5, *(p+2));
				memcpy(user->passwd, p+5+*(p+2), *(p+3));
				memcpy(email, p+5+*(p+2)+*(p+3), *(p+4));
				printf("username: %s, password: %s, email: %s\n", user->username, user->passwd, email);
				if((ret = user_account_register(user->username, user->passwd, email)) == 0)
				{
					*(q+2) = 0;
				}else{
					*(q+2) = 1;
				}
				len = 3;
				memcpy(msg->buf, sendbuf, len);
				msg->len = len;
				event.data.ptr = msg;
				event.events = EPOLLOUT | EPOLLET;  
				epoll_ctl(usr_efd, EPOLL_CTL_MOD, msg->fd, &event);

				break;

			case CMD_USER_LOGIN:
				memset(user->username, 0, sizeof(user->username));
				memset(user->passwd, 0, sizeof(user->passwd));
				memcpy(user->username, p+4, *(p+2));
				memcpy(user->passwd, p+4+*(p+2), *(p+3));
				printf("client send username: %s, password: %s\n", user->username, user->passwd);
				if((ret = user_login_verify(user)) == 0)
				{
					*(q+2) = 0;
					user->islogin = true;
				} else {
					*(q+2) = 1;
				}
				len = 3;
				memcpy(msg->buf, sendbuf, len);
				msg->len = len;
				event.data.ptr = msg;
				event.events = EPOLLOUT | EPOLLET;  
				epoll_ctl(usr_efd, EPOLL_CTL_MOD, msg->fd, &event);

				break;

			case CMD_USER_LOGOUT:
				user->islogin = false;
				len = 2;
				memcpy(msg->buf, sendbuf, len);
				msg->len = len;
				event.data.ptr = msg;
				event.events = EPOLLOUT | EPOLLET;  
				epoll_ctl(usr_efd, EPOLL_CTL_MOD, msg->fd, &event);

				break;

			case CMD_USER_BIND_DEV:
				//dev_id = buf_to_long(p+2);
				memcpy(dev_id, p+2, 8);
				printf("CMD_USER_BIND_DEV dev_id is "DEVSTR"\n", DEV2STR(dev_id));
				*(q+2) = 1;
				if(user->islogin) {
					if((ret = user_bind_dev(user->username, dev_id)) == 0) {
						*(q+2) = 0;
					}
				}
				len = 3;
				memcpy(msg->buf, sendbuf, len);
				msg->len = len;
				event.data.ptr = msg;
				event.events = EPOLLOUT | EPOLLET;  
				epoll_ctl(usr_efd, EPOLL_CTL_MOD, msg->fd, &event);
				break;
				
			case CMD_USER_UNBIND_DEV:
				memcpy(dev_id, p+2, 8);
				printf("CMD_USER_UNBIND_DEV dev_id is "DEVSTR"\n", DEV2STR(dev_id));
				*(q+2) = 1;
				if(user->islogin) {
					if((ret = user_unbind_dev(user->username, dev_id)) == 0) {
						printf("user_unbind_dev return success\n");
						*(q+2) = 0;
					}
				}
				len = 3;
				memcpy(msg->buf, sendbuf, len);
				msg->len = len;
				event.data.ptr = msg;
				event.events = EPOLLOUT | EPOLLET;  
				epoll_ctl(usr_efd, EPOLL_CTL_MOD, msg->fd, &event);
				break;

			case CMD_USER_LIST_DEV:
				if(user->islogin) {
					if((ret = user_list_dev(user->username, buf)) >= 0) {
						*(q+2) = 0;
						*(q+3) = ret;
						for(i = 0; i < ret; i++) {
							//dev_id = (dev_id_t)(q + 4 + 9 * i);
							//memcpy(dev_id, q + 4 + 9 * i, sizeof(dev_id));
							*(q + 12 + 9 * i) = get_dev_status((unsigned char *)(q + 4 + 9 * i));
						}
						memcpy(q+4, buf, ret * (DEVID_LEN + 1));
						len = 4 + ret * (DEVID_LEN + 1);
					}
				}
				else {
					*(q+2) = 1;
					len = 3;
				}
				memcpy(msg->buf, sendbuf, len);
				msg->len = len;
				event.data.ptr = msg;
				event.events = EPOLLOUT | EPOLLET;  
				epoll_ctl(usr_efd, EPOLL_CTL_MOD, msg->fd, &event);
				break;

			case CMD_USER_SELECT_DEV:
				if(user->islogin == false) {
					*(q+2) = 1;
					printf("can't select device, you did not login\n");
				} else {
					memcpy(dev_id, p+2, 8);
					memcpy(user->cur_dev_id, dev_id, DEVID_LEN);
					pthread_mutex_lock(&dev_list_lock);
					dev_info_t *dev = find_dev_by_id(dev_id);
					pthread_mutex_unlock(&dev_list_lock);
					if(dev != NULL) {
						//pthread_mutex_lock(&user->mutex);
						//pthread_mutex_unlock(&user->mutex);
						printf("select device succeed, dev_id is "DEVSTR"\n", DEV2STR(user->cur_dev_id));
						*(q+2) = 0;
					}
					else {
						*(q+2) = 1;
						printf("select device failed, device not online\n");
					}
				}
				len = 3;
				memcpy(msg->buf, sendbuf, len);
				msg->len = len;
				event.data.ptr = msg;
				event.events = EPOLLOUT | EPOLLET;  
				epoll_ctl(usr_efd, EPOLL_CTL_MOD, msg->fd, &event);
				break;

			default:
				break;
		}
		
	}
	else if((cmd_head >> 8) == 0xbd || (cmd_head >> 8) == 0xbe || (cmd_head >> 8) == 0xb1)
	{
		if(user->islogin == false) {
			printf("can't ctrl device, you did not login\n");
			return NULL;
		}
		pthread_mutex_lock(&dev_list_lock);
		dev_info_t *dev = find_dev_by_id(user->cur_dev_id);
		if(dev != NULL)
		{
			printf("msg destination is device, src_usr_sock is %d, dst_dev_sock is %d.\n", user->sockfd, dev->sockfd);
			pthread_mutex_lock(&dev->mutex);
			dev->cur_usr_sock = user->sockfd;
			pthread_mutex_unlock(&dev->mutex);
			msg->fd = dev->sockfd;
			event.data.ptr = msg;
			event.events = EPOLLOUT | EPOLLET;  
			epoll_ctl(dev_efd, EPOLL_CTL_MOD, msg->fd, &event);
		}
		else {
			printf("cann't transfer to device "DEVSTR", maybe is offline\n", DEV2STR(user->cur_dev_id));
		}
		pthread_mutex_unlock(&dev_list_lock);
	}
	return NULL;
}

static void *user_event_loop(void *arg)
{
	int lis_usr_fd;
	int ret;
	struct epoll_event event;
	struct epoll_event *events;

	lis_usr_fd = create_and_bind(USER_PORT);
	if (lis_usr_fd == -1)
		abort ();
	ret = set_non_blocking (lis_usr_fd);
	if (ret == -1)
		abort ();
	ret = listen(lis_usr_fd, BACKLOG);
	if (ret == -1)
    {
		perror ("listen");
		abort ();
	}	
	usr_efd = epoll_create1(0);
	if (usr_efd == -1)
    {
		perror ("epoll_create");
		abort ();
    }
	event.data.fd = pfd[0];
	event.events = EPOLLIN | EPOLLET;
	ret = epoll_ctl(usr_efd, EPOLL_CTL_ADD, pfd[0], &event);
	if (ret == -1)
    {
		perror ("user epoll_ctl");
		abort ();
    }
	event.data.fd = lis_usr_fd;
	event.events = EPOLLIN | EPOLLET;
	ret = epoll_ctl(usr_efd, EPOLL_CTL_ADD, lis_usr_fd, &event);
	if (ret == -1)
    {
		perror ("user epoll_ctl");
		abort ();
    }

	/* Buffer where events are returned */
	events = calloc(MAXEVENTS, sizeof(event));

	/* The event loop */
	while (!exit_flag)
    {
		int n, i;
		n = epoll_wait(usr_efd, events, MAXEVENTS, -1);
		for (i = 0; i < n; i++)
		{
			if (pfd[0] == events[i].data.fd) {
				printf("user_event_loop: pfd[0] event\n");
				break;
			}/*
			else if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP))
			{
				//An error has occured on this fd, or the socket is not
				//ready for reading (why were we notified then?) 
				fprintf (stderr, "epoll error\n");
				//close(events[i].data.fd);
				int *sockptr = malloc(sizeof(int));
				*sockptr = events[i].data.fd;
				queue_add_work(work_queue, user_disconn_process,(void *)sockptr);
				continue;
			}*/
			else if (lis_usr_fd == events[i].data.fd)
        	{
				/* We have a notification on the listening socket, which
				means one or more incoming connections. */
				while (1)
                {
					struct sockaddr in_addr;
					socklen_t in_len;
					int infd;
					new_conn_t *new_conn;
					in_len = sizeof(in_addr);
					infd = accept(lis_usr_fd, &in_addr, &in_len);
						   //accept(listenfd, (struct sockaddr *)&client, (socklen_t*)&sin_size));
					if (infd == -1)
                    {
						if ((errno == EAGAIN) ||
							(errno == EWOULDBLOCK))
						{
							/* We have processed all incoming
							connections. */
							break;
						}
						else
						{
							perror ("accept");
							break;
						}
					}
					if((new_conn = malloc(sizeof(new_conn_t))) != NULL) {
						memcpy(&new_conn->in_addr, &in_addr, sizeof(in_addr));
						new_conn->sockfd = infd;
						queue_add_work(work_queue, user_conn_process, (void *)new_conn);
					}
				}
				continue;
			}
			else if(events[i].events & EPOLLIN)
			{
				/* We have data on the fd waiting to be read. Read and 
				display it. We must read whatever data is available 
				completely, as we are running in edge-triggered mode 
				and won't get a notification again for the same 
				data. */  
				int done = 0;  
  
				while (1)  
                {  
					ssize_t count;  
					char buf[512];
					user_info_t *user;
  
					count = read (events[i].data.fd, buf, sizeof(buf));  
					if (count == -1)  
                    {  
						/* If errno == EAGAIN, that means we have read all 
							data. So go back to the main loop. */  
                      if (errno != EAGAIN)  
                        {  
                          perror ("read");  
                          done = 1;  
                        }  
						break;  
					}  
					else if (count == 0)  
                    {  
						/* End of file. The remote has closed the 
						connection. */  
						done = 1;  
						break;  
                    }
					int fd = events[i].data.fd;
					if((user = find_user_by_sock(fd)) != NULL) {
						pthread_mutex_lock(&user->mutex);
						user->offline = 0;
						pthread_mutex_unlock(&user->mutex);
						msg_t *msg = &(user->msg);
						//msg_t *msg = malloc(sizeof(msg_t));
						memcpy(msg->buf, buf, (count > sizeof(msg->buf))?sizeof(msg->buf):count);
						msg->fd = fd;
						msg->len = count;
						event.data.ptr = msg;
						//dev_msg_parse(dev);
						queue_add_work(work_queue, user_msg_parse, (void *)user);
					}
					
					//event.events = EPOLLOUT | EPOLLET;  
					//epoll_ctl(dev_efd, EPOLL_CTL_MOD, fd, &event);
                }  
  
				if (done)  
                {
					int *sockptr = malloc(sizeof(int));
					*sockptr = events[i].data.fd;
					queue_add_work(work_queue, user_disconn_process,(void *)sockptr);
                }
            }
			else if(events[i].events & EPOLLOUT)
			{  
				msg_t *msg = (msg_t *)events[i].data.ptr;
				send(msg->fd, msg->buf, msg->len, 0);
				event.data.fd = msg->fd;
				printf("msg->fd is %d\n", msg->fd);
				event.events = EPOLLIN | EPOLLET;
				epoll_ctl(usr_efd, EPOLL_CTL_MOD, msg->fd, &event);
			}
			else
			{

			}
        }
    }
	destroy_user_list();
	free (events);
	close (lis_usr_fd);
	return NULL;
}

void sigint(int signo)
{
	printf("got SIGINT\n");
	exit_flag = 1;
	close(pfd[1]);
}

int main (int argc, char *argv[])
{
	struct sigaction sa;

	if(already_running()) {
		printf("The server is already running\n");
		exit(1);
	}
	
	sa.sa_handler = sigint;
	sigemptyset(&sa.sa_mask);
	sigaddset(&sa.sa_mask, SIGINT);
	sa.sa_flags = 0;
	if (sigaction(SIGINT, &sa, NULL) < 0) {
		printf("can't catch SIGINT: %s\n", strerror(errno));
		exit(1);
	}
	
	if (pipe(pfd) < 0) {
		perror("pipe");
		exit(1);
	}
	
	INIT_LIST_HEAD(&dev_list);
	INIT_LIST_HEAD(&user_list);
	
	work_queue = work_queue_init(THREAD_POOL_SIZE);
	queue_add_work(work_queue, dev_event_loop, NULL);
	queue_add_work(work_queue, user_event_loop, NULL);

	online_check(NULL);

	work_queue_destroy(work_queue);
	
	close(pfd[0]);
	
	return EXIT_SUCCESS;
}
