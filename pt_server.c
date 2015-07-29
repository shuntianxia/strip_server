#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/time.h>
#include <sys/wait.h>

#include "list.h"
#define SERVER_U
#include "pt_server.h"

#define QLEN     5
#define BUFSIZE  1024
#define CMDROW   3
#define CMDLINE  20

#define HASH_BITS       6
#define HASH_SIZE       (1UL << HASH_BITS)
#define HASH_MASK       (HASH_SIZE-1)
 
static struct list_head plug_dev_hashtable[HASH_SIZE];

pthread_mutex_t client_list_mutex, glob_info_mutex;

/*
 *msg_process_work-receive message, handle it and  send back
 * @sock    : new socket address
 * @Returns
 *     NULL
 */
void *dev_login_process(void *sock)
{
    int new_socket;
    int mode;
    int msglen;
    client_info_t *client;
	dev_info_t *new_dev;
    char msgbuf[BUFSIZE];
	
    new_socket = *(int *)sock;
	new_dev = (dev_info_t *)malloc(sizeof(dev_info_t));
    if (new_dev == NULL) {
        printf("malloc new_dev failed!\n");
        exit(1);
    }
    new_dev->sock = new_socket;
    new_dev->dev_id = dev_id;
	char devkey_str[40];
	unsigned long dev_key;
    
    while (read(new_socket, msgbuf, sizeof(msgbuf))) {
        msglen = strlen(msgbuf);
		if ((pstr = (char *)os_strstr(pbuffer, "\v1/device/activate")) != NULL) {
			if ((pstr = (char *)os_strstr(pbuffer, "devkey")) != NULL) {
				pstr += 7;
				if ((pstr2 = (char *)os_strstr(pstr, "\"")) != NULL)
					devkey = 

				device_status = DEVICE_ACTIVE_DONE;
				esp_param.activeflag = 1;
				user_esp_platform_save_param(&esp_param);
				user_esp_platform_sent(pespconn);
			} else {
				ESP_DBG("device activates failed.\n");
				device_status = DEVICE_ACTIVE_FAIL;
			}
		}
		else if ((pstr = (char *)os_strstr(pbuffer, "/v1/device/identify")) != NULL) {
			if ((pstr = (char *)os_strstr(pbuffer, "\"version\":")) != NULL) {
				struct upgrade_server_info *server = NULL;
				int nonce = user_esp_platform_parse_nonce(pbuffer);
				user_platform_rpc_set_rsp(pespconn, nonce);

				server = (struct upgrade_server_info *)os_zalloc(sizeof(struct upgrade_server_info));
				os_memcpy(server->upgrade_version, pstr + 12, 4);
				server->upgrade_version[4] = '\0';
				os_sprintf(server->pre_version, "v%d.%d", SDK_VERSION_MAJOR, SDK_VERSION_MINOR);
				user_esp_platform_upgrade_begin(pespconn, server);
			}
		} else if ((pstr = (char *)os_strstr(pbuffer, "/v1/device/timers/")) != NULL) {
			int nonce = user_esp_platform_parse_nonce(pbuffer);
			user_platform_rpc_set_rsp(pespconn, nonce);
			os_timer_disarm(&client_timer);
			os_timer_setfn(&client_timer, (os_timer_func_t *)user_platform_timer_get, pespconn);
			os_timer_arm(&client_timer, 2000, 0);
		} else if ((pstr = (char *)os_strstr(pbuffer, "\"method\": ")) != NULL) {
			if (os_strncmp(pstr + 11, "GET", 3) == 0) {
				user_esp_platform_get_info(pespconn, pbuffer);
			} else if (os_strncmp(pstr + 11, "POST", 4) == 0) {
				user_esp_platform_set_info(pespconn, pbuffer);
			}
		} else if ((pstr = (char *)os_strstr(pbuffer, "ping success")) != NULL) {
			ESP_DBG("ping success\n");
			ping_status = 1;
		} else if ((pstr = (char *)os_strstr(pbuffer, "send message success")) != NULL) {
		} else if ((pstr = (char *)os_strstr(pbuffer, "timers")) != NULL) {
			user_platform_timer_start(pusrdata , pespconn);
		}
        memset(msgbuf, 0, sizeof(msgbuf));
    } /* end of while(1) */
    
    close(new_socket);
    
    if(client != NULL) {
        pthread_mutex_lock(&client_list_mutex);
        list_del_init(&client->list);
        pthread_mutex_unlock(&client_list_mutex);
        free(client);
    }
    pthread_mutex_lock(&glob_info_mutex);
    glob_head.Clients--;    
    pthread_mutex_unlock(&glob_info_mutex);
    
    printf("\nDisconnected from the client %d\n", new_socket);
    printf("SERVER> ");
    fflush(stdout);
    
    return NULL;
}

int main(int argc, char *argv[])
{
    char input_buf[BUFSIZE];
    int msock;
    int ret, n;
    int new_socket;
    client_info_t *new_client;
	dev_info_t *new_dev;
    struct sockaddr_in saddr,caddr;
	unsigned int alen;
    
    pthread_t th;
    pthread_attr_t th_attr;
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    int maxfd;
    fd_set fd_read;

	saddr.sin_family = PF_INET;                               /*指定服务器地址参数*/
	saddr.sin_addr.s_addr = INADDR_ANY;
	//port=(unsigned short)atoi(argv[1]);
	saddr.sin_port =8000;

    if ((msock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
        printf("socket init error!\n");
        exit (1);
    }
    
    ret = bind(msock, (struct sockaddr *)&saddr, sizeof(saddr));
    if (ret == -1) {
        printf("bind socket error!\n");
        close(msock);
        exit(1);
    }
    
    maxfd = msock + 1;
    printf("SERVER> ");
    fflush(stdout);
    
    ret = listen(msock, QLEN);
    if (ret == -1) {  
        perror("cannot listen the client connect request");  
        close(msock);  
        exit(1);  
    }

	for (i = 0; i < HASH_SIZE; i++) {
		INIT_LIST_HEAD(&plug_dev_hashtable[i]);
	}

    (void) pthread_attr_init(&th_attr);
    (void) pthread_attr_setdetachstate(&th_attr, PTHREAD_CREATE_DETACHED);
    glob_head.Characters = 0;
    glob_head.Clients = 0;
    glob_head.glb_mode = 0;
    INIT_LIST_HEAD(&glob_head.client_head);

    ret = pthread_mutex_init(&glob_info_mutex, NULL);  
    if (ret != 0) {  
        perror("pthread_mutex_init failed\n");  
        exit(EXIT_FAILURE);  
    }
    
/* the main thread use I/O multiplexing  technology, listen stdin input and new socket connection */
    while (1) {
        FD_ZERO(&fd_read);
        FD_SET(0, &fd_read);
        FD_SET(msock, &fd_read);
        
        n = select(maxfd, &fd_read, NULL, NULL, &tv);
        if (n < 0) {
            perror("select error\n");
        }
            
        if (FD_ISSET(0, &fd_read)) {
			while((ret = get_input_str(input_buf, sizeof(input_buf))) == 0) {
				printf("SERVER> ");
			}
            
            if (strcmp(input_buf, "quit") == 0) {
                break;
            } else {
                parse_input(input_buf);
            }
            
            printf("SERVER> ");
            fflush(stdout);
            continue;
        }
        
        if (FD_ISSET(msock, &fd_read)) {     /* if a new client request, connect it and create a new thread for it */
            new_socket = accept(msock, (struct sockaddr *)&caddr, &alen);
            if (new_socket <= 0) {
                printf ("connected error! %d\n", new_socket);
                close(msock);  
                exit(1);
            }
            ret = pthread_create(&th, &th_attr, dev_login_process, &new_socket);
            if (ret != 0) {
                printf("pthread_create failed!\n");
                exit(1);
            }
            
            //pthread_mutex_lock(&client_list_mutex); 
            list_add_tail(&new_dev->list, &plug_dev_hashtable[dev_id % HASH_SIZE];
            //pthread_mutex_unlock(&client_list_mutex);
        }
    } /* end of while(1) */
    
    close(msock);
    pthread_mutex_destroy(&client_list_mutex); 
    pthread_mutex_destroy(&glob_info_mutex);     
    return 0;
}
