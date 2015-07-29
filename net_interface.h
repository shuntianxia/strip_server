#ifndef _NET_INTERFACE_H_
#define _NET_INTERFACE_H_

#define USER_PORT "8088"
#define DEV_PORT "8000"

extern int create_and_bind (char *port);

extern int set_non_blocking(int sfd);

#endif /* _NET_INTERFACE_H_ */