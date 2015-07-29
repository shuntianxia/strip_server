#ifndef _DB_INTERFACE_H_
#define _DB_INTERFACE_H_

#include <mysql/mysql.h>
#include "smart_strip.h"

#define DB_SERVER "127.0.0.1"
#define DB_NAME "smart_strip"
#define DB_USER "gzq"
#define DB_PWD  "bestidear"
#define SQL_LEN 256

MYSQL *init_db_connect();

MYSQL_RES *query_data(char *sql);

int user_account_register(char *username, char *passwd, char *email);

int user_login_verify(user_info_t *user);

int dev_activate(dev_id_t dev_id);

int dev_login_verify(dev_info_t *dev);

int dev_logout_verify(dev_id_t dev_id);

int user_bind_dev(char *username, dev_id_t dev_id);

int user_unbind_dev(char *username, dev_id_t dev_id);

int user_list_dev(char *username, char *buf);

#endif /* _DB_INTERFACE_ */