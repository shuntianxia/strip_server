#include <stdio.h>
#include <stdlib.h>
#include "db_interface.h"

#define USER_REGISTER "INSERT INTO userinfo(username,userpasswd,useremail) VALUES('%s',md5('%s'),'%s');"
#define USER_VERIFY_PASSWD "select * from userinfo where username='%s' and userpasswd=md5('%s');"
#define USER_LOGIN_UPDATE_INFO "update userinfo set last_login_time=CURRENT_TIMESTAMP,last_login_ip=inet_aton('%s') where username='%s';"
#define USER_BIND_DEV "insert into bindinfo(d_id,u_id) select devinfo.id,userinfo.id from devinfo,userinfo where dev_id='%s' and username='%s';"
#define USER_UNBIND_DEV "delete t1 from (bindinfo t1 inner join devinfo t2 on t1.d_id=t2.id and t2.dev_id='%s') inner join userinfo t3 on t1.u_id=t3.id where t3.username='%s';"
#define USER_LIST_DEV "select dev_id,online_flag from (devinfo inner join bindinfo on devinfo.id=bindinfo.d_id) inner join userinfo on bindinfo.u_id=userinfo.id where username='%s';"
#define DEV_LOGIN_UPDATE_STATUS "update devinfo set online_flag=TRUE,last_login_ip=inet_aton('%s') where dev_id='%s';"
#define DEV_LOGOUT_UPDATE_STATUS "update devinfo set online_flag=FALSE,last_offline_time=CURRENT_TIMESTAMP where dev_id='%s';"
#define DEV_VERIFY_EXIST "select * from devinfo where dev_id='%s';"
#define DEV_VERIFY_BIND "select * from bindinfo inner join devinfo on bindinfo.d_id=devinfo.id where dev_id='%s';"
#define DEV_DEL_BIND "delete t1 from bindinfo t1 inner join devinfo t2 on t1.d_id=t2.id and t2.dev_id='%s';"
#define DEV_REGISTER "INSERT INTO devinfo(dev_id) VALUES('%s');"

static MYSQL mysql;

static int str_to_devid(dev_id_t devid, const char *str)
{  
    char c;
	int i, j;
	unsigned char h, s;
	char *p = (char *)devid;
    memset(devid, 0, DEVID_LEN);
	for(i = 0; i < DEVID_LEN; i++)
	{
		s = 0;
		for(j=0; j<2; j++)
		{
			c = str[2*i +j];
			if(c>='0'&&c<='9') {
				h = c - '0';
			}
			else if(c>='a'&&c<='f') {
				h = c - 'a' + 10;
			}
			else if(c>='A'&&c<='F'){
				h = c - 'A' + 10;
			}
			else {
				return -1;
			}
			s = (s << (4*j)) + h;
		}
		p[i] = s;
	}
	return 0;
}

static void devid_to_str(char *str, dev_id_t devid)
{
	int i;
	char cl, ch;
	for(i = 0; i < DEVID_LEN; i++)
	{
		ch = '0' + devid[i] / 16;
		cl = '0' + devid[i] % 16;
		if(ch > '9')
			ch = ch + 7;
		if (cl > '9')
			cl = cl + 7;
		str[i*2] = ch;
		str[i*2+1] = cl;
	}
	str[DEVID_LEN*2] = '\0';
}

MYSQL *init_mysql_connect()
{
	MYSQL *db_handle;
	mysql_init(&mysql);
	db_handle = mysql_real_connect(&mysql, DB_SERVER, DB_USER, DB_PWD, DB_NAME, 0, NULL, 0);
	if(db_handle == NULL) {
		printf("%s\n", mysql_error(&mysql));  
        return NULL;
	}
	return db_handle;
}

int user_account_register(char *username, char *passwd, char *email)
{
	char sql[SQL_LEN];
	if(strlen(username) == 0 || strlen(email) == 0)
		return -1;
	MYSQL *conn = init_mysql_connect();
	if(conn == NULL)
		return -1;
	sprintf(sql, USER_REGISTER, username, passwd, email);
	int res = mysql_query(conn, sql);
	if (res != 0) {
        fprintf(stderr, "Select error %d: %s\n", mysql_errno(conn), mysql_error(conn));
		res = -1;
    }
	printf("select %lu rows\n", (unsigned long)mysql_affected_rows(conn));
	mysql_close(conn);
	return res;
}

int user_login_verify(user_info_t *user)
{
	char sql[SQL_LEN];
	char sql2[SQL_LEN];
	MYSQL_RES *res_ptr;
	unsigned long num_rows;
	MYSQL *conn = init_mysql_connect();
	if(conn == NULL)
		return -1;
	sprintf(sql, USER_VERIFY_PASSWD, user->username, user->passwd);
	printf("username is %s, password is %s.\n", user->username, user->passwd);
	sprintf(sql2, USER_LOGIN_UPDATE_INFO, user->ipaddr, user->username);
	int res = mysql_query(conn, sql);
	if (res != 0) {
        fprintf(stderr, "Select error %d: %s\n", mysql_errno(conn), mysql_error(conn));
		res = -1;
    }
	//printf("select %lu rows\n", (unsigned long)mysql_affected_rows(conn));
	res_ptr = mysql_store_result(conn);
	if (res_ptr) {
		num_rows = (unsigned long)mysql_num_rows(res_ptr);
        printf("Retrieved %lu rows\n", num_rows);
		if (num_rows == 1) {
			res = 0;
			mysql_query(conn, sql2);
		}
		else {
			res = -1;
		}
        if (mysql_errno(conn)) {
            fprintf(stderr, "Retrive error: %s\n", mysql_error(conn));
        }
        mysql_free_result(res_ptr);
    }
	mysql_close(conn);
	return res;
}

int user_bind_dev(char *username, dev_id_t dev_id)
{
	char sql[SQL_LEN];
	int ret_value;
	char devid_str[DEVID_STR_LEN];
	devid_to_str(devid_str, dev_id);
	MYSQL *conn = init_mysql_connect();
	if(conn == NULL)
		return -1;
	sprintf(sql, USER_BIND_DEV, devid_str, username);
	int res = mysql_query(conn, sql);
	if (res != 0) {
        fprintf(stderr, "user_bind_dev error %d: %s\n", mysql_errno(conn), mysql_error(conn));
		ret_value = -1;
    }
	if((res = (unsigned long)mysql_affected_rows(conn)) == 1) {
		ret_value = 0;
	} else {
		ret_value = 1;
	}
	printf("user_bind_dev %lu rows\n", (unsigned long)mysql_affected_rows(conn));
	mysql_close(conn);
	return ret_value;
}

int user_unbind_dev(char *username, dev_id_t dev_id)
{
	char sql[SQL_LEN];
	int ret_value;
	char devid_str[DEVID_STR_LEN];
	devid_to_str(devid_str, dev_id);
	MYSQL *conn = init_mysql_connect();
	if(conn == NULL)
		return -1;
	printf("ins user_unbind_dev devid is %s, username is %s\n", devid_str, username);
	sprintf(sql, USER_UNBIND_DEV, devid_str, username);
	int res = mysql_query(conn, sql);
	if (res != 0) {
        fprintf(stderr, "user_bind_dev error %d: %s\n", mysql_errno(conn), mysql_error(conn));
		res = -1;
    }
	if((res = (unsigned long)mysql_affected_rows(conn)) == 1) {
		ret_value = 0;
	} else {
		ret_value = 1;
	}
	printf("user_unbind_dev %lu rows\n", (unsigned long)mysql_affected_rows(conn));
	mysql_close(conn);
	return ret_value;
}

int user_list_dev(char *username, char *buf)
{
	char sql[SQL_LEN];
	MYSQL_RES *res_ptr;
	MYSQL_ROW sqlrow;
	unsigned int i;
	//unsigned int num_fields;
	unsigned long num_rows;
	//MYSQL_FIELD *fileds;
	char *p = buf;
	
	MYSQL *conn = init_mysql_connect();
	if(conn == NULL)
		return -1;
	sprintf(sql, USER_LIST_DEV, username);
	//sprintf(sql, "select dev_id,online_flag from devinfo;");
	int res = mysql_query(conn, sql);
	if (res != 0) {
        fprintf(stderr, "user_list_dev error %d: %s\n", mysql_errno(conn), mysql_error(conn));
		res = -1;
    }
	printf("user_list_dev %lu rows\n", (unsigned long)mysql_affected_rows(conn));

    res_ptr = mysql_store_result(conn);
	//num_fields = mysql_num_fields(res_ptr);
	//fileds = mysql_fetch_fields(res_ptr);
	
    if (res_ptr) {
		num_rows = (unsigned long)mysql_num_rows(res_ptr);
        printf("Retrieved %lu rows\n", num_rows);
		for(i = 0; i < num_rows; i++) {
	        while ((sqlrow = mysql_fetch_row(res_ptr)) != NULL) {
	            //printf("Fetched data...\n");
	            str_to_devid((unsigned char *)p, sqlrow[0]);
				p = p + 8;
				*p++ = atoi(sqlrow[1]);
				//printf("%s \t",sqlrow[j]);	
	        }
		}
		res = i;
        if (mysql_errno(conn)) {
            fprintf(stderr, "Retrive error: %s\n", mysql_error(conn));
        }
        mysql_free_result(res_ptr);
    }
	mysql_close(conn);
	return res;
}

int dev_login_verify(dev_info_t *dev)
{
	char sql[SQL_LEN];
	char devid_str[DEVID_STR_LEN] = {0};
	devid_to_str(devid_str, dev->dev_id);
	MYSQL *conn = init_mysql_connect();
	if(conn == NULL)
		return -1;
	printf("devid_str is %s\n", devid_str);
	sprintf(sql, DEV_LOGIN_UPDATE_STATUS, dev->ipaddr, devid_str);
	int res = mysql_query(conn, sql);
	if (res != 0) {
        fprintf(stderr, "dev_login_verify error %d: %s\n", mysql_errno(conn), mysql_error(conn));
		res = -1;
    }
	printf("dev_login_verify %lu rows\n", (unsigned long)mysql_affected_rows(conn));
	mysql_close(conn);
	return res;
}

int dev_logout_verify(dev_id_t dev_id)
{
	char sql[SQL_LEN];
	char devid_str[DEVID_STR_LEN] = {0};
	devid_to_str(devid_str, dev_id);
	MYSQL *conn = init_mysql_connect();
	if(conn == NULL)
		return -1;
	sprintf(sql, DEV_LOGOUT_UPDATE_STATUS, devid_str);
	int res = mysql_query(conn, sql);
	if (res != 0) {
        fprintf(stderr, "dev_logout_verify error %d: %s\n", mysql_errno(conn), mysql_error(conn));
		res = -1;
    }
	printf("dev_logout_verify %lu rows\n", (unsigned long)mysql_affected_rows(conn));
	mysql_close(conn);
	return res;
}

int dev_activate(dev_id_t dev_id)
{
	char sql_buf[SQL_LEN];
	char devid_str[DEVID_STR_LEN];
	devid_to_str(devid_str, dev_id);
	MYSQL_RES *res_ptr;
	unsigned long num_rows;
	int res;
	MYSQL *conn = init_mysql_connect();
	if(conn == NULL)
		return -1;
	sprintf(sql_buf, DEV_VERIFY_EXIST, devid_str);
	if((res = mysql_query(conn, sql_buf)) != 0) {
        fprintf(stderr, "Select error %d: %s\n", mysql_errno(conn), mysql_error(conn));
		mysql_close(conn);
		return -1;
    }
	if ((res_ptr = mysql_store_result(conn)) != NULL) 
	{
		if((num_rows = (unsigned long)mysql_num_rows(res_ptr)) == 0) 
		{
			memset(sql_buf, 0, sizeof(sql_buf));
			sprintf(sql_buf, DEV_REGISTER, devid_str);
			if((res = mysql_query(conn, sql_buf)) != 0) 
			{
				fprintf(stderr, "DEV_REGISTER error %d: %s\n", mysql_errno(conn), mysql_error(conn));
    		}
		}
		else 
		{
			memset(sql_buf, 0, sizeof(sql_buf));
			sprintf(sql_buf, DEV_DEL_BIND, devid_str);
			if((res = mysql_query(conn, sql_buf)) != 0) 
			{
				fprintf(stderr, "DEV_DEL_BIND error %d: %s\n", mysql_errno(conn), mysql_error(conn));
    		}
		}
		mysql_free_result(res_ptr);
    }
	mysql_close(conn);
	return 0;
}