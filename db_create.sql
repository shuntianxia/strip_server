CREATE DATABASE IF NOT EXISTS smart_strip;
use smart_strip;
CREATE TABLE IF NOT EXISTS userinfo(
	id int(11) NOT NULL AUTO_INCREMENT,
    username varchar(18) NOT NULL unique,
    userpasswd varchar(32) NOT NULL,
	useremail varchar(30) NOT NULL unique,
	reg_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	last_login_time TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
	last_login_ip int(10) unsigned DEFAULT NULL,
    PRIMARY KEY (id)
    )ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS devinfo(
	id int(11) NOT NULL AUTO_INCREMENT,
    dev_id varchar(16) NOT NULL unique,
	online_flag tinyint(1) NOT NULL DEFAULT FALSE,
	last_offline_time TIMESTAMP NOT NULL DEFAULT '0000-00-00 00:00:00',
	last_login_ip int(10) unsigned DEFAULT NULL,
    PRIMARY KEY (id)
    )ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS bindinfo(
	d_id int(11) NOT NULL unique,
	u_id int(11) NOT NULL,
	bind_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	FOREIGN KEY (d_id) REFERENCES devinfo(id) ON DELETE CASCADE ON UPDATE CASCADE,
	FOREIGN KEY (u_id) REFERENCES userinfo(id) ON DELETE CASCADE ON UPDATE CASCADE
    )ENGINE=InnoDB;