---
title: 如何科学的在Docker Container中运行多个服务
authorId: xm1994
tags:
 - linux
 - Docker
categories:
 - Devops
date: 2018-08-25 20:50:01
---

在一个Docker Container中运行多个服务？打扰了。

<!--more-->

# 0x00 前言
Docker，或说任何基于`内核namespace`的轻量级进程隔离技术，在设计之初，都不是为了当作虚拟机使用的。也就是说，其中运行的并不是一个完整的操作系统。包括Docker官方，也是推荐在一个Container内仅运行一个服务。如果需要运行多个服务，应通过`docker run --link` 或者`docker-compose`来关联多个容器。但是在实际的应用中，我们经常希望将一个完整的可运行环境打包成一个`docker image`，不再依赖其他的容器。比如在CTF比赛中，将多个服务打包成一个Image，可以有效地提高在环境受损后恢复的效率。在经历了多场比赛，看过各种大师傅用各种奇怪的姿势完成这个任务后，觉得应该好好的讨论一下这个问题。

# 0x01 错误的姿势

1. 使用upstart的启动方式

```
# Dockerfile
From ubuntu:14.04
RUN apt-get update && apt-get upgrade -y && apt-get install mysql apache2 php7.0 
ADD web /var/www/html
RUN service mysql start && /var/www/html/init_sql.sh && service mysql stop
CMD service mysql start && service apache2 start && while true; do sleep 10;done
```
2. 使用systemd的启动方式
```
# Dockerfile
From ubuntu:16.04
RUN apt-get update && apt-get upgrade -y && apt-get install mysql apache2 php7.0 
ADD web /var/www/html
RUN systemctl start mysql && /var/www/html/init_sql.sh && systemctl stop mysql
CMD systemctl start mysql && systemctl start apache2 && while true; do sleep 10;done
```

3. 使用启动脚本启动多个服务

```
# Dockerfile
From ubuntu:16.04
RUN apt-get update && apt-get upgrade -y && apt-get install mysql apache2 php7.0 
ADD web /var/www/html
ADD entrypoint.sh /sbin/
RUN chmod +x /sbin/entrypoint.sh /var/www/html/init_sql.sh&& \
     /etc/init.d/mysql start && /var/www/html/init_sql.sh && /etc/init.d/mysql stop
CMD /sbin/entrypoint.sh
```
```
#!/bin/bash 

# entrypoint.sh
/usr/bin/mysqld start &
/usr/bin/httpd &
while true
do
sleep 100
done
```

在实际中，使用`方法1`或者`方法2`很大几率无法完成将多个服务跑在同一个container中的任务。`方法3`虽然可以，但仍然存在一些问题：

1. 一旦产生僵尸进程，将无人回收，只有杀掉整个container才能解决。
2. 在停止container的时候将无人处理`SIGTERM`等信号。
3. 很难重启其中某一个服务

`方法1`和`方法2`不能成功，是因为docker只是一个进程隔离的沙箱环境，并不是真正的虚拟机。而`service xxx start` 和`systemctl start xxx` 分别是`upstart`和`systemd`这两个`/sbin/init`进程的替代者的服务管理命令。而`upstart`和`systemd`都要求系统必须是物理机或虚拟机，并不支持作为container的`init`进程。方法3存在问题是因为，在正常的系统中，`init`进程永远占用`PID=1`的位置，回收僵尸进程、处理未处理的信号等都是由`init`进程帮我们完成的，一个子进程如果失去了父进程，也会由`init`进程接管。但是在container中，`init`进程并不存在，`PID=1`的进程是我们在`Dockerfile`中定义的`Entrypoint`或最后一个`CMD`指定的命令。
```
root@vpscn:/var/lib/docker# docker exec -it hackmd sh
/hackmd # ps -ef
PID   USER     TIME   COMMAND
    1 hackmd     1:03 node app.js
   42 hackmd     0:00 /usr/local/bin/node ./lib/workers/dmpWorker.js
   62 root       0:00 sh
   69 root       0:00 ps -ef
```
因此，对于启动方法3的container，我们应该在启动时加上`--init`参数，来强制使用[tini](https://github.com/krallin/tini)作为`init`进程。但是就算这样，在服务多了之后，进行重启等操作仍然很繁琐。


# 0x02 推荐的姿势

作为一个~~金牌运维~~打杂的，简单谈谈我常用的方法。 

首先推荐一个超级好用的基础镜像`phusion/baseimage`。截至SUCTF2018环境准备完成时，该镜像的最新版本是`0.10.1`，基于`ubuntu 16.04`。我们常用的`apt-get`等命令都可以无缝兼容。[phusion/baseimage](https://github.com/phusion/baseimage-docker) 采用了作者自己开发的一个基于`python`的`init`进程作为Container的`Entrypoint`，采用`runit`作为服务管理器。这个基础镜像还是在Coding打杂的时候知道的，[Coding ~~WebIDE~~ Studio](https://studio.coding.net) 的Web Terminal也是基于这个镜像做的。NUAACTF/SUCTF的PWN题基础镜像[ctf-xinetd](https://github.com/Asuri-Team/ctf-xinetd)也是基于这个镜像做的。

然后直接贴个在SUCTF2018运维期间写的`Dockerfile`

```
#Dockerfile
FROM phusion/baseimage:0.10.1
MAINTAINER Yibai Zhang <xm1994@outlook.com>

RUN sed -i 's/archive.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list &&\
    sed -i 's/security.ubuntu.com/mirrors.aliyun.com/g' /etc/apt/sources.list &&\
    apt-get update && apt-get install -y apache2 libapache2-mod-php php-mysql mariadb-server &&\
    apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* /var/www/html/*

RUN mkdir -p /etc/service/apache2/ && \
    printf "#!/bin/sh\n\ntrap \"apachectl -k graceful-stop\" 1 2 3 6 15\n\nexec /usr/sbin/apachectl -D FOREGROUND\n" > /etc/service/apache2/run &&\
    chmod +x /etc/service/apache2/run && mkdir -p /etc/service/mysql/ &&\
    printf "#!/bin/sh\n\ntrap \"mysqladmin -uroot -psuCTF_P1us_1s shutdown\" 1 2 3 6 15\n\nexec /usr/bin/mysqld_safe" > /etc/service/mysql/run &&\
    mkdir -p /var/run/mysqld/ && chown mysql:mysql /var/run/mysqld &&\
    chmod 700 /etc/service/mysql/run /etc/service/apache2/run

COPY web /var/www/html
COPY flag /flag
RUN echo "secure-file-priv=/var/www/" >>/etc/mysql/mariadb.conf.d/50-server.cnf && chmod -R 777 /var/www/html/favicon
COPY init_sql.sh /tmp/init_sql.sh
RUN chmod +x /tmp/init_sql.sh && bash -c "/tmp/init_sql.sh" && rm /tmp/init_sql.sh
EXPOSE 80
```

```
#!/usr/bin/env bash
#init_sql.sh

mysqld_safe &   
echo -n "Waiting for mysql startup"
while ! mysqladmin --host="localhost" --silent ping ; do
    echo -n "."
    sleep 1
done
echo

mysql -uroot <<EOF
UPDATE mysql.user SET Password=PASSWORD('XXXXXX'), plugin = '' WHERE User='root';
create database calc;
use calc;
create table user(
id INT NOT NULL AUTO_INCREMENT primary key,
username varchar(32) NOT NULL,
password varchar(32) NOT NULL
)ENGINE=InnoDB DEFAULT CHARSET=utf8;
insert into user values(1,'admin','aa67095d8e65d624548cb6b50bd4778e');
create table file(
id INT NOT NULL AUTO_INCREMENT primary key,
filename varchar(32) NOT NULL,
filehash varchar(32) NOT NULL,
sig varchar(120) NOT NULL
)ENGINE=InnoDB DEFAULT CHARSET=utf8;
create table flag(
flag varchar(120) primary key
)ENGINE=InnoDB DEFAULT CHARSET=utf8;
insert into flag values('SUCTF{a_very_long_long_long_long_long_fake_flag_d}');
grant SELECT, INSERT on calc.user to 'suctf'@localhost identified by 'suctf';
grant SELECT, INSERT, UPDATE on calc.file to 'suctf'@localhost ;
grant SELECT on calc.flag to 'suctf'@localhost ;
FLUSH PRIVILEGES;
EOF

mysqladmin -uroot -pXXXXXX shutdown
```
这里着重看一下`printf "#!/bin/sh\n\ntrap \"apachectl -k graceful-stop\" 1 2 3 6 15\n\nexec /usr/sbin/apachectl -D FOREGROUND\n" > /etc/service/apache2/run`，这个命令就是在创建runit启动脚本。具体的说明可以去看`phusion/baseimage`或者`runit`的手册。执行完成后会在`/etc/service/apache2/run`下面生成如下内容的脚本
```
#!/bin/sh

trap "apachectl -k graceful-stop" 1 2 3 6 15

exec /usr/sbin/apachectl -D FOREGROUND
```
这个脚本会作为runit的子进程运行，并将Apache2保持在前台运行。在接收到`1 2 3 6 15`这几个信号的时候友好的(graceful)结束Apache2。如果在运行中需要重启Apache服务，只需要运行`docker exec container_name sv restart apache2`即可。通过这种方式，在Container停止的时候也可以通知相关的进程，而不是直接全部杀死，更可以保证服务的完整性。~~虽然在比赛中基本挂了就要恢复环境根本不需要保证完整性。~~
