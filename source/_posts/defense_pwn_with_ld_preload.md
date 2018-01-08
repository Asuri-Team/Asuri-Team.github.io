---
title: 使用LD_PRELOAD防御pwn
authorId: hac425
tags:
  - awd
  - pwn_defense
categories:
  - ctf
date: 2017-12-23 11:31:00
---
### 前言

本文介绍使用 `LD_PRELOAD` 防御 线下赛中常见的漏洞。


github上的相关项目：

`hook` 了常用的函数

https://github.com/poliva/ldpreloadhook



### 正文

由于可能会不允许加载 `脚本` ,所以用 `c` 来加载（可能需要加一些没有的东西凑大小）


```
#include <stdio.h>  
#include <unistd.h>  
  
int main(int arg,char **args)  
{  
  
    char *argv[]={"test",NULL};//传递给执行文件的参数数组，这里包含执行文件的参数   
  
    char *envp[]={"LD_PRELOAD=./libmy_printf.so",NULL};//传递给执行文件新的环境变量数组  
  
    execve("./test",argv,envp);  
   
}  
```
执行当前目录的 `test` 文件，同时设置 `LD_PRELOAD=./libmy_printf.so`,  运行时加载 `libmy_printf.so`

.




**堆相关漏洞**

使用 https://github.com/DhavalKapil/libdheap
```
#include <stdio.h>  
#include <unistd.h>  
  
int main(int arg,char **args)  
{  
  
    char *argv[]={"test",NULL};//传递给执行文件的参数数组，这里包含执行文件的参数   
  
	char *envp[]={"LD_PRELOAD=./libdheap.so", "LIBDHEAP_EXIT_ON_ERROR=1",NULL};//传递给执行文件新的环境变量数组  
    execve("./test",argv,envp);  
   
}  
```

`LIBDHEAP_EXIT_ON_ERROR=1`  检测到异常后就会退出。




**格式化字符串**


hook `printf`  和 `snprintf`过滤关键字

```
#define _GNU_SOURCE

#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
// gcc -shared -fPIC my_printf.c -o libmy_printf.so -ldl

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int fd = 0;

void log (char * buf) {

	if(!fd){
		fd = open("log.txt", O_WRONLY|O_CREAT|O_APPEND);
	}
  write(fd, buf, strlen(buf));
  write(fd, '\n', 1);
  sync();

}


void str_remove(char *src, char *target){

        char *p;    
        char c[81];
        char *dst[254]={0};
        while((p = strstr(src,target)) != NULL) { //strstr 找不到返回 NULL 
                *p = '\0'; // 指定连接下一步（连接函数）之前 a 的终止位置； 
                strcpy (c, p+strlen(target)); // strcat 函数中的两个传入参数的内存地址不能重叠，所以这里用 c 当作 temp 
                strcat (src, c);
        } 


}




int printf(const char *format, ...)
{
        va_list list;
        char *parg;
        typeof(printf) *old_printf;

        char *tmp = malloc(strlen(format) + 1);
        strcpy(tmp, format);

        

        /*

        remove some bad string

        */
        str_remove(tmp, "$p");
        str_remove(tmp, "$x");
        str_remove(tmp, "hn");
        str_remove(tmp, "ln");
        str_remove(tmp, "$n");
        log(tmp);

        // format variable arguments
        va_start(list, tmp);
        vasprintf(&parg, tmp, list);
        va_end(list);

        // get a pointer to the function "printf"
        old_printf = dlsym(RTLD_NEXT, "printf");
        (*old_printf)("%s", parg); // and we call the function with previous arguments

        free(parg);
        free(tmp);
}


int snprintf(char *str, size_t size, const char *format, ...){
        va_list list;
        char *parg;
        typeof(snprintf) *old_snprintf;

        char *tmp = malloc(strlen(format) + 1);
        strcpy(tmp, format);

        /*

        remove some bad string

        */
        str_remove(tmp, "$p");
        str_remove(tmp, "$x");
        str_remove(tmp, "hn");
        str_remove(tmp, "ln");
        str_remove(tmp, "$n");
        log(tmp);

        // format variable arguments
        va_start(list, tmp);
        vasprintf(&parg, tmp, list);
        va_end(list);
        
        // get a pointer to the function "printf"
        old_snprintf = dlsym(RTLD_NEXT, "snprintf");
        (*old_snprintf)(str, size, "%s", parg); // and we call the function with previous arguments

        free(parg);
        free(tmp);

}
```

使用 
```
gcc -shared -fPIC my_printf.c -o libmy_printf.so -ldl
```
编译之（`32` 位 加 `-m 32`）