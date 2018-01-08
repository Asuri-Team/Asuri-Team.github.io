---
title: Pwn with File结构体（二）
authorId: hac425
tags:
  - file struct
categories:
  - ctf
date: 2017-12-07 21:36:00
---
### 前言


---
本文由 **本人** 首发于 先知安全技术社区：  https://xianzhi.aliyun.com/forum/user/5274/

---

最新版的 `libc` 中会对 `vtable` 检查，所以之前的攻击方式，告一段落。下面介绍一种，通过修改 `_IO_FILE` 实现任意地址读和任意地址写的方式。

### 正文

`_IO_FILE` 通过这些指针，来读写数据。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512654157088d9edyn3q.png?imageslim)
如果我们修改了它们，然后通过一些文件读写函数时，我们就能实现 任意地址读写。

 **任意地址读**
 
 ![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512656021050j3vjc54v.png?imageslim)
 
 代码示例
 ```
 #include <stdio.h>
#include <stdlib.h>

int main(int argc, char * argv[])
{   
    FILE *fp; 
    char *msg = "hello_file";

    char *buf = malloc(100);
    read(0, buf, 100);
    fp = fopen("key.txt", "rw");

    // 设置 flag 绕过 check
    fp->_flags &= ~8;
    fp->_flags |= 0x800;

    // _IO_write_base write数据的起始地址， _IO_write_ptr  write数据的终止地址
    fp->_IO_write_base = msg;
    fp->_IO_write_ptr = msg + 6;

    //绕过检查
    fp->_IO_read_end = fp->_IO_write_base;

    // write 的目的 文件描述符， 1 --> 标准输出
    fp->_fileno = 1;
    fwrite(buf, 1, 100, fp);

    return 0;
}

 ```
 ![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512656917401bhu6ayhp.png?imageslim)
 
 
  **任意地址写**
  
  ![paste image](http://oy9h5q2k4.bkt.clouddn.com/15126569407780y6n1s1m.png?imageslim)
  
  ```
  #include <stdio.h>
#include <stdlib.h>

int main(int argc, char * argv[])
{   
    FILE *fp; 
    char msg[100];

    char *buf = malloc(100);
    fp = fopen("key.txt", "rw");

    // 设置 flag 绕过 check
    fp->_flags &= ~4;

    // _IO_buf_base buffer 的起始地址， _IO_buf_end  buffer 的终止地址
    // fread 先把数据读入 [_IO_buf_base, _IO_buf_end] 形成的 buffer
    // 然后复制到目的 buffer
    fp->_IO_buf_base = msg;
    fp->_IO_buf_end = msg + 100;

    // 设置 文件描述符， 0---> stdin, 从标准输入读数据
    fp->_fileno = 0;
    fread(buf, 1, 6, fp);
    
    puts(msg);
    puts(buf);

    return 0;
}

  ```
  ![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512657551566q5ox73ro.png?imageslim)
  
 
 **利用 stdin / stdout 任意地址写/ 读**
 
`puts`, `scanf` 等一批系统函数默认使用的 `stdin` , `stdout` ,`stderr` 等结构体进行操作，通过修改这些结构体的内容，可以更方便的实现任意地址读，任意地址写。
 
 `stdin` 也是 `_IO_FILE` 结构体
 ```
 #include <stdio.h>
#include <stdlib.h>


int global_val = 0xaabbccdd;


int main(int argc, char * argv[])
{   
    FILE *fp; 
    int var;

    fp = stdin;

    fp->_flags &= ~4;

    fp->_IO_buf_base = stdout;
    fp->_IO_buf_end = stdout + 100;


    scanf("%d",&var);
    
    printf("0x%x\n", global_val);

    return 0;
}

 ```
 运行之
 ![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512658393494amnz5255.png?imageslim)
 
 成功修改 `stdout` 结构体
 
 ```
 #include <stdio.h>
#include <stdlib.h>

int main(int argc, char * argv[])
{   
    FILE *fp; 
    char *msg = "hello_stdout";

    char *buf = malloc(100);

    fp = stdout;

    // 设置 flag 绕过 check
    fp->_flags &= ~8;
    fp->_flags |= 0x800;

    // _IO_write_base write数据的起始地址， _IO_write_ptr  write数据的终止地址
    fp->_IO_write_base = msg;
    fp->_IO_write_ptr = msg + 12;

    //绕过检查
    fp->_IO_read_end = fp->_IO_write_base;

    // write 的目的 文件描述符， 1 --> 标准输出
    fp->_fileno = 1;
    puts("<----->this is append on msg ");

    return 0;
}

 ```
 
 ![paste image](http://oy9h5q2k4.bkt.clouddn.com/15126587803351zrlnl5p.png?imageslim)
 
 成功读到了， `msg` 的内容。
 
 
 参考：
 
 https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique