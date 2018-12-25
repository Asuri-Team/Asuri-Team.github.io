---
title: xinetd-kafel - 一个更安全的xinetd服务
authorId: xm1994
tags:
 - linux
 - Tools
 - Pwn
categories:
 - Pwn
date: 2018-05-12 23:50:01
---

为了保证CTF解题/渗透赛中PWN服务有更稳定的表现（预防搅屎棍）和CTF攻防赛中有人使用ptrace/seccomp等系统调用做通用防御，我在xinetd中加入了对syscall的过滤。感谢Google的Kafel项目，给编写seccomp bpf代码提供了一种更方便的方法。

<!--more-->


# 0x00 前言：为啥要搞这个东西？
众所周知，在CTF线下赛中，各大主办方明令禁止使用通用防御软件/规则对赛题进行防御。但是目前在国内外的各大比赛中，PWN题目多用socat或xinetd提供服务。而这两个组建都太过简陋，无法提供精细的系统调用控制，主办方对通防工具的检查多为人工登陆gamebox检查。
在近日结束的一场线下赛中，某战队向我反馈成功的使用了我在去年编写的一个[PWN通防工具](https://github.com/Asuri-Team/pwn-sandbox)苟到了最后（关于这个工具的原理如果有兴趣欢迎star一下对应项目，人数多的话我会再开坑写文章）。
我也惊讶于主办方竟然对这么大型的通防工具都没有察觉。

而在CTF解题赛/渗透赛中，虽然有docker这一容器技术可以为pwn题目隔离运行环境，限制运行资源，方便重启等维护工作，但依然难以避免有部分搅屎选手采用诸如[Fork炸弹](https://zh.wikipedia.org/wiki/Fork%E7%82%B8%E5%BC%B9)等手段对服务器进行DoS攻击。
因此，对一些用不到的的系统调用进行限制，也可以大大减少搅屎棍选手的数量。（Docker已直接支持对container内程序进行系统调用限制[Read More](https://docs.docker.com/engine/security/seccomp/)）

因此，[xinetd-kafel](https://github.com/Asuri-Team/xinetd-kafel)这一改版的xinetd服务油然而生。

# 0x01 原理：你对xinetd做了点啥？
其实修改xinetd让其支持对系统调用的过滤这一想法最早在Defcon 2015 Final时就已被其主办方实现。但主办方并未开源其xinetd代码（也可能是我没找到），而且其只能在xinetd的配置文件中对syscall进行简单的黑白名单过滤，难以有效限制日渐增长的搅屎大军。
让程序支持syscall过滤通常来讲有两种办法： 
1. ptrace
2. seccomp
其中，ptrace就是linux下gdb用来调试程序所使用的syscall，而且其功能如其名，process trace， 用于跟踪进程的各种调用。
但是由于ptrace使用过于复杂，我们在xinetd中，并未使用这一方式，而采用了seccomp。

## seccomp是个啥？
`seccomp - operate on Secure Computing state of the process`
seccomp 中文直译就是“操作进程的安全计算状态”，其实就是通知内核对进程的系统调用进行限制。几年前CentOS/RedHat Linux默认启用的selinux底层就是使用的这个系统调用对进程进行系统调用限制。当年应该人人装完linux的第一件事就是关掉selinux。现在的Ubuntu和CentOS都已不再默认安装或开启selinux了。
通过`man seccomp`我们就能看到seccomp的相关调用方法。
```
prctl(PR_SET_SECCOMP, SECCOMP_MODE_XX, args);
seccomp(SECCOMP_MODE_XX, flags, args);
```
linux Man page对seccomp的描述非常有歧义，其提供了如上两种接口，这里我把其参数相应的对应了起来。`seccomp`的第二个参数flags很难查到相关资料，而且在我们的场景下并不影响使用，就不再多做解释。seccomp调用会对当前进程及其子进程生效，如果我们调用seccomp之后，当前进程的系统调用就会被限制。

`SECCOMP_MODE_XX`共有两种选择：
1. SECCOMP_MODE_STRICT
2. SECCOMP_MODE_FILTER

`SECCOMP_MODE_STRICT` 会将系统调限制在 `read, write, _exit (but not exit_group), sigreturn `中。 我们可以编写一个小程序测试一下：

```
#include <stdio.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <linux/signal.h>
#include <sys/prctl.h>
#include <unistd.h>

int main(void)
{
	puts("a");
	prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT, 0);
	puts("b");
	system("echo c");
	return 0;
}
```

编译运行后结果如下：
```
xm1994@xm1994-vm:~$ ./a.out 
a
b
Killed
```
程序在执行到system函数后就提示了Killed。这是因为在执行system时，会调用fork和execve两个系统调用。
如果我们删掉system()函数后再运行呢？程序依然会提示killed。这个问题是由于在新版的libc中，main函数退出后。libc_start_main会调用exit_group(0)结束程序以及其子进程（感觉是为了防止僵尸进程？），但再旧版的libc中，执行的是exit()。

`SECCOMP_MODE_FILTER` 模式则允许传入一个过滤器参数，进行自定义的系统调用过滤。

## 这过滤器咋搞啊？

seccomp使用的过滤器叫[BPF](https://zh.wikipedia.org/wiki/BPF), 允许在内核中直接设置数据包过滤模式。 我们使用wireshark/tcpdump进行网络抓包时，设置的抓包规则就会被编译成bpf送入内核。在内核中，系统调用流程也会反映在网络数据包（特殊的）的处理流程中（还有很多其他的系统事件也会以数据包的形式存在）。因此，我们也可以通过编译bpf规则到内核中，来自定义seccomp的过滤规则。

```
 struct sock_fprog {
    unsigned short      len;    /* Number of BPF instructions */
    struct sock_filter *filter; /* Pointer to array of
                                    BPF instructions */
};

Each program must contain one or more BPF instructions:

struct sock_filter {            /* Filter block */
    __u16 code;                 /* Actual filter code */
    __u8  jt;                   /* Jump true */
    __u8  jf;                   /* Jump false */
    __u32 k;                    /* Generic multiuse field */
};

```

bpf规则实际上是在内核中的bpf虚拟机中运行，也就是说他也是一种opcode，因此，我们需要一些工具去生成相应的opcode。一个比较常用的工具是libseccomp，它可以通过一些接口来生成bpf规则代码。但使用libseccomp的话就需要自己写一个parser去调用相关的接口了。万幸，在调研中，我发现了谷歌的某个员工编写的[kafel](https://github.com/google/kafel)库, 他可以很方便的将文本描述的过滤规则编译成sock_fprog结构体。

# 0x02 修改：你到底改了点啥？

在阅读了xinetd代码后，发现其代码结构是相当的干净易于理解的。我在其配置文件parser中添加了`kafel_rule` 这一选项，用于指定kafel规则文件。随后将文件编译为sock_fprog结构体保存在每个service的配置中。
xinetd在接收到连接后会fork出来一个子进程，随后通过dup/dup2进行流重定向。在流重定向完成后，会调用execve执行目标服务程序。这一过程类似于在shell中执行程序并对流重定向，如果读者实现过简易的shell，应该很好理解。
我们只需要在execve之前调用 `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, args);` 便可对目标服务程序设定seccomp规则。 

这一修改其实十分简单，代码的总变更行数不超过200行。

# 0x03 效果：真管用？

当然管用了，不信自己试试。 

这个版本的xinetd我们已经应用到了战队布置pwn题使用的docker image：[ctf-xinetd](https://github.com/Asuri-Team/ctf-xinetd)中。欢迎各位大师傅脱下来试用，好用的话别忘点个star~。

# 0x04 目标：理想很丰满
这个工具我用了不到六个小时就写完了。之所以这么赶时间，是希望在即将到来的国赛和以后的比赛中，能有主办方使用和推广这一工具，为选手提供更加干净公平的比赛环境。最终目的当然是国内外的所有比赛都能用上这一工具，但是理想很丰满，怕是到最后只有我们战队和比较熟悉的几个战队办比赛才会用吧233333。