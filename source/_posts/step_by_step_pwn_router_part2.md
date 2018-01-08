---
title: 一步一步pwn路由器之路由器环境修复&&rop技术分析
authorId: hac425
tags:
  - 路由器安全
  - mips rop
  - 路由器环境修复
categories:
  - 路由器安全
date: 2017-10-26 23:05:00
---
### 前言

---
本文由 **本人** 首发于 先知安全技术社区：  https://xianzhi.aliyun.com/forum/user/5274/

---
拿到路由器的固件后，第一时间肯定是去运行目标程序，一般是web服务程序。我们可以去 `/etc/init.d/` 找启动文件，或者看看一些有可能的目录。一般来说路由器的程序很少的情况下是可以直接用qemu运行起来的。我们需要做一些修复的工作，本文会介绍一个常用的方法，后面会分析在 `mips uclibc` 中常用的 `rop` 手法。

### 正文
**运行环境修复**

由于路由器运行时会去 nvram中获取配置信息，而我们的qemu中是没有该设备，路由器中的程序可能会因为没法获取配置信息而退出。我们可以使用	`https://github.com/zcutlip/nvram-faker` 配合着设置 `LD_PRELOAD` 环境变量来使用( 类似于一种 `hook` )。如果你的mips交叉编译工具链和它脚本里面的不一样就要修改它的脚本，比如

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15090309370211cupr2kg.png?imageslim)
编译后把 `libnvram-faker.so` 和 `nvram.ini` 放到 `/` 目录，然后使用 `LD_PRELOAD`来加载。即可

```
sudo chroot . ./qemu-mips-static -E LD_PRELOAD=/libnvram-faker.so  /usr/bin/httpd
```
如果程序还会在其他地方保错，就要自己分析程序，然后根据实际情况，在 `nvram-faker` 增加 `hook代码`

注：

- 要注意目标应用是用的 `glibc` 还是 `uclibc` ,从而选择对应的交叉编译工具链来进行编译。
- 先使用 `firmadyne` 运行看看，然后优先选择 `qemu-system-mips-static`来调试，实在不行用 `qemu-system`
- 如果需要某些静态编译（给生成的Makefile里面增加 `-static` 选项）的程序，建议去 `qemu-system` 编译，交叉编译太麻烦了。
----

**MIPS ROP分析**

看了 [Exploiting a MIPS Stack Overflow](http://www.devttys0.com/2012/10/exploiting-a-mips-stack-overflow/) 做的实验，因为	`tplink`上没有对应版本的固件了。于是只能自己写一个栈溢出的程序，并配合着gdb调试，来模拟整个rop过程。

代码如下：
```
#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>  


void getshell(){
    system("sh");
    sleep(1);
}

void vulnerable_function() {  
    char buf[128]; 
    read(STDIN_FILENO, buf, 256);  
}  
   
int main(int argc, char** argv) { 
	printf("%p\n", (int *)write); 
    vulnerable_function();  
    write(STDOUT_FILENO, "Hello, World\n", 13);  
} 
```
因为要使用 `qemu-mips-static` 来调试程序，这样就不方便找到libc的基地址。于是在程序运行时把libc中的函数地址打印出来，然后计算基地址，便于我们找到gadgets具体在内存中的位置。然后使用 uclibc的交叉编译工具链来编译。
```
/home/haclh/router_exploit/cross-compiler-mips/bin/mips-gcc level1.c -o level1
```
把它扔到一个路由器文件系统目录中，这样就不用单独拷贝它依赖的lib了。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15090326039915db83l6b.png?imageslim)

可以看到程序使用了 uClibc，通过查看qemu的maps，找到uClibc的路径
![paste image](http://oy9h5q2k4.bkt.clouddn.com/15090327179167od9lz52.png?imageslim)

拿到ida中分析找 gadgets.具体可以看上面的那篇文章。找到的gadgets如下。
```
rop_gad1:
	LOAD:00055C60                 li      $a0, 1
	LOAD:00055C64                 move    $t9, $s1
	LOAD:00055C68                 jalr    $t9 ; sub_55960
	LOAD:00055C5C                 lui     $s0, 2

gadg_2

	LOAD:0001E20C                 move    $t9, $s1
	LOAD:0001E210                 lw      $ra, 0x28+var_4($sp)
	LOAD:0001E214                 lw      $s2, 0x28+var_8($sp)
	LOAD:0001E218                 lw      $s1, 0x28+var_C($sp)
	LOAD:0001E21C                 lw      $s0, 0x28+var_10($sp)
	LOAD:0001E220                 jr      $t9
	LOAD:0001E224                 addiu   $sp, 0x28


rop_gad3:
	LOAD:000164C0                 addiu   $s2, $sp, 0x198+var_180
	LOAD:000164C4                 move    $a2, $v1
	LOAD:000164C8                 move    $t9, $s0
	LOAD:000164CC                 jalr    $t9 ; mempcpy
	LOAD:000164D0                 move    $a0, $s2


rop_gad4:
	LOAD:000118A4                 move    $t9, $s2
	LOAD:000118A8                 jalr    $t9

```
rop的过程，和对应的sp寄存器的值。
```
sp:0x76fff710
首先进入 rop_gad1， $s1 gadg_2

sp:0x76fff710
进入 gadg_2，这时$s1还是gadg_2， 从内存加载数据到寄存器s1-->sleep, ra--> rop_gad3, $s0--->rop_gad4

sp:0x76fff738
再次进入 gadg_2,s1-->sleep, ra--> rop_gad3, $s0--->rop_gad4

sp:0x76fff760
进入 rop_gad3， 获取栈地址到$s2,跳到 $s0


进入rop_gad4，s2-->0x76fff778 跳进栈中，。。。 

```
**gdb调试的部分截图**

断在函数返回地址被覆盖的时候，使用gdb命令，设置`$pc`寄存器的值，伪造劫持程序流程到 rop_gad1
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509033066831ysbgu293.png?imageslim)

汇编代码如下
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509033106631mwc1gl07.png?imageslim)

第一次进入rop_gad2
![paste image](http://oy9h5q2k4.bkt.clouddn.com/15090332319233l54m90b.png?imageslim)

第二次运行到 rop_gad2 时的寄存器状态。
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509033335464zv8t8p6f.png?imageslim)

`t9` 指向 `sleep `函数，接下来调用 `sleep(1)` 刷新 `cache`, 便于后面指向 `shellcode`。次数的 ` $ra` 为 `rop_gad3`的地址，便于在 `sleep` 返回后继续 `rop` ,获取一个栈的指针到寄存器，便于后面直接跳过去。


进入rop_gad3

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509033654570mt5p9xro.png?imageslim)

进入 rop_gad4,跳到栈上执行shellcode


![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509033720821o12bll0r.png?imageslim)

分析完毕。
### 总结

修复环境要注意使用的gcc, 必要时自己跟踪，逆向代码，修复运行环境。看了几篇mips漏洞利用的文章，rop的思路就是上面的思路，估计那就是通用思路吧，记录下来，以备不时只需。调rop的过程还是有趣的。

参考链接：


http://www.devttys0.com/2012/10/exploiting-a-mips-stack-overflow/

注：

&emsp;&emsp;本文先发布于：https://xianzhi.aliyun.com/forum/topic/1509/