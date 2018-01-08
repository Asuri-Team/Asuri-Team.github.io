---
title: 一步一步pwn路由器之radare2使用实战
authorId: hac425
tags:
  - radare2
categories:
  - 路由器安全
date: 2017-11-01 19:33:00
---
### 前言


---
本文由 **本人** 首发于 先知安全技术社区：  https://xianzhi.aliyun.com/forum/user/5274/

---

前文讲了一些 `radare2` 的特性相关的操作方法。本文以一个 `crackme` 来具体介绍下 `radare2` 的使用

程序的地址： [在这里](https://gitee.com/hac425/blog_data/blob/master/crackme0x03)

### 正文

首先使用 `radare2` 加载该程序。使用了 `aaa` 分析了程序中的所有函数。使用 `iI` 查看二进制文件的信息。可以看到是 `32` 位的。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509536312825toj2ruk1.png?imageslim)

使用 `aaa`分析完程序后，可以使用 `afl` 查看所有的函数。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509536413775tyxowxq5.png?imageslim)
直接跳到 `main` 函数看看逻辑

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15095364686834obsuwoc.png?imageslim)

不习惯看文本模式的汇编的话，可以使用 `VV` 进入图形化模式
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509536557600j6sv26da.png?imageslim)

拿到个程序，我会首先看函数调用理解程序的大概流程。比如这里先调用了 `printf` 打印了一些提示信息，然后使用 `scanf` 获取我们的输入，分析 `scanf`的参数
```
|           0x080484cc      8d45fc         lea eax, [local_4h]
|           0x080484cf      89442404       mov dword [local_4h_2], eax
|           0x080484d3      c70424348604.  mov dword [esp], 0x8048634  ; [0x8048634:4]=0x6425
|           0x080484da      e851feffff     call sym.imp.scanf          ; int scanf(const char *format)


```
我们可以知道`0x8048634 ` 是我们的第一个参数, `local_4h`是我们的第二个参数。看看 `0x8048634 `存放的是什么。
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509536913132ckutls7d.png?imageslim)

所以程序需要我们输入的是一个 整数，然后把它存在 `local_4h`里面了。那我们就可以把  `local_4h` 变量改下名字。这里改成 `input`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509537156669asiszojb.png?imageslim)

继续往下看发现 `input` 变量后来没有被处理直接传到了  `test` 函数。他的第二个参数是这样生成的

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509538263559azqlu0hp.png?imageslim)

为了获得这个参数我们有很多方法，比如 我们可以直接静态分析，或者用 `gdb` 调试这都很容易得到结果。

这里正好试试 `radare` 的模拟执行功能。使用该功能我们需要先分析要模拟执行的代码对环境的依赖，比如寄存器的值，内存的值等，然后根据依赖关系修改内存和寄存器的值来满足代码运行的上下文。

在这里这段代码只对栈的内存进行了处理。那我们就先分配一块内存，然后用 `esp` 刚刚分配的内存。由于这里一开始没有对内存数据进行读取，所以我们直接使用分配的内存就好，不用对他进行处理。


首先我们跳到目标地址，然后使用 `aei` 或者 `aeip` 初始化虚拟机堆栈，然后使用 `aer` 查看寄存器状态。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15095388389068csy8248.png?imageslim)

然后分配一块内存作为栈内存，给程序模拟执行用。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509538957638rwu5ocqr.png?imageslim)

在 `0xff0000` 分配了 `0x40000` 大小的内存。然后把 `esp` 和 `ebp` 指到这块内存里面。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509539081176y3sckgra.png?imageslim)

然后我们让模拟器运行到 `0x0804850c` 也就是调用 `test` 函数的位置处，查看他的参数，可以看到第二个参数的值就是 `0x00052b24`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509539169362t234cqgc.png?imageslim)
最后我们进去 `test` 函数里面看看

![paste image](http://oy9h5q2k4.bkt.clouddn.com/150953929096164elui3y.png?imageslim)
就是判断 `参数一` 和 `参数二` 是否一致，所以这个 `crackme` 的 `key` 就是 `0x00052b24` 十进制数表示 `338724`.
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509539408734tys3o1xg.png?imageslim)

成功


### 总结

`radare2` 的模拟执行功能是通过 `esil` 来实现的，粗略的试了一下感觉还是挺不错的感觉和  `unicorn` 有的一拼，不过`radare2`也是有 `unicorn`的插件的。



 参考：
 
 http://radare.org/r/talks.html
 
 https://github.com/radare/radare2book
 
 https://codeload.github.com/radareorg/r2con/