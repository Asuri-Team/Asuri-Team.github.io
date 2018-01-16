---
title: 一步一步 Pwn RouterOS之调试环境搭建&&漏洞分析&&poc
authorId: hac425
tags:
  - diff
  - setup env
categories:
  - pwn_router_os
date: 2018-01-05 23:13:00
---
### 前言


---
本文由 **本人** 首发于 先知安全技术社区：  https://xianzhi.aliyun.com/forum/user/5274

---

本文分析 `Vault 7` 中泄露的 `RouterOs` 漏洞。漏洞影响 `6.38.5` 以下的版本。

```
What's new in 6.38.5 (2017-Mar-09 11:32):
!) www - fixed http server vulnerability;
```

文中涉及的文件：

链接: https://pan.baidu.com/s/1i5oznSh 密码: 9r43


### 正文


**补丁对比&&漏洞分析**

首先我们先来看看漏洞的原理，漏洞位于 `www` 文件。

我们需要拿到 `www` 文件， 直接用 `binwalk` 提取出 `router os` 镜像文件的所有内容。

```
binwalk -Me mikrotik-6.38.4.iso
```
然后在提取出的文件中搜索即可。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515165746693cgztdv73.png?imageslim)

同样的方法提取出 `mikrotik-6.38.5.iso` 中的 `www` 文件。

然后使用 `diaphora` 插件 对 这两个文件进行补丁比对 （因为 `6.38.5` 正好修复了漏洞）


首先打开 `www_6384` (6.38.4版本的文件）， 然后使用 `diaphora` 导出 `sqlite` 数据库， `diaphora` 使用这个数据库文件进行 `diff` 操作。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515166093523oxrusj58.png?imageslim)


然后打开 `www_6385` (6.38.5版本的文件），使用 `diaphora` 进行 `diff`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515166195628syhogd51.png?imageslim)

找到相似度比较低的函数

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515165950046enxkrdzl.png?imageslim)

选中要查看差异的 条目 ，然后右键 

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515166256270id9v1odu.png?imageslim)
可以选择查看 `diff` 的选项，使用 `diff pseudo-code` 就可以对 `伪c` 代码  `diff`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515166371796rzohbnad.png?imageslim)

对比 `diff` 可以发现， 修复漏洞后的程序 没有了 `alloca`， 而是直接使用 `string::string` 构造了 字符串。

下面直接分析 `www_6384` .

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515166511848had11egp.png?imageslim)
获取 `content-length` 的值之后，就传给了 `alloca` 分配内存。

这里和前文不同的是，这里 `alloca`的参数是 无符号数。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515166646043t0iiacnt.png?imageslim)
所以我们能修改的是栈顶以上的数据，触发崩溃的poc.

**poc**

```
from pwn import *
def makeHeader(num):
    return "POST /jsproxy HTTP/1.1\r\nContent-Length: " + str(num) + "\r\n\r\n"
s1 = remote("192.168.2.124", 80)
s1.send(makeHeader(-1) + "A" * 1000)
```

注：ip 按实际情况设置


**调试环境搭建&&Poc测试**


首先我们得先安装 `routeros`， 使用 `vmware` 加载 `iso`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/151516721340747r1xr5x.png?imageslim)

注： `routeros` 是 32 位的， 硬盘类型要为 `ide` 否则会找不到驱动。

然后开启虚拟机，就会进入

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515167336617v46o0ig8.png?imageslim)

按 `a`选择所有 ，然后按 `i` 进行安装，然后一直输入 `y` 确定即可。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515167432691gf6rqz53.png?imageslim)
安装完成后，重启，就会进入 登录界面了，使用 `admin` 和空密码登录即可。

然后输入 `setup` ，接着输入 `a`, 按照提示配置好 `ip` 地址。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515167541207kvenwy3d.png?imageslim)
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515167628938ab0thmw5.png?imageslim)

然后就可以使用 `ssh` 登录了。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515167693696iosa57jc.png?imageslim)


`Router Os ` 对 `linux` 做了大量的裁剪，所以我们需要给系统增加一些文件方便进行调试，`busybox` 和 `gdbserver` （文件在百度云内）。


要增加文件需要使用一个 `live-cd` 版的 `linux` 挂载 `router os` 的磁盘分区，增加文件。这里使用了 `ubuntu`. 


关闭虚拟机，设置光盘镜像，然后修改引导为 光盘即可进入 `live-cd`。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515168110904jefbfa9f.png?imageslim)


选择 `try ubuntu`, 进入系统后，挂载 `/dev/sda1` 和 `/dev/sda2`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515168515234ev3kupe7.png?imageslim)

把 `busybox` 和 `gdbserver` 放到 `bin` 目录(不是在`/dev/sda1`  就是在 `/dev/sda2` )下，然后在 `etc` 目录下新建 `rc.d/run.d/S99own `, 内容为

```
#!/bin/bash
mkdir /ram/mybin
/flash/bin/busybox-i686 --install -s /ram/mybin
export PATH=/ram/mybin:$PATH
telnetd -p 23000 -l bash
```
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515168595733d7l2hl3n.png?imageslim)

`umount` 然后去掉光盘， 重新启动，应该就可以 `telnet 192.168.2.124 23000` 连接了。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515168775379dbz2ytfl.png?imageslim)

此时使用 

`gdbserver.i686 192.168.2.124:5050 --attach $(pidof www)`

如图
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515168937045jx5tlvv1.png?imageslim)


然后 gdb 连上去。


```
target remote 192.168.2.124:5050
```


-
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515168983975bczey67j.png?imageslim)



运行`poc`,程序崩溃。



![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515169108092kn41spn7.png?imageslim)



参考：

https://github.com/BigNerd95/Chimay-Red/