---
title: Windbg学习笔记
authorId: l1nk
tags:
 - Windows
 - Tools
categories:
 - Reverse
date: 2017-06-13 10:54:01
---
windbg可被誉为是windows下的一个很棒的调试器，这里借助比赛的机会学习一波好了
<!--more-->
Windbg学习笔记
------------------------------
## 基本介绍
windbg的指令分成以下几类

 * 标准命令
 * 元命令
 * 扩展指令
 
标准命令相当于是内建在windbg中的默认指令。  
元命令则是提供给标准指令中没有的指令，调用时开头要加上`.`符号。  
扩展指令则是用于实现针对特定目标的调试功能，使用前要加上`!`符号，其完整的调用格式为:
```
！nameofExtentModule.nameofExtentCommand 参数
```
其中如果扩栈模块已经加载了，那么`nameofExtentModule.`不是必须的，windbg会直接查找。

## 常用指令

### 执行、调试相关

#### dt 
dt命令看可以显示局部变量、全局变量或数据类型的信息。它也可以仅显示数据类型。即结构和联合(union)的信息。
例如，查看当前的线程块:
```
	dt _teb
```

#### d 查看数据
默认格式如下
```
	d [type] [address range]
```
d这个命令能够查看指定地址和内存的内容，其中常用的有dd（使用双字节来查看内存内容），如：
```
	dd 77400000
```


#### ！peb
_扩展指令_
可以查看当前进程中的peb的基本情况。


#### bp
指令格式如下
```
    bp <address>
```
常见的下断点的方式。对应的清除断点的方式为bc num,而列出断点的方法为bl



#### g

最基本的指令，运行当前程序。除此之外，还有gu // 执行到当前函数完成时停下 【Go Up】等

#### u
将指定的地址反汇编:
```
u[u|b] address(.表示当前的程序执行地址)
```
其中uu和ub可以指定当前反汇编的长度(暂时没看出什么区别，似乎是ub的话使用\.会自动计算从函数开始的地址进行汇编)。可以使用以下的语法进行长度的指定
```
uu Address L[Length]
```
使用L表示后面的数字表示的是长度

#### r
查看当前的寄存器
同时可以修改当前的寄存器，比如说:
```
r @eax=1
```
将当前的eax寄存器的值修改成1


#### ed
```
ed [address][content]
```
将当前的内存修改成指定值
例如
```
ed 08041000 11111111
```
将地址08041000处的内容修改成11111111
#### p   

常见指令，单步步过。除此之外还有:

 * p 2 // 2为步进数目
 * pc // 执行到下一个函数调用处停下 【Step to  Next Call】
 * pa 7c801b0b // 执行到7c801b0b地址处停下  【Step to Adress】


#### t

常见指令，单步步入


### 调试辅助相关

#### \.sympath


表示当前的符号加载情况。符号能够帮助我们更加方便的分析程序。
```
.sympath+ D:\Filename
```
将D:\\Filename添加到符号查找的路径中。
关于符号，其中`lm`指令可以检查当前的文件中是否加载了符号文件:
```
0:000> lm
start    end        module name
009e0000 009e6000   test_x86_wo_gs_safeseh_dep   (deferred)             
65430000 65506000   MSVCR110   (deferred)             
74c80000 74e57000   KERNELBASE   (deferred)             
756b0000 75780000   KERNEL32   (deferred)             
77e00000 77f8d000   ntdll      (pdb symbols)          E:\Competition\reverse\WinDBG\Debuggers\x86\sym\wntdll.pdb\30D581A78028B9E4A0BF83EE93B38BD31\wntdll.pdb
```

 * deffered：表示延迟绑定
 * pdb symbols：表示已经加载当前符号

#### .load
```
.load dllname
```
导入指定名字的dll文件，常常用于导入插件


### 漏洞利用相关
#### !py mona
`mona`是一个好东西哈，可以用来生成`ROP`，查找`Gadget`，进行漏洞挖掘等等。

##### 生成ROP Chain
```
!py mona rop -m "module"
```
利用module生成`ROP Chain`

#### 参数
有些程序传递参数的时候，可以从下图的位置的位置传递数据。
![](http://showlinkroom.me/2017/06/13/Windbg%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/Windbg09.png)



## 实战：用windbg来分析dmp文件
这里用一次比赛的题目来记录此次的学习过程好了。
当程序运行到某些重大错误的时候，windows会帮我们生成一个.dmp文件，这里的dmp就是文件进程的内存镜像，可以把程序的执行状态通过调试器保存在其中。

我们首先将dmp文件导入到windbg中，选择**open crash dump**即可打开文件。然后等待文件打开之后，我们输入指令

	!analyze –v

!analyze是分析用的指令，-v表示要看详细信息。结果大概如下：
![](http://showlinkroom.me/2017/06/13/Windbg%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/Windbg00.png)
![](http://showlinkroom.me/2017/06/13/Windbg%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/Windbg01.png)
![](http://showlinkroom.me/2017/06/13/Windbg%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/Windbg02.png)
从图中，我们可以看到如下信息:
```
BUCKET_ID_PREFIX_STR:  STATUS_BREAKPOINT_

FAILURE_PROBLEM_CLASS:  STATUS_BREAKPOINT

```
这段一次就是说，当前的dmp是由于STATUS_BREAKPOINT导致的，也就是【断点让其中断】导致	，上网查阅资料后可以知道，此类中断是由windbg本身强制中断所引发的。然后我们查看一下当前加载了哪些模块
	
	lm

![](http://showlinkroom.me/2017/06/13/Windbg%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/Windbg04.png)
PS:这段我还发现用VS也可以查看来着
![](http://showlinkroom.me/2017/06/13/Windbg%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/Windbg03.png)
我们能够发现这里有一个叫做`stolen.dll`的动态链接库。。仔细想这个名字实在是奇怪，我们尝试上网查一下这个东西,发现完全没办法查到，这反而增加了这个东西的可疑性——毕竟正常的dll都能够在网上查到的。于是我们尝试跟踪一下当前的dll

	lmv m stolen

![](http://showlinkroom.me/2017/06/13/Windbg%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/Windbg05.png)
能够看见其起始地址为

	10000000

但是当我们去查看的时候，这段内容由于并没有被映射，无法被查看。。。
![](http://showlinkroom.me/2017/06/13/Windbg%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/Windbg06.png)
那么既然这段内容不能被查看，那不如我们来查看一下整个内存空间信息，看看哪段是被映射了的
	
	!vadump

![](http://showlinkroom.me/2017/06/13/Windbg%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/Windbg07.png)
其中这条信息比较有意思

	BaseAddress: 10001000
	RegionSize:  000062f4

很显然是在那个stolen.dll范围中的一个数据，我打开memory窗口，输入地址进行查看:
![](http://showlinkroom.me/2017/06/13/Windbg%E5%AD%A6%E4%B9%A0%E7%AC%94%E8%AE%B0/Windbg08.png)
这里有一段很神奇的ascii码。。。这个

	great!acaa16770db76c1ffb9cee51c3cabfcf

就是我们需要寻找的flag