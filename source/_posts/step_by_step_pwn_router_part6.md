---
title: 一步一步pwn路由器之uClibc中malloc&&free分析
authorId: hac425
tags:
  - uclibc源码分析
  - malloc && free
categories:
  - 路由器安全
date: 2017-10-28 12:21:00
---
### 前言



---
本文由 **本人** 首发于 先知安全技术社区：  https://xianzhi.aliyun.com/forum/user/5274/

---
栈溢出告一段落。本文介绍下 `uClibc` 中的 `malloc` 和 `free` 实现。为堆溢出的利用准备基础。`uClibc` 是 `glibc` 的一个精简版，主要用于嵌入式设备，比如路由器就基本使用的是 `uClibc`， 简单自然效率高。所以他和一般的`x86`的堆分配机制会有些不一样。

### 正文

uClibc 的 `malloc` 有三种实现，分别为：

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509164969446w1f222m1.png?imageslim)
其中 `malloc-standard` 是最近更新的。它就是把 `glibc` 的 `dlmalloc` 移植到了 `uClibc`中。`malloc` 是`uClibc`最开始版本用的 `malloc`。本文分析的也是`malloc`目录下的`uClibc`自己最初实现的 `malloc`。 因为如果是 `malloc-standard` 我们可以直接按照 一般 `linux` 中的堆漏洞相关的利用技巧来利用它。

现在编译 `uClibc` 的话默认使用的是  `malloc-standard` ，我也不知道该怎么切换，所以就纯静态看看 `malloc`目录下的实现了。


#### malloc
从 `malloc` 的入口开始分析。 为了简单起见删掉了无关代码。
```

//malloc 返回一个指定大小为 __size 的指针。

/*
调用 malloc 申请空间时，先检查该链表中是否有满足条件的空闲区域节点
如果没有，则向内核申请内存空间，放入这个链表中，然后再重新在链表中
查找一次满足条件的空闲区域节点。

它实际上是调用 malloc_from_heap 从空闲区域中申请空间。

*/

void *
malloc (size_t size)
{
  void *mem;


  //参数有效性检测。这里没有检测参数为负的情况

  if (unlikely (size == 0))
    goto oom;


  mem = malloc_from_heap (size, &__malloc_heap, &__malloc_heap_lock);

  return mem;
}

```

`malloc` 实际使用的是 `malloc_from_heap` 来分配内存。

```
static void *
__malloc_from_heap (size_t size, struct heap_free_area **heap
		)
{
  void *mem

  /* 一个 malloc 块的结构如下：
  
	  +--------+---------+-------------------+
	  | SIZE   |(unused) | allocation  ...   |
	  +--------+---------+-------------------+
	  ^ BASE			 ^ ADDR
	  ^ ADDR - MALLOC_ALIGN
  
	  申请成功后返回的地址是 ADDR
	  SIZE 表示块的大小，包括前面的那部分，也就是 MALLOC_HEADER_SIZE
   */
  
  //实际要分配的大小，叫上 header的大小
  size += MALLOC_HEADER_SIZE;

//加锁
  __heap_lock (heap_lock);

  /* First try to get memory that's already in our heap.  */
  //首先尝试从heap分配内存.这函数见前面的分析
  mem = __heap_alloc (heap, &size);

  __heap_unlock (heap_lock);
  
  /*
  后面是分配失败的流程，会调用系统调用从操作系统分配内存到 heap, 然后再调用__heap_alloc，进行分配，本文不在分析。
  */
  
  
```



计算需要分配内存块的真实大小后进入  `__heap_alloc` 分配。

在 `heap`中使用 `heap_free_area` 来管理空闲内存，它定义在 `heap.h`
```

/*


struct heap_free_area
{
	size_t size;  //空闲区的大小
	 //用于构造循环链表
	struct heap_free_area *next, *prev;
};

size 表示该空闲区域的大小，这个空闲区域的实际地址并没有用指针详细地指明，
因为它就位于当前 heap_free_area 节点的前面，如下图所示：

+-------------------------------+--------------------+
|                               |   heap_free_area   |
+-------------------------------+--------------------+
\___________ 空闲空间 ___________/\___ 空闲空间信息 ___/


实际可用的空闲空间大小为 size – sizeof(struct heap_free_area)

指针 next, prev 分别指向下一个和上一个空间区域，
所有的空闲区域就是通过许许多多这样的节点链起来的，
很显然，这样组成的是一个双向链表。

*/

```
所以 `free` 块在内存中的存储方式和 `glibc` 中的存储方式是不一样的。它的元数据在块的末尾，而 `glibc`中元数据在 块的开头。


下面继续分析 `__heap_alloc`


```

/* 
   堆heap中分配size字节的内存
   */
void *
__heap_alloc (struct heap_free_area **heap, size_t *size)
{
  struct heap_free_area *fa;
  size_t _size = *size;
  void *mem = 0;

  /* 根据 HEAP_GRANULARITY 大小向上取整，在 heap.h 中定义 */

  _size = HEAP_ADJUST_SIZE (_size);
  //如果要分配的内存比FA结构还要小，那就调整它为FA大小
  

  if (_size < sizeof (struct heap_free_area))
   

 //根据HEAP_GRANULARITY 对齐 sizeof(double)
    _size = HEAP_ADJUST_SIZE (sizeof (struct heap_free_area));

	//遍历堆中的FA，找出有合适大小的空闲区,在空闲区域链表中查找大小大于等于 _SIZE 的节点 
  for (fa = *heap; fa; fa = fa->next)
    if (fa->size >= _size)
      {
		/* Found one!  */
		mem = HEAP_FREE_AREA_START (fa);
		 //从该空间中分得内存。这函数前面已经分析过了
		*size = __heap_free_area_alloc (heap, fa, _size);
		break;
      }
  return mem;
}

```
找到`大小 >= 请求size` 的 `heap_free_area`，然后进入 `__heap_free_area_alloc 分配`。

```
/* 
   该函数从fa所表示的heap_free_area中，分配size大小的内存
   */
static __inline__ size_t
__heap_free_area_alloc (struct heap_free_area **heap,
			struct heap_free_area *fa, size_t size)
{
  size_t fa_size = fa->size;

  //如果该空闲区剩余的内存太少。将它全部都分配出去






  if (fa_size < size + HEAP_MIN_FREE_AREA_SIZE)
    {
    ////将fa从heap中删除
      __heap_delete (heap, fa);
      /* Remember that we've alloced the whole area.  */
      size = fa_size;
    }
  else
	  /* 如果这个区域中还有空闲空间，就把 heap_free_area 节点中
		   的 size 减小 size就可以了：
	  
		   分配前：
		 __________ 空闲空间 __________ 	__ 空闲空间信息 __
		/							   \ /					\
		+-------------------------------+--------------------+
		|								|	heap_free_area	 |
		+-------------------------------+--------------------+
		\__________ fa->size __________/
	  
		   分配后：
			 ___ 已分配 __	  __ 空闲空间 __   __ 空闲空间信息 __
		/			  \ /			   \ /					\
		+-------------------------------+--------------------+
		|			   |				|	heap_free_area	 |
		+-------------------------------+--------------------+
		\____ size ___/ \__ fa->size __/
	  
		*/

    fa->size = fa_size - size;

  return size;
}

```

注释很清晰了。所以如果我们有一个堆溢出，我们就需要覆盖到下面空闲空间的 `heap_free_area` 中的 指针，才能实现 `uClibc` 中的 `unlink` 攻击（当然还要其他条件的配合）,另外我们也知道了在 `malloc` 的时候，找到合适的 `heap_free_area`  后，只需要修改 `heap_free_area` 的 size位就可以实现了分配，所以在 `malloc` 中是无法 触发类似 `unlink` 的攻击的。

下面进入 `free`

#### Free
首先看 free 函数。

```
void
free (void *mem)
{
  free_to_heap (mem, &__malloc_heap, &__malloc_heap_lock);
}

```

直接调用了 `  free_to_heap ` 函数。

```

static void
__free_to_heap (void *mem, struct heap_free_area **heap)
{
  size_t size;
  struct heap_free_area *fa;
   /* 检查 mem 是否合法 */
  if (unlikely (! mem))
    return;
/* 获取 mem 指向的 malloc 块的的实际大小和起始地址 */
  size = MALLOC_SIZE (mem); //获取块的真实大小
  mem = MALLOC_BASE (mem); //获取块的基地址
  __heap_lock (heap_lock); //加锁
  /* 把 mem 指向的空间放到 heap 中  */
  fa = __heap_free (heap, mem, size);

 //如果FA中的空闲区超过  MALLOC_UNMAP_THRESHOLD。就要进行内存回收了,涉及 brk, 看不懂，就不说了，感觉和利用也没啥关系。
```

首先获得了 内存块的起始地址和大小，然后调用 `__heap_free` 把要 `free` 的内存放到 `heap` 中。

```

/*
语义上的理解是释放掉从mem开始的size大小的内存。换句话说，就是把从从mem开始的，size大小的内存段，映射回heap。
*/
struct heap_free_area *
__heap_free (struct heap_free_area **heap, void *mem, size_t size)
{
  struct heap_free_area *fa, *prev_fa;
  
  //拿到 mem的 结束地址
  void *end = (char *)mem + size;


  /* 空闲区域链表是按照地址从小到大排列的，这个循环是为了找到 mem 应该插入的位置 */
  for (prev_fa = 0, fa = *heap; fa; prev_fa = fa, fa = fa->next)
    if (unlikely (HEAP_FREE_AREA_END (fa) >= mem))
      break;

  if (fa && HEAP_FREE_AREA_START (fa) <= end)
   //这里是相邻的情况,不可能小于，所以进入这的就是 HEAP_FREE_AREA_START (fa) == end, 则 mem, 和 fa所表示的内存块相邻
    {
    /* 
		如果 fa 和 mem 是连续的，那么将 mem 空间并入 fa 节点（增加fa的大小即可）管理, 如图所示，地址从左至右依次增大
	
		  +---------------+--------------+---------------+
		  | 	  |prev_fa| 	 mem	 |fa_chunk| fa   |
		  +---------------+--------------+---------------+
						  ^______________________________^ 
	
		prev_fa 与 fa 的链接关系不变，只要更改 fa 中的 size 就可以了
	   */

      size_t fa_size = fa->size + size;
      if (HEAP_FREE_AREA_START (fa) == end)
	{
	  if (prev_fa && mem == HEAP_FREE_AREA_END (prev_fa))
	    {

		 /* 如果 fa 前一个节点和 mem 是连续的，那么将 fa 前一个节点的空间
			     也并入 fa 节点管理

			   +---------------+---------------+--------------+---------------+
			   |       |pre2_fa|       |prev_fa|      mem     |       |   fa  |
			   +---------------+---------------+--------------+---------------+
		                       ^______________________________________________^

			    将 prev_fa 从链表中移出，同时修改 fa 中的 size
          */
	      fa_size += prev_fa->size;
	      __heap_link_free_area_after (heap, fa, prev_fa->prev);
	    }
	}
      else
	{
	  struct heap_free_area *next_fa = fa->next;

	   /* 如果 mem 与 next_fa 是连续的，将 mem 并入 next_fa 节点管理

 	   +---------------+--------------+--------------+---------------+
	   |       |prev_fa|      |   fa  |      mem     |       |next_fa|
	   +---------------+--------------+--------------+---------------+
                       ^_____________________________________________^ 

	   将 fa 从链表中移出，同时修改 next_fa 中的 size
	  */
	  if (next_fa && end == HEAP_FREE_AREA_START (next_fa))
	    {
	      fa_size += next_fa->size;
	      __heap_link_free_area_after (heap, next_fa, prev_fa);
	      fa = next_fa;
	    }
	  else
	    /* FA can't be merged; move the descriptor for it to the tail-end
	       of the memory block.  */


	      /* 如果 mem 与 next_fa 不连续，将 fa 结点移到 mem 尾部

 	   +---------------+--------------+--------------+---------------+
	   |       |prev_fa|      |   fa  | mem | unused |       |next_fa|
	   +---------------+--------------+--------------+---------------+
                          ^___________________^^________________________^

	       需要重新链接 fa 与 prev_fa 和 next_fa 的关系
            */
	    {
	      /* The new descriptor is at the end of the extended block,
		 SIZE bytes later than the old descriptor.  */
	      fa = (struct heap_free_area *)((char *)fa + size);
	      /* Update links with the neighbors in the list.  */
	      __heap_link_free_area (heap, fa, prev_fa, next_fa);
	    }
	}
      fa->size = fa_size;
    }
  else
     /* 如果fa和 mem之间有空隙或者 mem> HEAP_FREE_AREA_END (fa)，那么可以简单地
       把 mem 插入 prev_fa 和 fa之间 */
    fa = __heap_add_free_area (heap, mem, size, prev_fa, fa);

  return fa;
}

```

`__heap_link_free_area` 就是简单的链表操作。没有什么用。
```
static __inline__ void
__heap_link_free_area (struct heap_free_area **heap, struct heap_free_area *fa,
		       struct heap_free_area *prev,
		       struct heap_free_area *next)
{
  fa->next = next;
  fa->prev = prev;

  if (prev)
    prev->next = fa;
  else
    *heap = fa;
  if (next)
    next->prev = fa;
}
```

感觉唯一可能的利用点在于,前后相邻的情况，需要先把 `prev_fa` 拆链表，我们如果可以伪造 `prev_fa->prev`，就可以得到一次内存写的机会，不过也只能写入 `fa` 的值
```
fa_size += prev_fa->size;
__heap_link_free_area_after (heap, fa, prev_fa->prev);
          ```

```
static __inline__ void
__heap_link_free_area_after (struct heap_free_area **heap,
			     struct heap_free_area *fa,
			     struct heap_free_area *prev)
{
  if (prev)
    prev->next = fa;
  else
    *heap = fa;
  fa->prev = prev;
}
```

### 总结

怎么感觉没有可利用的点，还是太菜了。以后如果遇到实例一定要补充进来。

tips:

- 分析库源码时看不太懂可以先编译出来，然后配合这 `ida` 看，所以要编译成 `x86` 或者 `arm` 方便 `f5` 对照看。比如这次，我把 `uClibc` 编译成 `arm` 版后，使用 `ida` 一看，发现 `uClibc` 怎么使用的是 `glibc` 的那一套，一看源码目录发现，原来它已经切换到 `glibc` 这了。

- 忽然想起来交叉编译环境感觉可以用 docker 部署，网上一搜发现一大把，瞬间爆炸。

参考链接：

http://blog.chinaunix.net/uid-20543183-id-1930765.html

http://hily.me/blog/2007/06/uclibc-malloc-free/