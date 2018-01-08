---
title: 使用sa-jdi.jar dump 内存中的class
authorId: hac425
tags:
  - dump class
  - sa-jdi.jar
categories:
  - java应用破解思路
date: 2017-11-17 19:01:00
---
### 前言
在分析一个 `jar` 包时发现他把关键类采用了运行时使用 `classloader` 的方式加载了。懒得分析算法了，可以使用 `jdk` 自带的工具 `dump` 出需要的`class`.

### 正文

从运行的java进程里dump出运行中的类的class文件的方法，所知道的有两种

- 用agent attatch 到进程，然后利用 Instrumentation和 ClassFileTransformer就可以获取 到类的字节码了。

- 使用 sd-jdi.jar里的工具

本文介绍的就是使用 `sd-jdi.jar` 来dump.  `sd-jdi.jar`里自带的的 `sun.jvm.hotspot.tools.jcore.ClassDump` 可以把类的class内容dump到文件里。

`ClassDump` 里可以设置两个 `System properties`：

- sun.jvm.hotspot.tools.jcore.filter  Filter的类名
- sun.jvm.hotspot.tools.jcore.outputDir 输出的目录


#### 示例
首先写一个 `filter` 类

```

import sun.jvm.hotspot.tools.jcore.ClassFilter;
import sun.jvm.hotspot.oops.InstanceKlass;
import sun.jvm.hotspot.tools.jcore.ClassDump;
public class MyFilter implements ClassFilter {
    @Override
    public boolean canInclude(InstanceKlass kls) {
        String klassName = kls.getName().asString();
        return klassName.startsWith("com/fr/license/selector/");
    }
}  

```

代码很显而易见了， 作用是 `dump` 所有 以 `com/fr/license/selector/` 开头的 类的· 字节码。

然后编译成class文件

要使用这个首先需要把  `sa-jdi.jar` 加到 `java` 的 `classpath` 里。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1510917062153e72v6rn3.png?imageslim)

进入 刚刚写的 `filter` 类的class文件的目录下。执行

```

java  -Dsun.jvm.hotspot.tools.jcore.filter=MyFilter  -Dsun.jvm.hotspot.tools.jcore.outputDir=d:\dump  sun.jvm.hotspot.tools.jcore.ClassDump 5308

```

把`MyFilter` 改为你自己的类名， `5308` 为目标 java进程的 `pid`(可以使用 `jps` 查看）。然后就会在 `d:\dump ` 产生相应的 `class` 文件。

### 问题解决
* 如果直接点击应用的 exe, 来启动应用，使用 jps 获取到的 pid， 可能没有办法附加， 所以我们要找到启动的命令， 比如 bat脚本里面。

* 一般大型应用会自带 jre, 我们要使用上面的技术，替换 jre,为我们的，才能正常dump, 否则会出现版本不匹配。
* windows下还需把 `sawindbg.dll` 放到 `jre/bin/` 和java.exe 同目录下。否则可能会遇到 加载不了这个 dll 的问题。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1510919261728mq8ffmr8.png?imageslim)


### 最后

搞java应用第一步还是找到启动的命令，便于后面的分析。一般别使用 `exe`启动应用