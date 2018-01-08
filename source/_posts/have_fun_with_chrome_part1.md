---
title: Play-with-chrome之环境搭建
authorId: hac425
tags:
  - pwn chrome
categories:
  - chrome
date: 2017-11-27 22:49:00
---
### 前言
浏览器漏洞在 `APT` 攻击中用的比较多，而且这基本上是用户上网的标配了，所以研究浏览器的漏洞是十分有前景的，我认为。我选择 `chrome` 浏览器 ( `chromium`和 `chrome`之间的关系请自行百度 )为研究对象，主要原因如下： 
- 用户基数大，大量的用户使用 `chrome`  或者由 `chrome` 改装的浏览器。
- 安卓从 `4.4` 就已经开始使用 `chromium` 和 `v8` 作为 `webkit`，所以`chrome` 中的漏洞极有可能在 安卓上也有。


工欲善其事，必先利其器 , 本文主要讲环境的搭建，包括 `chrome`的编译与调试 && `v8` 引擎到的编译与调试。


测试环境

```
Win10 64 位， Visual Studio 2015
```



### 正文

#### Chrome编译

**Visual Studio 2015**

如果你有比较稳定（**速度要快，不然得下特别久**）的 `翻墙` 方案，可以直接按照官方的教程来。

在不能 `翻墙` 时，可以按照我的方案来。

首先下载下面的资源, 其中包括 `chrome 58` 的源代码， 以及编译时需要的工具。

```
链接: https://pan.baidu.com/s/1qXMy19U 密码: 49kx
```

然后下载安装 `Visual Studio 2015` , 在安装的时候除了 `移动开发相关` 的取消掉，其他的都选上，以免重来 , 要不然重新安装又得花特别长的时间。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1511797573213lqdl1irn.png?imageslim)

如果系统语言是 `中文` 的话还需要，修改 `非Unicode 程序的语言` 为 ` 英语(美国) `  , 如下图所示

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1511797829186y0k8z77e.png?imageslim)

**depot_tools**

然后解压 `depot_tools-2017-1-ALL.rar` 到一个目录，目录名不要有 `空格`, `中文` 。然后把目录添加到环境变量，后面编译时要用到。

比如我的 `depot_tools` 的目录是 `D:\depot_tools\depot_tools`

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15117981790191rhl9y6l.png?imageslim)

然后新建一个 `DEPOT_TOOLS_WIN_TOOLCHAIN` 系统变量， 其值设为 `0`.

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1511798411307ye1pwmcl.png?imageslim)

**设置 chromium 源码**



首先解压 `chromium` 到一个目录，然后解压 `develop-for-Stable-chromium-58.0.3029.81.zip` 文件，然后拷贝相应文件夹到  `chromium` 源码目录，覆盖掉相应的文件夹。

**编译**

进入源码目录，执行命令，生成编译需要的文件和 `vs 2015` 的解决方案。

```
gn gen out/Default --args="enable_nacl=false"
gn args out/Default --ide=vs
```
然后使用 `ninja` 编译
```
ninja -C out\Default chrome
```
如果没有问题，等几个小时就好了。然后会在 `out\Default` 下生成 `chrome.exe` 和相关的 `dll` 和  `pdb` 调试文件。


**调试**


**方案一**

使用 `Visual Studio 2015` 加载 `all.sln` 直接调试。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1511800354896kkv4p42s.png?imageslim)




**方案二**


用 `Visual Studio 2015` 会非常的慢， 可以使用 `windbg preview` 调试，图形化，而且快，也有 `windbg` 的强大功能


`windbg preview` 可以在  `windows store` 下载

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512744068940bhb543ao.png?imageslim)

打开点击 左上角 `文件`， 根据情况设置好即可。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512744193260miecf7qu.png?imageslim)

这里以 调试 `node` 为例 （原因是 `node` 使用 `v8` ）

首先进入 `settings` 设置符号路径。
![paste image](http://oy9h5q2k4.bkt.clouddn.com/15127443375937hbphlup.png?imageslim)
然后根据上上图设置调试的程序 和 参数。 点击 `ok` 运行之
![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512744412429sbp9bh3z.png?imageslim)

设置断点，断点断下来后可以直接定位到源码（自己编译）

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512745006342lg0jlhf3.png?imageslim)
调试信息非常的直观


### 编译 node

有时漏洞是位于 `v8` 引擎里面的。 我们可以使用 `node` 或者 `d8`来调试 `v8` ，这样调试速度比较快。

`node` 可以去 淘宝的 [镜像](https://npm.taobao.org/mirrors/node) 里面下载， 这样速度快。

下载完后，解压。如果是在 `windows` 下编译，先运行

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1512746124924rwpwxyab.png?imageslim)

生成 `vs` 解决方案，然后编译就行了。
如果在 `linux` 下 直接 

```
./configure --debug && make -j8
```
