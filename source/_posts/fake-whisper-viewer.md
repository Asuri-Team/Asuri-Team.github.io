---
title: 让老司机纷纷翻车的“悄悄话查看器”究竟有啥名堂？
authorId: rexskz
tags:
  - reverse
categories:
  - Reverse
date: 2016-06-17 12:12
---

# 0x00 Introduction

相信大家一定被所谓的“QQ悄悄话查看器”刷屏了吧？从上个月开始我就郁闷，有人给我发悄悄话，然而我又猜不到是谁。有了这么一个 APP，岂不是可以调戏回去？然而大家的反应似乎不是这样的：

![1](https://dn-rexskz.qbox.me/blog/article/qiaoqiaohua/1.png)

“这一切来的太快”

![2](https://dn-rexskz.qbox.me/blog/article/qiaoqiaohua/2.png)

“强行上车 车速过快 引发多起事故”

![3](https://dn-rexskz.qbox.me/blog/article/qiaoqiaohua/3.png)

“这很强势，很清真”

![4](https://dn-rexskz.qbox.me/blog/article/qiaoqiaohua/4.png)

“逸夫楼教室此起彼伏”

![5](https://dn-rexskz.qbox.me/blog/article/qiaoqiaohua/5.jpg)

“对不起，我们不认识”

就是这么个安卓 APP，害了好多老司机纷纷翻车。

下午刚陪女朋友上完自习（此处省略秀恩爱的若干字），各种群、空间、朋友圈就被这些图刷屏了。我所在的群中，有四个群里面已经有了这个文件。于是我就顺手反编译了一下，看看它究竟是个什么玩意儿。

**如果迫不及待的话，我可以提前告诉你，这就是某个人顺手写出来的整人的玩意儿。好了全文到此结束。**

![坑爹呢这是！](https://dn-rexskz.qbox.me/blog/article/qiaoqiaohua/keng-die-ne.gif)

当然，对于感兴趣的同学，我当然要说一下逆向这个 APP 的过程。由于这个 APP 写的很简单，因此**逆向起来没有任何难度**，大神就不要喷啦。

后文可能会有福利哦~

# 0x01 Unzip

呃，之所以需要这一步，是因为如果直接用 `dex2jar` 来反编译 apk 的话会报错，大概是打包的时候出了问题吧。

```bash
$ d2j-dex2jar.sh qq_secret.apk
dex2jar qq_secret.apk -> qq_secret-dex2jar.jar
com.googlecode.dex2jar.DexException: java.util.zip.ZipException: invalid entry compressed size (expected 252773 but got 252747 bytes)
        at com.googlecode.dex2jar.reader.DexFileReader.opDataIn(DexFileReader.java:217)
        at com.googlecode.dex2jar.reader.DexFileReader.<init>(DexFileReader.java:229)
        at com.googlecode.dex2jar.reader.DexFileReader.</init><init>(DexFileReader.java:240)
        at com.googlecode.dex2jar.tools.Dex2jarCmd.doCommandLine(Dex2jarCmd.java:104)
        at com.googlecode.dex2jar.tools.BaseCmd.doMain(BaseCmd.java:174)
        at com.googlecode.dex2jar.tools.Dex2jarCmd.main(Dex2jarCmd.java:34)
Caused by: java.util.zip.ZipException: invalid entry compressed size (expected 252773 but got 252747 bytes)
        at java.util.zip.ZipInputStream.readEnd(Unknown Source)
        at java.util.zip.ZipInputStream.read(Unknown Source)
        at java.util.zip.ZipInputStream.closeEntry(Unknown Source)
        at java.util.zip.ZipInputStream.getNextEntry(Unknown Source)
        at com.googlecode.dex2jar.reader.ZipExtractor.extract(ZipExtractor.java:31)
        at com.googlecode.dex2jar.reader.DexFileReader.readDex(DexFileReader.java:129)
        at com.googlecode.dex2jar.reader.DexFileReader.opDataIn(DexFileReader.java:213)
        ... 5 more</init>
        ```

于是用压缩软件解包之后，反编译里面的 dex 文件即可：

```bash
$ d2j-dex2jar.sh classes.dex
dex2jar classes.dex -> classes-dex2jar.jar
```

然后用 `jd-gui` 载入，发现里面有两个大包：`com.e4a.runtime` 和 `com.o`，前者是安卓版的易语言运行环境，后者就是主程序了。

![6](https://dn-rexskz.qbox.me/blog/article/qiaoqiaohua/6.png)

看了几眼，发现 `R.class` 中声明的元素少得可怜。于是往下看到 `主窗口.class`：

```java
public void $define() {
    // ....
    图片框Impl local图片框Impl = new 图片框Impl(主窗口);
    Objects.initializeProperties(local图片框Impl);
    this.图片框1 = ((图片框)local图片框Impl);
    this.图片框1.左边((int)算术运算.取整(ByteVariant.getByteVariant((byte)0).mul(IntegerVariant.getIntegerVariant(系统相关类.取屏幕宽度()))));
    this.图片框1.顶边((int)算术运算.取整(ByteVariant.getByteVariant((byte)0).mul(IntegerVariant.getIntegerVariant(系统相关类.取屏幕高度()))));
    this.图片框1.宽度((int)算术运算.取整(ByteVariant.getByteVariant((byte)1).mul(IntegerVariant.getIntegerVariant(系统相关类.取屏幕宽度()))));
    this.图片框1.高度((int)算术运算.取整(ByteVariant.getByteVariant((byte)1).mul(IntegerVariant.getIntegerVariant(系统相关类.取屏幕高度()))));
    this.图片框1.背景颜色(-1);
    this.图片框1.显示方式(1);
    this.图片框1.图像("6M5UBF2J9ZI70.jpg");
    this.图片框1.可视(true);
    // ....
}
```

隐去了部分代码，可以看到这里全屏显示了一张图片。那么所谓的 `6M5UBF2J9ZI70.jpg` 是个什么东西呢？我们来翻一下 `assets` 文件夹好了：

![7](https://dn-rexskz.qbox.me/blog/article/qiaoqiaohua/7.png)

看到缩略图，好像是福利？于是点开大图。结果发现跟女朋友相比差了好多，并没有 xing 趣欣赏，不知道大家是什么反应？

继续往下看：

```java
public void 主窗口$创建完毕() {
    音量操作.置音量(4, 100);
    音量操作.置音量(4, 100);
    音量操作.置音量(2, 100);
    音量操作.置音量(3, 100);
    媒体操作.播放音乐("0.mp3");
    媒体操作.置循环播放(true);
    // ....
    this.系统设置1.屏幕锁定();
    this.系统设置1.保持屏幕常亮();
    this.系统广播1.注册广播("后台服务广播");
    this.系统闹钟1.设置闹钟(1, 500L, "闹钟");
    this.时钟1.时钟周期(500);
}
```

将音量调到最高，播放音乐，保持屏幕常亮……毕竟是易语言，想都不用想就知道是干什么的了~

看到有一段音乐，又想起了刚才的图片，于是打开听一听吧……

我还是不评价了，放一张别人的评论好了：

![0](https://dn-rexskz.qbox.me/blog/article/qiaoqiaohua/8.png)

![坑爹呢这是！](https://dn-rexskz.qbox.me/blog/article/qiaoqiaohua/keng-die-ne.gif)

还是继续往下看吧……

```java
public void 主窗口$按下某键(int paramInt, BooleanReferenceParameter paramBooleanReferenceParameter) {
    boolean bool = paramBooleanReferenceParameter.get();
    if (paramInt == 24) {
      bool = true;
    }
    if (paramInt == 25) {
      bool = true;
    }
    if (paramInt == 82) {
      bool = true;
    }
    paramBooleanReferenceParameter.set(bool);
}
```

两个音量控制键（24、25）、菜单键（82），大概是要屏蔽这三个按键吧。

```java
public void 时钟2$周期事件() {
    this.时钟1.时钟周期(0);
    系统相关类.创建快捷方式2("QQ悄悄话查看器0", 2130837504, "http://");
    系统相关类.创建快捷方式2("QQ悄悄话查看器1", 2130837504, "http://");
    系统相关类.创建快捷方式2("快手双击工具2", 2130837504, "http://");
    系统相关类.创建快捷方式2("快手双击工具3", 2130837504, "http://");
    系统相关类.创建快捷方式2("QQ悄悄话查看器4", 2130837504, "http://");
}
```

创建一堆奇怪的快捷方式。

```java
public void 系统广播1$收到广播(int paramInt) {
    主窗口.标题(this.系统广播1.取广播内容());
    if (主窗口.标题().equals("1")) {
        if (!应用操作.是否在前台()) {
            音量操作.置音量(4, 100);
            音量操作.置音量(1, 100);
            音量操作.置音量(2, 100);
            音量操作.置音量(3, 100);
            应用操作.返回应用();
            this.系统设置1.屏幕解锁();
        }
    }
    // ....
}
```

乍看起来像是保持前台运行的，如果被切到后台了，就强行跑到前台刷存在感（顺便如果你锁屏了人家还会帮你解个锁）。然而这个 `主窗口.标题().equals("1")` 的条件是个什么鬼？这个 class 没有什么可看的了，看最后的 `后台服务操作.class` 吧：

```java
public void 服务处理过程(String paramString) {
    boolean bool = paramString.equals("闹钟");
    int i = 0;
    if (bool) {
        for (;;) {
            i = IntegerVariant.getIntegerVariant(i).add(ByteVariant.getByteVariant((byte)1)).getInteger();
            系统相关类.发送广播("后台服务广播", 1, 转换操作.整数到文本(i));
            if (IntegerVariant.getIntegerVariant(i).cmp(ByteVariant.getByteVariant((byte)1)) == 0) {
                i = 0;
            }
        }
    }
}
```

这里可以看到发送广播的内容是 `1`，然后配上上面的 `主窗口.标题(this.系统广播1.取广播内容())`，这样就达到刷存在感的条件了。

**翻完了所有的代码，没发现疑似病毒或者其它恶意软件的痕迹。大家如果对上面的图片或者音频感兴趣，可以放心地安装使用。**

# 0x02 Result

所以，其实——

> 这就是某个人顺手写出来的整人的玩意儿。

![坑爹呢这是！](https://dn-rexskz.qbox.me/blog/article/qiaoqiaohua/keng-die-ne.gif)

嗯，不光整了一个人，而是若干高校的图书馆、逸夫楼、自习室。

好了，全文到此结束。
