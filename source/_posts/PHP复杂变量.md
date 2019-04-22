---
title: 从一道题讲PHP复杂变量
authorId: Zedd
tags:
  - php
categories:
  - Web 安全
date: 2019-04-11 01:57:32
---

近期有小伙伴问了我一道题，然后自己发掘到了一些关于 PHP 复杂变量不太被关注的问题。

> ​	文章首发于先知社区：https://xz.aliyun.com/t/4785

<!--more-->

[TOC]

##	起因

起因是因为一个小伙伴问了我一道题

```php
<?php
highlight_file(__FILE__);
$str = $_GET['str'];
$str = addslashes($str);
if(preg_match('/[A-Za-z0-9]+\(/i',$str) == 1){
    die('hack');
}
eval('$a="' . $str . '";');
?>
```

自己想了好一会好像并没有能用自己当时的现有知识去解决这个问题，于是我去搜集了一些资料学到了一些新的知识。感兴趣的小伙伴可以先自己做一下哈～



###	题目解释

整个代码逻辑非常简单，接受一个`$_GET['str']`的传参，在经过`addslashes()`函数转义特殊符号与正则表达式检验之后，传入`eval()`当中拼接到`$a="";`变量当中。

既然有`eval()`，那是不是可以执行命令呢？答案是当然可以的。

首先我们来看正则表达式的效果如下图所示

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g1wudhruk9j20fa0bq753.jpg)

如果小括号前有数字或者字母的话就会`die()`掉整个程序，大概意思就是防止直接使用函数，例如不能直接使用`system('ls')`这样子。



##	PHP 复杂变量

###	Introduction

下面我们简单介绍一个关注度比较少的一个 php 知识——PHP 复杂变量。按照 php 官方文档对复杂变量的介绍

> ​	复杂语法不是因为其语法复杂而得名，而是因为它可以使用复杂的表达式。
>
> 任何具有 [string](https://www.php.net/manual/zh/language.types.string.php) 表达的标量变量，数组单元或对象属性都可使用此语法。只需简单地像在 [string](https://www.php.net/manual/zh/language.types.string.php) 以外的地方那样写出表达式，然后用花括号 *{* 和 *}* 把它括起来即可。由于 *{* 无法被转义，只有 *$* 紧挨着 *{* 时才会被识别。可以用 *{\$* 来表达 *{$*。

我们介绍一个简单的例子：

```php
<?php
$great = 'fantastic';

// 无效，输出: This is { fantastic}
echo "This is { $great}";

// 有效，输出： This is fantastic
echo "This is {$great}";
echo "This is ${great}";
```

也就是说在 php 中，我们还可以利用`${xxx}`的形式来表达一个变量。



###	Usage

官方文档还给出了一个非常有意思的 Note:

> ​	**Note**:
>
> 函数、方法、静态类变量和类常量只有在 PHP 5 以后才可在 *{$}* 中使用。然而，只有在该字符串被定义的命名空间中才可以将其值作为变量名来访问。只单一使用花括号 (*{}*) 无法处理从函数或方法的返回值或者类常量以及类静态变量的值。

函数、方法！所以我们根据文档可以怎么利用呢？

```php
<?php
highlight_file(__FILE__);
$a = "${phpinfo()}";
?>
```

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g1xyg3hhraj22800v6qgb.jpg)



###	Thinking

然而为什么可以这么做呢？虽然官方文档很明确的指出了，但是是不是还是有一点费解的感觉？

其实在 php 中，我们可以查阅 php 文档知道有

> ​	PHP 中的变量用一个美元符号后面跟变量名来表示。变量名是区分大小写的。
>
> 变量名与 PHP 中其它的标签一样遵循相同的规则。一个有效的变量名由字母或者下划线开头，后面跟上任意数量的字母，数字，或者下划线。按照正常的正则表达式，它将被表述为：`[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*'`。

我们可以看到`${phpinfo()}`里面在严格意义上来说并不是一个变量，那为什么可以执行呢？

让我们来看一个例子

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g1xypdkfm8j22800x64cb.jpg)

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g1xyr8th9xj213i0lq44j.jpg)

在 php 中，可以接受函数的返回值作为变量名，而`phpinfo()`的返回值为`TRUE`，所以先将`phpinfo()`执行了，将返回值返回作为了变量名。

我们可以再来看一个例子。

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g1y1vwzzh3j21jo09gn22.jpg)

这里就更清楚的说明了执行了`system('whomai')`并把其返回值`zedd`作为了变量，最后`$zedd`才被修改了。

这里也与[php变量解析的复杂语法](<https://www.chabug.org/ctf/425.html>)作者 @s1ye 师傅交流了一下，也跟他讨论了他文章中有几个地方存在的疏忽之处，`${phpinfo()}`得到的并非是`$TRUE`，具体可以使用上述方法看看。



##	Challanges

###	Easy

我们不妨先把问题简化，如果没有任何防护，我们可以怎么做呢？

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$str = $_GET['str'];
eval('$a="' . $str . '";');
?>
```

直接传入拼接自然我们肯定有双引号闭合进而执行命令。



###	Medium

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
$str = $_GET['str'];
$str = addslashes($str);
eval('$a="' . $str . '";');
?>
```

那加上`addslashes()`方法呢？既然不能逃逸双引号，我们就可以利用 php 复杂变量来处理。

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g1y2cip77aj20ws0ek40c.jpg)



###	Difficult

```php
<?php
highlight_file(__FILE__);
$str = $_GET['str'];
$str = addslashes($str);
if(preg_match('/[A-Za-z0-9]+\(/i',$str) == 1){
    die('hack');
}
eval('$a="' . $str . '";');
?>
```

好的，终于回到了我们题目，这样的话就不能单纯地使用函数方法了。那我们可以怎么做呢？

如果开启了`Notice`回显的话，我们可以利用反引号就可以简单实现命令执行了

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g1y2gxu0vcj22800lgq97.jpg)

那要是没开启呢？自然不可行了。

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g1y2j8au4cj20vu0pago5.jpg)

接下来就可以利用可变函数的与字符串拼接的特性了，简单来说就用下图的技巧，详细的可以移步个人博客查看[Some Tricks of Bypass php waf](<https://blog.zeddyu.info/2019/02/28/Some-Tricks-of-Bypass-php-waf/>)

![](<https://ws1.sinaimg.cn/large/64ef14dcgy1g0m4ju4fjfj20m80b4dge.jpg>)

![](<https://ws1.sinaimg.cn/large/64ef14dcgy1g0m55go2pvj20m80b43zd.jpg>)

所以我们可以这里玩法就很多样了

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g1y2o9jg8uj22800g60x4.jpg)

关于 php 复杂变量的玩法还有很多，这里就大概说到这里吧，文中有不对之处还望师傅们斧正。



##	Reference

[php 文档-String 字符串](<https://www.php.net/manual/zh/language.types.string.php>)

[php 文档-复杂(花括号)语法](<https://www.php.net/manual/zh/language.types.string.php#language.types.string.parsing.complex>)

[php变量解析的复杂语法](<https://www.chabug.org/ctf/425.html>)