---
title: JCTF2015非官方writeup
authorId: rexskz
tags:
  - jctf
  - writeup
categories:
  - Writeup
date: 2015-11-27 10:56
---

这次水平有限，所以只做出了四道题……请大家尽情鄙视我们吧……

# 0x1

在资源文件夹中有一个bababa.wav的文件，用AU打开，发现是四声道，下面的两个音轨是二进制波形。按照高低不同分为01记下后，每八位一组，转换为char，即可得到flag。

# 0x2

根据提示可得栈226有问题， 发现所有记录中均使用DES-EBC加密，key为stringWi。从github上down一个des解密算法，把226的post数据base64解码后使用des解密，即可得到flag。

```json
{
  "bundle" : "com.Securitygossip",
  "os" : "0.0.1",
  "status" : "solved",
  "app" : "XcodeGhost",
  "country" : "CN",
  "language" : "zh-Hans",
  "version" : "426",
  "type" : "iPhone6,",
  "timestamp" : "1440065480",
  "name" : "JCTF{XcodeGhost_is_everywhere}"
}
```

# 0x6-1

在根目录下的robots.txt中发现如下字符串：

```yaml
User-agent: *
Disallow: /13c087c969641bc59fffc97dccd5e673.php?ajiao=whosays*$
```

最后两个字符看起来像一个正则表达式。

打开Disallow的网址之后，发现php文件的ETAG有点特殊，其它文件的ETAG都是正常的，只有php文件的ETAG是一串连起来的字符：

```text
61573135623356795a6d467563773d3d
```

将ETAG每两位分隔开，作为URL编码来解码，得到一个base64串：

```text
aW15b3VyZmFucw==
```

解码后得到“imyourfans”。

考虑之前robots.txt中的提示，将此字符串带入参数：

```text
?ajiao=whosaysimyourfans
```

访问之后，可以在最下方找到如下代码：

```html
<script>alert("JCTF{keep_clam_and_carry_on}")</script><script>alert("# 0x2/1c8bd3e2bdb4c43d317ef5fbef73aab0.php")</script>
```

# 0x6-2

查看网页源代码，可以看到一段注释：

```html
<!--my birthday 19xxxxxx-->
```

根据注释和上面`<img>`标签的alt，容易联想到“刘涛生日”，百度可得19780712。然而输入进去发现并没有立即提交。

看到网页中的一段js，这是在用jQuery发post包：

```javascript
function sendreq() {
    var requestUrl = "./1c8bd3e2bdb4c43d317ef5fbef73aab0.php";
    $.ajax({
        type: "post",
        data: "pwd=" + $("#liutao").val(),
        dataType: "text",
        contentType: 'application/x-www-form-urlencoded',
        url: requestUrl,
        async: false,
        complete: function() {},
        error: function(xhr) {
            alert(xhr);
        },
        success: function(msg) {
            if (msg == "error")
                alert("Password Error!");
            else
                window.location.href = msg;
        }
    });
}
```

其中data的值为“pwd=19780712”，用Fiddler模拟发个包就好了，可以在网页最下方发现提示：“不是土豪不过关，请用iphone7浏览”……主办方丧心病狂……

然后我当时智商太低，并没有意识到iphone只出到了6s，傻傻去百度iphone7的参数去了……结果真发现了，iphone7使用的是iOS10系统，所以将浏览器UA中的版本改成10就可以了，访问得到一个图片的路径，以及一句提示：“wrong session”。

打开图片，里面是一些用xss获取到的cookie，将PHPSESSID替换掉再访问，即可获取flag。
