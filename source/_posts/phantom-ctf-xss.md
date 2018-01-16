---
title: 使用 PhantomJS 来实现 CTF 中的 XSS 题目
authorId: rexskz
tags:
  - phantom
  - xss
categories:
  - Develop
date: 2017-06-24 08:42
---

# 零：CTF、XSS 的概念

CTF 在这个博客中提到的已经很多了，它是一类信息安全竞赛，在比赛中，选手通过各种方式，从题目给出的文件或者网址中，获取到某一特定格式的字符串。

CTF 中比较常见的一个题型就是 XSS（跨站脚本攻击），大概的原理就是服务端没有正确过滤用户的输入，导致用户提交的畸形字符串被插入到网页中并被解析成 JavaScript 执行。在 CTF 中，XSS 一般用来拿管理员的 Cookie，伪造身份登录后台，再进行后续的渗透（顺便提一下，现在大部分网站的敏感 Cookie 都被设成了 HTTP Only，因此 XSS 是没法拿到的，需要用其它的方法）。

一个非常简单的反射型 XSS 注入如下（为了突出重点，我就不把页面写的这么完整了，一般的 CTF 题目也鲜有很符合规范的页面）：

```php
<html>
<body>
Hello <?php echo $_GET['name']; ?>!
</body>
</html>
```

如果我们输入的网址中，`name` 参数值为 `rex<script>alert(1)</script>`，那么整个网页会变成这样：

```html
<html>
<body>
Hello rex<script>alert(1)</script>!
</body>
</html>
```

页面上就会有一个弹框。当然，如果能成功 alert(1)，那么一般来说大概应该可能有其它方法来获取 Cookie，因此比较简单的 XSS 的检测方式通常是看页面上能否 alert(1)。

当然，XSS 还有其它方法，例如在一个论坛上发帖内容为 `<img src=# onerror=alert(1)>`，而这个论坛也没做输入过滤，那么这段恶意代码就会一直保留在这个帖子里，基本每个点进来的人都会遭殃。此为存储型 XSS。

就算服务端做了一些过滤，黑客也可能会绕过。例如服务端的过滤如下：

```php
function escape($str) {
    return preg_replace('/<script>/', '', $str);
}
```

想绕过的话，只需要使用 `<scr<script>ipt>alert(1)</script>` 即可，左边被过滤之后剩下的刚好又拼接成了一个 `<script>` 标签。

有一个很好玩的网站：[alert(1) to win](https://alf.nu/alert1)，是我在大一的时候某只姓三的学长给我的。这个网站给了你 `escape` 函数，你的目标就是输入 `input`，使其通过 `escape` 函数之后依旧可以 alert 出数字 1（注意是数字 1，不是字符串 1）。这个网站的题目对于目前的我来说还是比较难的，如果大家有兴趣，可以去挑战一下。

# 一：PhantomJS 的概念

我之前对电脑的认识是非常肤浅的。第一次听说虚拟机居然还可以跑在命令行下的时候，我心想：虚拟机软件本身没有图形界面，那你该怎么显示虚拟机里面的图形呢？后来特么又看到了 PhantomJS，居然是个没有图形界面的浏览器！当时还心想，这玩意又没法给人看，会有啥用啊……

后来接触了爬虫之后才逐渐理解了这玩意的用途。它是一个通过命令行和 API 操作的、没有图形界面的浏览器，专注于自动化测试、爬虫等不需要人们浏览，但需要获取数据的一些场合。

如果觉得 PhantomJS 官方的文档太多懒得看，针对一些简单的编程，看阮老师的这篇文章也可以：[PhantomJS -- JavaScript 标准参考教程（alpha）](http://javascript.ruanyifeng.com/tool/phantomjs.html)。

# 二：基于 PhantomJS 的 CTF-XSS-Checker 的实现

我的思路大概是参照了上面的网站实现的，但是上面的 `escape` 函数是返回了一个过滤之后的字符串，而我打算直接用 eval 方法。

先放一下界面好啦！可以看到，上面网站中的 `escape` 函数被我改成了 `check`，里面会有一句 `eval`。

![0](https://dn-rexskz.qbox.me/blog/article/phantom-ctf-xss/0.png)

由于 Node.js 与 PhantomJS 的交互最为简单，因此后端使用 Node.js 来编写。思路其实很简单：启动一个服务器，针对前端的静态文件直接返回文件内容（当然，这一点也可以用 Nginx 代劳），针对题目生成对应的题目网页，针对 `/check` 路由根据 POST body 进行 XSS 判断。

具体的路由逻辑我就不写了，毕竟即使不会开服务器，不会写路由，使用 koa 等框架也能很轻松地实现。这里重点说一下前后端的检验流程。写一个网页解释器实在是太难，而且也不值得，所以最简单的方法就是不如就让它 alert 成功，只不过我们修改一下 alert 函数罢了。

前端先生成一个隐藏的 `iframe`，通过劫持里面的 `onerror`、`console.log`、`alert` 等函数来处理，通过 HTML5 Message API 在父页面和 `iframe` 之间传递信息。具体代码如下：

```javascript
window.onerror = function (a) {
    parent.postMessage({
        error: a.toString()
    }, "*");
};

window.console = window.console || {};
window.console.log = function (a) {
    parent.postMessage({
        console: a
    }, "*");
};

window.alert = function (a) {
    if (a === 1)
        parent.postMessage({
            success: 1
        }, "*");
    else if (a == 1)
        parent.postMessage({
            warning: "You should alert *NUMBER* 1."
        }, "*");
    else {
        parent.postMessage({
            warning: "You need to alert 1."
        }, "*");
    }
};

window.onmessage = function (a) {
    try {
        check(a.data);
    } catch(e) {
        parent.postMessage({
            error: e.toString().split("\\n")[0]
        }, "*");
    };
};
```

然后父页面通过返回的数据来处理就可以了，例如 onerror 的时候就将下面的黄条变红，并显示传过来的信息，如果 success 了，就将数据发给服务端进行验证。代码如下：

```javascript
// script 就是上面说的要嵌入 iframe 里面的代码
iframe.src = 'data:text/html,' + encodeURIComponent(problemText.replace(/\n\s*/g, '')) + script;
iframe.onload = function () {
    this.contentWindow.postMessage(textarea.value, '*');
};

// 父页面通过 iframe 传回来的信息进行相应的处理
window.onmessage = function (e) {
    var d = e.data;
    console.log(d);
    if (d.success !== undefined) {
        tab.className = 'rs-tab rs-tab-success';
        tab.innerText = 'Local check passed, running server check...';
        // server check
        var xhr = new XMLHttpRequest();
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                if (xhr.status === 200) {
                    tab.innerText = 'Server response: \'' + xhr.responseText + '\'.';
                }
            }
        };
        xhr.open('POST', '/check', true);
        xhr.send(JSON.stringify({
            id: location.pathname.match(/^\/(\d+)$/)[1],
            ans: textarea.value,
        }));
    } else if (d.warning !== undefined) {
        tab.className = 'rs-tab rs-tab-warning';
        tab.innerText = d.warning;
    } else if (d.error !== undefined) {
        tab.className = 'rs-tab rs-tab-danger';
        tab.innerText = d.error;
        output.innerText = '';
    } else if (d.console !== undefined) {
        output.innerText = d.console;
    }
};
```

这样本地的检验就可以啦！去看看服务端的 `/check` 是怎么写的。由于服务端是接收 JSON 返回 JSON 的，因此如果出了结果，直接输出一段 JSON 即可。假设我们已经想办法获取到了用户输入（上面那段代码中的 `ans`）、检验函数（之前提到的 `check`），那么可以这样写：

```javascript
var input = /* 获取到的 ans */;
var outputStr = '';

function output(obj) {
    outputStr = JSON.stringify(obj);
}

window.onerror = function (a) {
    output({ error: a.toString() });
}

window.alert = function (a) {
    if (a === 1) {
        output({ success: 1 });
    } else if (a == 1) {
        output({ error: "You should alert *NUMBER* 1." });
    } else {
        output({ error: "Server check failed, you need to alert 1." });
    }
};

/* 在这儿注入 check 函数的实现 */

try {
    check(input);
} catch (e) {
    output({ error: e.toString().split("\\n")[0] });
} finally {
    return outputStr;
}
```

说了这么多流程，终于要用到 PhantomJS 啦！我们需要用它创建一个页面，执行上面的代码，获取返回结果，并且在用户提交耗资源的操作（例如死循环）时及时将其关闭。

```javascript
var phantom = require('phantom');
    var phInstance = null;
    var exitted = false;
    phantom.create()
        .then(instance => {
            phInstance = instance;
            return instance.createPage();
        })
        .then(page => {
            var script = /* 上面提到的 script */;
            var evaluation = page.evaluateJavaScript(script);
            evaluation.then(function (html) {
                html = JSON.parse(html);
                if (html.success) {
                    res.write('Check passed, flag: ' + /* 对应题目的 flag */);
                    res.end();
                } else {
                    res.write(html.error);
                    res.end();
                }
                if (!exitted) {
                    phInstance.exit();
                    exitted = true;
                }
            });
        })
        .catch(error => {
            console.log(error); // eslint-disable-line no-console
            if (!exitted) {
                phInstance.exit();
                exitted = true;
                res.write('PhantomJS error');
                res.end();
            }
        });
    // prevent time limit exceeded
    setTimeout(function () {
        if (!exitted) {
            phInstance.exit();
            exitted = true;
            res.write('TLE');
            res.end();
        }
    }, 5000);
}
```

最后配上一点样式，就大功告成啦！

![1](https://dn-rexskz.qbox.me/blog/article/phantom-ctf-xss/1.png)

![2](https://dn-rexskz.qbox.me/blog/article/phantom-ctf-xss/2.png)

![3](https://dn-rexskz.qbox.me/blog/article/phantom-ctf-xss/3.png)

----

P.S. 即将到来的 NUAACTF 会使用这个程序来设计 XSS 题目。当然，题目与 Flag 均不是本文中放出来的这些。

P.S.S. Chrome 目前也推出了 Headless 模式，而且支持 Chrome 的全部特性。PhantomJS 作者表示自己要失业了……23333
