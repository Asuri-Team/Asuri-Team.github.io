---
title: NUAACTF 2016 官方 Writeup
authorId: rexskz
tags:
  - nuaactf
  - writeup
categories:
  - Writeup
date: 2016-04-26 16:05
---

# Web1

签到题，打开浏览器的Console即可找到flag：

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/1.png)

下面那行带有中文的句子是我早上修改界面的时候加上去的，同样的彩蛋在网页源代码中也有，就是每个页面查看源代码之后显示的那个佛祖，23333。

# Web2

仔细看会发现题干中百度的链接有点奇怪：

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/2.png)

根据题目提示，用百度搜索“一只苦逼的开发狗”，发现出题人的博客，第一篇文章有提示：

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/3.png)

看起来是base64编码，解码之后查看文件类型：

```bash
$ echo "bnVhYWN0ZiU3Qi93ZWIyL2NlYmE2ZmJiZjBlZGU0MzI1MjY0MWNkMzM2ZTM2YTAzJTdE" | base64 -d > out.dat
$ file out.dat
out.dat: ASCII text, with no line terminators
$ cat out.dat
nuaactf%7B/web2/ceba6fbbf0ede43252641cd336e36a03%7D
```

是一个URI编码之后的字符串，解码即可得到flag，也是下一题的地址：

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/4.png)

# Web3

将题目网址的路径替换成Web2的flag，跳转到http://xxx.xxx.xxx.xxx:8080/web2/xedni.php，查看源代码之后发现了一段PHP代码：

```php
<?php
    if(isset($_GET["password"]) && md5($_GET["password"]) == "0e731198061491163073197128363787")
        echo file_get_contents("flag.txt");
    else
        echo file_get_contents("xedni.php");
?>
```

所以我们的目标就是反查md5。扔进cmd5中发现是一条付费记录，我没钱所以看不了。但是扔到百度中即可得到结果：s1184209335a。于是访问网址：

http://xxx.xxx.xxx.xxx:8080/web2/xedni.php?password=s1184209335a

得到flag：nuaactf{/web3/b481b86354a413b898b6f01af539366d}。

其实还有一种解法，因为PHP的一个“特性”：任何0e开头的字符串都会被解析为数字0，因此只需要找到任意一个md5之后0e开头的字符串，放进password参数中提交即可。看题目描述感觉本题应该是用此方法解，与出题人讨论之后，认为如果考此方法，代码中的md5判断改为”0e23333”更好一点。

# Web4

将题目网址的路径替换成Web3的flag，跳转到http://211.65.102.2:8080/web3/login.php，这是一个登录界面，没有任何多余信息，因此考虑SQL注入。测试了一下发现有报错，但是报错中没有语句相关的信息，因此只能盲注，如果将数据库中的数据dump出来，将花费很长的时间。根据提示“需要用管理员账号来看flag”，于是猜想用户表中有一列标记是否为admin。直接在用户名中输入【' and 1=0 union select 1,1,1,1 -- 】（别忘了一开始的单引号和最后的空格，1的数量是从两个开始试出来的，表示用户表一共有4列），提交之后会跳转，通过抓包看到flag：nuaactf{hApPy_haCk1n9_t0Day}，以及下一题的地址。

为了验证猜想是否正确，可以使用sqlmap扫一下：

```bash
$ ./sqlmap.py -u "http://xxx.xxx.xxx.xxx:8080/web3/login.php" --forms –dbs
available databases [2]:
[*] information_schema
[*] nuaactf
```

然后看一下nuaactf里面有什么信息：

```bash
$ ./sqlmap.py -u "http://xxx.xxx.xxx.xxx:8080/web3/login.php" --forms -D nuaactf --tables --dump
```

可以dump出表结构，如下图所示：

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/5.png)

证实了刚才的猜想。

# Web5

根据题目描述“你从哪里来“，可以推测是修改HTTP头。在HTTP头中加上：

```http
Origin: http://cs.nuaa.edu.cn/
X-Forwarded-For: 【cs.nuaa.edu.cn的IP】
```

得出flag：nuaactf{C0ndrulation!&#95;y0u&#95;f1n1shed_a11_web_quest}。

# Reverse1

这是一个apk，先用dex2jar将其转换为jar文件：

```bash
$ d2j-dex2jar.sh reverse1.apk
dex2jar reverse1.apk -> reverse1-dex2jar.jar
```

用jd-gui打开，在cc.sslab.app1中发现flag：nuaactf{Happy_crack1ng_app!}。

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/6.png)

# Reverse2

根据题目描述，可能跟音频有关，于是用压缩工具打开apk（apk本质上是个压缩包），在res/raw文件夹中发现sound.wav。使用高级一点的音频工具（例如AU）打开，发现有四个声道，下面的两个声道非常可疑。

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/7.png)

于是就变成了一道数数题，令上面的为1，下面的为0，得到如下的01序列：

```text
011011100111010101100001011000010110001101110100011001100111101101110011011010000011000001110010011101000101111101100110001100010100000101100111
```

然后将其每8个一组，转换为ASCII字符：

```javascript
a = '01101110 01110101 01100001 01100001 01100011 01110100 01100110 01111011 01110011 01101000 00110000 01110010 01110100 01011111 01100110 00110001 01000001 01100111'.split(' ')
b = ''
a.forEach(function (item, index) {
    ascii = parseInt(item, 2)
    b += String.fromCharCode(ascii)
})
console.log(b)
```

得出flag：nuaactf{sh0rt_f1Ag}。（原数据缺少右花括号，比赛现场修正了题目。）

# Reverse3

根据题目描述（拖拽即可生成界面）以及exe文件打开之后的窗口图标，可以确定这是一个.NET的程序。使用ILSpy（或者.NET Reflector）打开，在reverse3的Form1中发现：

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/8.png)

分析可得：点击按钮之后判断你输入的字符串经过decrypt2加密后是否等于通过decrypt1解密过的一串字符串，如果相等则显示“Correct Flag!”。也就是说，flag应该是图中的长字符串经过decrypt1解密后再经过decrypt2解密得到的答案。

在reverse3中有decrypt1和decrypt2两个class，里面都有加密和解密函数（据出题人说，为了降低难度特地写的解密函数，本应由参赛者自行推断解密算法）。扔进C#环境中运行一遍即可。

由于我本机没有C# 环境，因此搜索出来一个支持多种语言的在线运行环境。将decrypt1、decrypt2、MyMap三个类摘出来拼到一个文件中，自己另写了一个Test类来调用。

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/9.png)

上图是我在Sublime Text中整合的代码，为了方便截图我将三个类折叠起来了。 下图是在一个在线运行网站上得出的结果。

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/10.png)

最终得出flag：NUAACTF{HAPPYCRACK1NGCHHARP}。

# Reverse4

这是一个Mac下的二进制文件，使用IDA打开，看到 _main函数的逻辑是：获取程序调用时的第一个参数（argv1），使用encrypt函数加密之后输出。

于是找到encrypt函数，不得不说IDA的变量改名和注释功能挺好用的，一番折腾之后见下图。其中关于&#95;DefaultRuneLocale&#95;ptr和 __maskrune的知识，请参考下面的两个文件：

[http://users.sosdg.org/~qiyong/mxr/source/lib/libc/locale/runetable.c#L54](http://users.sosdg.org/~qiyong/mxr/source/lib/libc/locale/runetable.c#L54) [http://users.sosdg.org/~qiyong/mxr/source/lib/libc/locale/runetype_file.h#L60](http://users.sosdg.org/~qiyong/mxr/source/lib/libc/locale/runetype_file.h#L60)

这也是编译器实现isalpha和isupper等函数的原理。

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/11.png)

可能是IDA的F5工具逻辑有问题，将一个循环编译成的汇编还原成伪代码的结果很奇怪。再进行一遍逻辑整理之后，推测出源代码如下：

```c
void encrypt(char *str, char *buffer) {
    int str_length = strlen(str);
    int password_length = strlen(password);
    // 生成密码字典dict
    for (int i = 0; i < password_length; i++) {
        alphabet[password[i] - 'a'] = true;
        dict[i] = password[i] - 'a';
    }
    for (int i = 0; i < 25; i++)
        if (alphabet[i] == false)
            dict[password_length++] = i;
    // 使用dict来置换对str中的字母
    for (int i = 0; i < str_length; i++) {
        if (isalpha(str[i]) == true) {
            t = tolower(str[i]) - 'a';
            c = str[i];
            if (isupper(c) == false) buffer[i] = dict[t] + 'a';
            else buffer[i] = dict[t] + 'A';
        }
        else buffer[i] = t;
    }
}
```

可以看出，上方生成的字典其实就是a-z的字母表，将password放到开头，然后剩下的字母依次排列。下方的替换其实就是str[i]→dict[str[i]]，也就是说，这是一个用password做表头的标准字头密码体制。至于password是什么，用IDA全局搜索一下就知道了：

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/12.png)

可以看到password的值为”asuri”，那么密码表就是”asuribcdefghjklmnopqtvwxyz”，写程序也好，手动替换也好，可以得出加密串ktaauqb{Apto1_Mo0qiuq_Y0t} 的原串，也就是题目的flag为：nuaactf{Asur1_Pr0tect_Y0u}。

顺便提一下：我在IDA中看到有一个函数叫generateDict，但是在main中并没有被调用，与出题人核对一遍源代码之后才发现，源代码在encrypt函数中调用了generateDict，然而编译器将它inline优化掉了，因此encrypt中才有了生成字典的代码段。

# Pwn1

打开链接发现是一个txt文件，可以断定用了jsfuck，因此将代码复制粘贴到浏览器中执行即可得到flag：nuaactf{Isnt_js_FunNy>?}。

# Pwn2

裸最短路问题，可以使用Dijkstra或者SPFA来解决。最终得到flag：nuaactf{1159}。

# Pwn3

下载下来一个Linux下的ELF文件，直接用Linux环境执行会输出：

```text
Cannot find flag files!,use default flag: nuaactf{FLAG_w0nt_b1_s0_EASY}
```

这个flag是一个假的flag，因此需要继续破解。扔到IDA中F5一下，然后定位到main函数，发现先在本地读取了flag.txt，如果没有的话输出上面那段话，因此只能通过nc连过去之后输入，或者在本机先输出，然后通过管道接到nc里面。

剩下的绝大部分代码都是连接socket的，只有最后一段：

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/13.png)

于是找到str_echo函数，发现并未读取v7，然而判断了v7是否等于0x800，因此可以确定有缓冲区溢出漏洞。找到result = read(a1, &amp;s, 500uLL)，那么漏洞应该在这里。到上面查看s和v7的位置吧，如下图所示，s的起点在sp+10h，v7的起点在sp+124h，说明需要读入114h个8的长度（因为sizeof(char)=8）才可以开始读v7。

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/14.png)

那么方法就是构造这样一个二进制串：一开始是长度为114h*8（2208位二进制）的随机串，最后补上一个0x800的二进制串就可以了。如果使用WinHex或者Sublime Text查看这个串，应该是先有552个0，之后接了0008（大端模式）。将这个文件存成一个二进制文件例如a.dat，然后在命令行中输入：

```bash
$ cat a.dat | ./nc.exe xxx.xxx.xxx.xxx 43321
```

得到flag：nuaactf{explo1t_a_l0t_fun}。

# Pwn4

模拟题，读入矩阵并按照题目描述来操作。最后求行和与列和的输出一共24个数字，根据提示说最终答案是一个长度为24的字符串，考虑到这些数字对127取余后可能就是flag。最终得到结果：nuaactf{M4tr1X_15_gRe4t}。

# Misc1

使用file命令查看文件类型：

```bash
$ file misc1.rar
misc1.rar: PNG image data, 454 x 340, 8-bit/color RGBA, non-interlaced
```

发现是一个PNG文件。修改后缀打开得到flag：nuaactf{Hello_MISC_nOt_RAR}。

# Misc2

使用binwalk命令查看文件数据：

```bash
$ binwalk misc2.png

DECIMAL HEXADECIMAL DESCRIPTION
--------------------------------------------------------------------------------
0       0x0         PNG image, 512 x 512, 8-bit/color RGBA, non-interlaced
85      0x55        Zlib compressed data, best compression
2773    0xAD5       Zlib compressed data, best compression
195124  0x2FA34     Zip archive data, at least v1.0 to extract, compressed size: 28, uncompressed size: 28, name: flag.txt
195244  0x2FAAC     End of Zip archive
```

发现在第195124的地方是一个zip压缩包。于是使用dd命令将其提取出来：

```bash
$ dd if=misc2.png of=out.zip bs=1 skip=195124
142+0 records in
142+0 records out
142 bytes (142 B) copied, 0.00722364 s, 19.7 kB/s
```

打开out.zip，里面是一个flag.txt，内容为：nuaactf{z1p_0vEr_Png_1s_fun}。

# Misc3

使用StegSolve工具打开文件，切换至Red plane 1，在文件左下角有一个二维码。

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/15.png)

扫码得出来一个字符串：

```text
QlpoOTFBWSZTWXhAk1kAAAtfgAAQIABgAAgAAACvIbYKIAAigNHqNGmnqFMJpoDTEO0CXcIvl9SeOAB3axLQYn4u5IpwoSDwgSay
```

可以看出这是一个Base64编码。然而这串编码并不是编码了一段文字，可能是一段二进制数据。将其提取出来，并查看文件类型：

```bash
$ echo "QlpoOTFBWSZTWXhAk1kAAAtfgAAQIABgAAgAAACvIbYKIAAigNHqNGmnqFMJpoDTEO0CXcIvl9SeOAB3axLQYn4u5IpwoSDwgSay" | base64 –d > out.dat
$ file out.dat
out.dat: bzip2 compressed data, block size = 900k
```

发现是一个bzip2压缩的文件，将其解压即可得到flag：

```bash
$ cat out.dat | bunzip2
nuaactf{qrc0de_in_C011ect1on!}
```

# Misc4

首先先用dex2jar将apk解包，使用jd-gui查看，发现里面超级复杂，于是转向pcapng文件，用Wireshark打开之后，过滤出HTTP请求，发现每个POST请求的JSON串都会带上一个body参数，而且是经过加密的，与题目给的数据很像。于是思路变为查找body的加密过程。使用jd-gui全局查找，发现在<code>com.huidong.mdschool.net.HttpTask.class</code>文件的<code>onPreExecute</code>函数中有如下代码：

```java
for (String str = "'" + AesUtil.encrypt(localGson.toJson(this.bodyRequest), new StringBuilder("www.wowsport.cn").append(BodyBuildingUtil.getDeviceId(this.context)).toString()) + "'";; str = localGson.toJson(this.bodyRequest)) {
    localHashMap.put("body", str);
    this.jsonObject = localHashMap.toString();
    return;
}
```

于是找到了加密方式：

```java
AesUtil.encrypt(localGson.toJson(this.bodyRequest), new StringBuilder("www.wowsport.cn").append(BodyBuildingUtil.getDeviceId(this.context))
```

定位至AesUtil.encrypt函数，如下图所示：

![0](https://dn-rexskz.qbox.me/blog/article/nuaactf-2016/16.png)

其中函数<code>secureBytes</code>的作用是将字符串长度变为16，多则截取少则补零。然后<code>encrypt</code>使用了AES做加密，key就是那个16位字符串，也就是<code>secureBytes(new StringBuilder("www.wowsport.cn").append(BodyBuildingUtil.getDeviceId(this.context)))</code>。前面一共15位，也就是说只需要知道<code>getDeviceId</code>的结果就可以了。看起来这个值与设备有关，应该只能从pcapng文件中找。发现POST数据中有一个"devId":"81505f1ad0d49485"，于是密钥为www.wowsport.cn8，解密得出：{"flag":"nuaactf{f**K_mE_D0nG_sp0rt!}"}。
