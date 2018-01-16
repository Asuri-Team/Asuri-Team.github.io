---
title: 2016 全国大学生网络安全邀请赛暨第二届上海市大学生网络安全大赛 Writeup
authorId: rexskz
tags:
  - writeup
categories:
  - Writeup
date: 2016-11-15 11:10
---

天知道为啥这比赛的名字这么长……还是写一写我过的那些题吧！

# [Web] 仔细

打开发现是一个伪 nginx 测试页面，然后扫了一下发现有个 `/log` 文件夹，打开发现里面记录了 `access.log`，猜想里面有访问记录，于是下载下来直接搜 `200`，搜到一条记录：

```text
http://xxx.xxx.xxx.xxx:15322/wojiushiHouTai888/denglU.php?username=admin&password=af3a-6b2115c9a2c0&submit=%E7%99%BB%E5%BD%95
```

打开发现里面有 flag：`flag{ff11025b-ed80-4c42-afc1-29b4c41010cb}`。

# [Web] 威胁（1）

根据提示“管理于2016年建成该系统”，生成一个 2016 年所有日期的字典，最终爆破出密码是 `20160807`，登进去发现 flag：`flag{2eeba717-0d8e-4a7e-9026-e8e573afb99b}`。

# [Web] 威胁（2）

源代码注释中提示用户名为 `test`，密码为 `123456`，然而最后猜出来真正的用户名应该是 `guest`，登录之后发现 flag：`flag{6db7d9f2-e7cf-4986-b116-e1810e6e4176}`。

# [Web] 物超所值

点击网页中的 `SHOP NOW` 按钮提示金钱不足，抓包没发现数据，说明是前端验证。查看网页源代码发现了点击按钮执行的函数，直接在 console 里面执行“验证成功”的句子：`document.getElementById('Shop').submit()`，依旧提示金钱不足，抓包发现提交了 `id=25535&Price=10000` 这段数据，将 Price 改为 0.01，在网页中发现了一行代码：

```javascript
confirm('Purchase success，flag is：flag{e6985c27-0353-4dc4-83dc-1833426779a0}');
```

# [Web] 分析

打开是个静态页面，扫了一下发现了 `http://xxx.xxx.xxx.xxx:1999/administrator.php`，在页面最下方的注释中发现账号 `administrator administrator`，登录后提示 IP 不在许可范围内，抓包看了一下发现一段注释：`<!--许可ip:localhost/127.0.0.1-->`，于是修改 HTTP 头添加 `X-Forwarded-For: 127.0.0.1`，得出结果：`flag{33edd0c8-3647-4e09-8976-286ed779e5d3}`。

# [Web] 抢金币

一开始以为是暑假某场比赛的原题，结果发现直接输入验证码抢劫会被抓，被抓之后就没法买 flag 了。后来发现，只要先让服务器生成一遍验证码，再直接抢，发的包中不带 `code` 参数，就可以（也仅可以）抢劫一次且不被抓。于是写脚本每隔一秒发两个请求（一个生成验证码，一个抢劫），等金币大于 1000 之后访问 `getflag.php`，即可得到 flag：`flag{defee21d-4e09-41fa-aab4-052bd3d406c6}`。

# [Crypto] 洋葱

这题简直能用“恶心”来形容。下载下来的附件是一个 7zip 文件，可以查看文件列表，但打开文件和解压都需要密码。文件列表中有四个文件：`CRC32 Collision.7z`、`pwd1.txt`、`pwd2.txt`、`pwd3.txt`，猜想后三个拼起来就是压缩包的密码。根据第一个文件名的提示，应该是用 CRC32 的碰撞来解。三个密码文件的 CRC32 分别是 `7C2DF918`、`A58A1926`、`4DAD5967`，大小均为六个字节，于是尝试用 hashcat 来跑所有长度为六位的明文，然而跑出来的并不像最终答案。后来想到 CRC32 的碰撞是非常多的，因此得想办法跑出所有的解。经队友助攻，将 `hashcat64.exe` 中 `0x4d79a` 处的 `0001 5000` 改成 `0005 5000` 即可。三个 CRC32 一共输出了 509 个解，人工分析了一下，分别找出了一个最可能是解的答案，拼起来即可得到解压密码：`_CRC32_i5_n0t_s4f3`。

接下来的 `CRC32 Collision.7z` 文件解压之后有 `Find password.7z`、`ciphertext.txt`、`keys.txt` 几个文件，是一个维吉尼亚密码，其中给了一万个 key，有一个是正确的……随手写了段程序分别用这一万个 key 对密文解密，猜想英文中的 `the` 出现频率比较高，于是直接在结果中搜 `the`（首尾带空格），看到一段话：

```text
the vigenere cipher is a method of encrypting alphabetic text by using a series of different caesar ciphers based on the letters of a keyword it is a simple form of polyalphabetic substitution so password is vigenere cipher funny
```

因此密码为 `vigenere cipher funny`，从而进入下一层。

这一层的提示中给了一个不完整的明文 `*7*5-*4*3?` 和不完整的 sha1 值 `619c20c*a4de755*9be9a8b*b7cbfa5*e8b4365*`，其中每一个星号对应一个可打印字符。对 sha1 中的星号枚举 `[0-9a-f]` 并将其放到字典中，对明文中的星号枚举 ASCII 为 33~127 的字符并将其 sha1 后查找是否在字典中出现，最终得出答案：`I7~5-s4F3? 619c20c4a4de75519be9a8b7b7cbfa54e8b4365b`，进入下一层。

本层题目有两个提示，一个是 `Hello World ;-)`，另一个是 `两个程序 md5 相同`，百度搜索 `md5 相同 Hello World`，可以搜到两个程序：<a href="http://www.win.tue.nl/hashclash/SoftIntCodeSign/HelloWorld-colliding.exe">HelloWorld-colliding.exe</a> 和 <a href="http://www.win.tue.nl/hashclash/SoftIntCodeSign/GoodbyeWorld-colliding.exe">GoodbyeWorld-colliding.exe</a>，其中第一个输出是 `Hello World ;-)`，第二个循环输出 `Goodbye World :-(`，这个就是解压密码。但是原则上来说，有无数个具有不同输出的程序都可以跟第一个程序的 md5 相同，因此感觉这一层出的有问题。

最后一层给了一个 `flag.enc` 和 `rsa_public_key.pem`，可以通过 `RsaCtfTool` 直接生成私钥：

```text
$ python RsaCtfTool.py --pkey rsa_public_key.pem --pri > private.key
$ openssl rsautl -decrypt -in flag.enc -inkey private.pem -out flag.txt
```

最终得出 flag：`flag{W0rld_Of_Crypt0gr@phy}`。

# [Misc] 面具

将图片下载下来分析一下：

```text
$ binwalk C4n_u_find_m3_DB75A15F92D15B504D791F1C02B8815C.jpg

DECIMAL         HEX             DESCRIPTION
-------------------------------------------------------------------------------------------------------
12              0xC             TIFF image data, little-endian
478718          0x74DFE         Zip archive data, at least v2.0 to extract, compressed size: 153767, uncompressed size: 3145728, name: "flag.vmdk"
632637          0x9A73D         End of Zip archive

$ dd if=C4n_u_find_m3_DB75A15F92D15B504D791F1C02B8815C.jpg of=flag.zip bs=1 skip=478718
```

解压 `flag.zip` 是一个 vmdk 文件，使用高版本的 WinHex 打开后，点击菜单中的“专业工具→将镜像文件转换为磁盘”，然后找到 `分区1`，里面有两个文件夹 `key_part_one` 和 `key_part_two`，第一个文件夹里面有一段 Brainfuck 代码，运行结果为 `flag{N7F5_AD5`；第二个里面没有有意义的文件，但是根目录下还有个曾经被删除过的文件（WinHex 提示：曾经存在的，数据不完整），打开是一段 Ook 程序，运行结果为 `_i5_funny!}`，拼起来即可得到 flag：`flag{N7F5_AD5_i5_funny!}`。

----

下面是队友们做出来的题。

# [Basic] 签到题

rar 解压，密码 `ichunqiu&dabiaojie`，flag{ctf_1s_interesting}。

# [Web] 跳

访问首页得到测试账号 `test`，`test`，猜测 `admin`，`test`。拿到 token，访问 `admin.php` 得 flag。

# [Crypto] 简单点

Brainfuck 解密得到 `flag{url_lao_89}`。

# [Misc] 大可爱

把那张图 binwalk 解压出来,得到 `29.zlib`。解压 zlib：

```python
import zlib
with open("29.zlib","rb") as fp:
    s = fp.read()
    ds = zlib.decompress(s)
    dsss = zlib.decompress(ds[0x28D28D:])
with open("decode","wb") as fp:
    fp.write(dsss.decode("hex"))
```

之后再 binwalk 解压，得到一个加密的 zip 文件，密码在注释：`M63qNFgUIB3hEgu3C5==`，解压得 flag：`flag{PnG_zLiB_dEc0mPrEsS}`。

# [Reverse] re400

先用 IDA 载入 `re400.static`，发现这程序：

1. 没有引用动态库，给我们这一堆没有符号的动态库的出题人是想作甚？
2. 什么符号都没有…还是先跑一下，看有什么提示吧。

运行程序之后，随便输入一些数据，程序打印出 `Wrong.`，然后就退出了。IDA 里搜一下 `Wrong.` 这个字符串，看一下所在函数，基本可以推断出这个 `sub_400CF0` 就是 `main` 函数，大概的代码是这样的：

```c++
const char *expect = "OSHzTJ4pwFgRG6eS6y3xVOOEGcbE5rzwqTs7VCK6ACQLuiTamZpXcQ==";
int main() {
  char input[256];
  read(0, input, 256);
  if (check(input, expect, strlen(expect)) {
    puts("Right.");
  } else {
    puts("Wrong.");
  }
  return 0;
}
```

那个 `expect` 怎么看都像是 base64 编码的字符串，试着解码后，只知道它的内容长度是 40，没看出什么规律。

然后重点是 `check` 函数（sub_401510）到底是怎么检查输入数据的。但点开 `check` 函数后，里面一大堆 `call` 指令实在看得有点慌…点开第一个 `call sub_429AE0` 就看到一堆 `xmm` 寄存器，正常写出来的代码，基本不会被编译出用 `xmm` 寄存器的，所以猜测这应该是个 `libc` 的库函数。另找一个带有符号的 `libc`，用 IDA + bindiff 插件，尝试匹配其中的无名函数。虽然会有一些误判，大胆猜测一下，给一些函数重命名：

```text
* sub_429AE0: strlen
* sub_402730: malloc
* sub_42C990: memset
* sub_432520: strcpy
* sub_402710: free
```

开始一边运行，一边分析 `check` 函数：

```text
0x40153E - 0x40154C: 判断了 strlen(input) <= 5，如果成立的话，就直接退出了。因此输入的长度必须大于 5
0x401552 - 0x401576: 是一个以 rax 为循环变量的循环，检查了输入的前5个字符是否满足 [0-9A-Z]{5}
0x401578 - 0x4015E5: 申请了两块内存空间并初始化，然后把栈上的两块空间清零
0x4015EE - 0x4015FF: 循环，把输入的前五个字节复制到栈内存
0x401601 - 0x40163B: 有三个 call，先看第一个 call sub_401CA0，看到 0x10325476 之类的数字，md5 无疑了，仔细阅读一下，这块代码是在计算输入数据前五个字节的 md5
0x401648 - 0x401662: 又一个循环，循环变量应该是 r15，每次递增 8，与输入长度 r12d 进行比较，然后 call sub_401B30 的参数有三个：
  * lea rdi, [rbx+r15] arg[0]：输入数据
  * lea rsi, [rsp+30h] arg[1]：上一步算出来的 md5 的前半部分
  * lea rdx, [rbp+r15] arg[2]：第一块 malloc(strlen(input)+16) 的空间
```

至于那个 `sub_401B30` 到底是做什么的，（一开始）实在没搞懂，暂时不管它，接着分析代码。

```text
0x401674 - 0x4016AD: 看到 call 了 malloc 和 memset，然后有一个 call sub_401120，分析它参数：
  * mov rdi, rbp  arg[0]：上一步用 sub_401B30 算出来的结果
  * mov rsi, r13  arg[1]：刚刚 malloc 的空间
  * mov edx, r12d arg[2]：strlen(input)，aligned 8
```

调试时，运行过这个 `call` 后，发现 `arg[1]` 的空间里是一个 base64 编码的字符串，解码后就是 `arg[0]` 的内容，确定这个 `sub_4011120` 应该就是 `b64encode(src, dst, len)`。剩下的代码，就是把这个 base64 编码的字符串和 `expect` 比较了。至此，剩下一个关键的 `sub_401B30`…

花了好几个小时，重写出里面调用到的几个子函数，每个函数都用到了几十到几百字节的非线性变换。虽然不是特别难的事情，但工作量太大了…直到开始重写最后一个子函数的时候，注意到这个循环的流程是这样的：

```text
* call sub_401930
* call sub_4018C0
* call sub_401AA0
* loop xor
* call sub_401930
* call sub_4018C0
* call sub_401AA0
* loop xor
```

为啥我联想到了密码学里的 Feistel 网络…然后再看这个函数最底下的那个

```text
.text:0000000000401C6F                 call    sub_4018C0
```

`sub_4018C0` 是一个相对简单的变换，我想，这该不会是 DES 加密吧？验证一下，这果然就是 DES。

(｀□′)╯┴┴
(╯°Д°)╯︵ ┻━┻
(╯#-_-)╯~~~~~~~~~~~~~~~~~╧═╧

算法就是：`base64(DES.new(key=md5(input[:5]).digest()[:8], mode=DES.MODE_ECB).encrypt(input))`。

写一个程序，穷举输入前五个字节，能找到唯一匹配 `expect` 的输入：`SHSECflag{675ac45bc131a1b7c145b605f4ba5}`。

附求解程序：

```c++
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <mbedtls/des.h>
#include <mbedtls/md5.h>

int main(int argc, char *argv[]) {
    int pos = atoi(argv[1]);
    const uint8_t *t = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint8_t plain[8];
    uint8_t cipher[9];
    uint8_t key[16];
    uint8_t target[] = {0x39,0x21,0xf3,0x4c,0x9e,0x29,0xc0,0x58,0x11,0x1b,0xa7,0x92,0xeb,0x2d,0xf1,0x54,0xe3,0x84,0x19,0xc6,0xc4,0xe6,0xbc,0xf0,0xa9,0x3b,0x3b,0x54,0x22,0xba,0x00,0x24,0x0b,0xba,0x24,0xda,0x99,0x9a,0x57,0x71};
    mbedtls_des_context des;
    cipher[8] = 0;
    for (uint8_t a0 = 0; a0 < 36; a0++) {
        plain[0] = t[a0];
        for (uint8_t a1 = 0; a1 < 36; a1++) {
            plain[1] = t[a1];
            printf("status %c%c\r", plain[0], plain[1]);
            fflush(stdout);
            for (uint8_t a2 = 0; a2 < 36; a2++) {
                plain[2] = t[a2];
                for (uint8_t a3 = 0; a3 < 36; a3++) {
                    plain[3] = t[a3];
                    for (uint8_t a4 = 0; a4 < 36; a4++) {
                        plain[4] = t[a4];
                        mbedtls_md5(plain, 5, key);
                        mbedtls_des_init(&des);
                        mbedtls_des_setkey_dec(&des, key);
                        mbedtls_des_crypt_ecb(&des, target, cipher);
                        if (memcmp(cipher, plain, 5) == 0) {
                            printf("found %s\n", cipher);
                            for (size_t t = 0; t < sizeof(target); t += 8) {
                                mbedtls_des_crypt_ecb(&des, target + t, cipher);
                                printf("%s", cipher);
                            }
                            printf("\n\n");
                        }
                    }
                }
            }
        }
    }
    return 0;
}
```
