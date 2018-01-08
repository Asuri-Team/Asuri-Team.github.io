---
title: 破解 jeb  2.3.7 demo
authorId: hac425
tags:
  - jeb 2.3.7
categories:
  - jeb破解
date: 2017-10-27 10:15:00
---
### 前言
使用的技术和上文的一样。


`mips` 版本的修改版

百度云：

链接: https://pan.baidu.com/s/1c1Oh0x6 密码: ekjj

### 正文

**安卓版**

`
jeb-2.3.7.201710262129-JEBDecompilerDemo-121820464987384338
`


重新编译一个 `com.pnfsoftware.jeb.client.Licensing `

```
//
// Source code recreated from a .class file by IntelliJ IDEA
// (powered by Fernflower decompiler)
//

package com.pnfsoftware.jeb.client;

import com.pnfsoftware.jeb.AssetManager;
import com.pnfsoftware.jeb.util.format.Strings;
import com.pnfsoftware.jeb.util.logging.GlobalLog;
import com.pnfsoftware.jeb.util.logging.ILogger;
import com.pnfsoftware.jebglobal.GN;
import com.pnfsoftware.jebglobal.mW;

public final class Licensing {
    private static final ILogger logger = GlobalLog.getLogger(Licensing.class);
    public static final String user_email = "love_lh@hac425.com";
    public static final String user_group = "hacker";
    public static final int user_id = 2116188757;
    public static final String user_name = "hac425";
    public static final int user_count = 20;
    public static final int license_ts = 0;
    public static final int license_validity = 40000;
    public static int real_license_ts = 0;
    public static int build_type = 0;
    public static final int FLAG_AIRGAP = 8;
    public static final int FLAG_ANYCLIENT = 16;
    public static final int FLAG_COREAPI = 32;
    public static final int FLAG_DEBUG = 1;
    public static final int FLAG_FLOATING = 4;
    public static final int FLAG_FULL = 2;
    public static final int FLAG_JEB2 = 128;


    static {
        int v0 = Licensing.build_type | 2;
        Licensing.build_type = v0;
        v0 |= 4;
        Licensing.build_type = v0;
        v0 |= 8;
        Licensing.build_type = v0;
        v0 |= 16;
        Licensing.build_type = v0;
        v0 |= 32;
        Licensing.build_type = v0;
        Licensing.build_type = v0 | 128;
    }


    public Licensing() {
    }

    public static final void setLicenseTimestamp(int var0) {
        real_license_ts = 1505267330;
    }

    public static final int getExpirationTimestamp() {
        return real_license_ts + 345600000;
    }

    public static final int getBuildType() {
        return build_type;
    }

    public static final boolean isDebugBuild() {
        return true;
    }

    public static final boolean isReleaseBuild() {
        return !isDebugBuild();
    }

    public static final boolean isFullBuild() {
        return true;
    }

    public static final boolean isDemoBuild() {
        return !isFullBuild();
    }

    public static final boolean isFloatingBuild() {
        return (build_type & 4) != 0;
    }

    public static final boolean isIndividualBuild() {
        return !isFloatingBuild();
    }

    public static final boolean isAirgapBuild() {
        return (build_type & 8) != 0;
    }

    public static final boolean isInternetRequired() {
        return false;
    }

    public static final boolean allowAnyClient() {
        return (build_type & 16) != 0;
    }

    public static final boolean canUseCoreAPI() {
        return true;
    }

    public static final String getBuildTypeString() {
        StringBuilder var0 = new StringBuilder();
        if (isReleaseBuild()) {
            var0.append(mW.UU(new byte[]{-119, 23, 9, 9, 4, 18, 22, 74}, 1, 251));
        } else {
            var0.append(mW.UU(new byte[]{35, 1, 7, 23, 18, 72}, 1, 71));
        }

        if (isFullBuild()) {
            var0.append(mW.UU(new byte[]{37, 26, 28, 21, 93}, 2, 39));
        } else {
            var0.append(mW.UU(new byte[]{39, 10, 29, 22, 93}, 2, 200));
        }

        if (isFloatingBuild()) {
            var0.append(mW.UU(new byte[]{-114, 10, 3, 14, 21, 29, 7, 9, 72}, 1, 232));
        } else {
            var0.append(mW.UU(new byte[]{42, 1, 20, 16, 4, 0, 3, 29, 21, 76, 7}, 2, 150));
        }

        if (isAirgapBuild()) {
            var0.append(mW.UU(new byte[]{34, 6, 2, 84, 21, 8, 23, 71}, 2, 100));
        } else {
            var0.append(mW.UU(new byte[]{8, 23, 20, 92, 68, 7, 26, 17, 23, 28, 11, 17, 91}, 1, 122));
        }

        if (allowAnyClient()) {
            var0.append(mW.UU(new byte[]{82, 15, 23, 84, 78, 15, 5, 12, 11, 26, 91}, 1, 51));
        } else {
            var0.append(mW.UU(new byte[]{-85, 9, 0, 15, 10, 10, 8, 13, 65, 78, 15, 5, 12, 11, 26, 91}, 1, 196));
        }

        if (canUseCoreAPI()) {
            var0.append(mW.UU(new byte[]{32, 0, 2, 28, 95, 8, 23, 1}, 2, 169));
        } else {
            var0.append(mW.UU(new byte[]{-27, 1, 66, 78, 12, 29, 23, 72, 76, 17, 25}, 1, 139));
        }

        return var0.toString();
    }

    public static String getLicense() {
        byte[] var0 = AssetManager.UU("LICENSE.TXT");
        return var0 == null ? null : Strings.decodeUTF8(var0);
    }

    public static String getChangeList() {
        byte[] var0 = AssetManager.UU("CHANGELIST.TXT");
        return var0 == null ? null : Strings.decodeUTF8(var0);
    }

}

```

然后patch掉退出函数和更新检测

```
package me.hacklh;

import com.pnfsoftware.jeb.Launcher;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtNewMethod;
import com.pnfsoftware.jeb.client.Licensing;


public class JebCracker {

    public static void main(String[] args) throws Exception {

//        com.pnfsoftware.jeb.installer.Launcher.main(new String[]{"--di"});
//        DES.main(args);
//         Launcher.main(new String[]{"--generate-key"});
        CtClass.debugDump = "./debugDump/";

        System.out.println(Licensing.allowAnyClient());

        /**
         * 修改getStatus， AbstractContext会起几个线程修改status
         */
        ClassPool pool = ClassPool.getDefault();
        pool.importPackage("com.pnfsoftware.jeb.client.AbstractContext");
        CtClass old_class = pool.get("com.pnfsoftware.jeb.client.AbstractContext");
        old_class.detach();
        CtMethod old_method = old_class.getDeclaredMethod
                (
                        "getStatus",
                        new CtClass[]
                                {
                                }
                );
        old_method.setBody("return 0;");

        old_method = old_class.getDeclaredMethod
                (
                        "terminate",
                        new CtClass[]
                                {
                                }
                );
        old_method.setBody(";");
        old_class.writeFile();



        /**
         * patch 掉与网络下载有关的函数，禁止升级
         */
        pool = ClassPool.getDefault();
        pool.importPackage("com.pnfsoftware.jeb.util.net.Net");
        old_class = pool.get("com.pnfsoftware.jeb.util.net.Net");
        old_class.detach();
        old_method = old_class.getDeclaredMethod

                (
                        "downloadBinary",
                        new CtClass[]
                                {
                                        pool.get(String.class.getName())
                                }
                );
        old_method.setBody("return null;");

        old_method = old_class.getDeclaredMethod
                (
                        "httpPost",
                        new CtClass[]
                                {
                                        pool.get(String.class.getName()),
                                        pool.get(String.class.getName()),
                                        pool.get(long[].class.getName())
                                }
                );
        old_method.setBody("return null;");
        old_class.writeFile();


    }
}


```

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1509071049085jtzkc8nm.png?imageslim)

**mips版**
类似


### 最后
可以在jeb的官网下载其他平台的适配包
```
https://www.pnfsoftware.com/jeb2/support-package
```