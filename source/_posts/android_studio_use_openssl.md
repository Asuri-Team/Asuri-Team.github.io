---
title: android studio使用openssl
authorId: hac425
tags:
  - openssl
  - 开发
  - ''
categories:
  - 安卓安全
date: 2017-11-19 14:30:00
---
### 前言
逆向的基础是开发， 逆向分析时很多时候会使用一些公开的加密函数来对数据进行加密，通过使用 `openssl` 熟悉下。

### 正文
首先得先编译出来 `openssl`，然后把它们复制到你的工程目录下。

![paste image](http://oy9h5q2k4.bkt.clouddn.com/15110733397054zqc1idw.png?imageslim)

`include` 是 `openssl` 的头文件。`lib` 下的那些是编译出来的so。

然后修改 `build.gradle` 中的 `cmake` 项：

![paste image](http://oy9h5q2k4.bkt.clouddn.com/1511073468721ci33oo8v.png?imageslim)

`cppFlags` 是编译选项， `abiFilters`指定编译so的 `abi`，和 刚才 `lib` 目录中的目录项对应。后面会用到。

增加 ![paste image](http://oy9h5q2k4.bkt.clouddn.com/1511073600119rzvpfdcl.png?imageslim)

`jniLibs.srcDirs` 的值为`openssl` so的目录。表示打包时直接复制这些就行了。
最终的 `build.gradle`
```
apply plugin: 'com.android.application'

android {
    compileSdkVersion 26
    defaultConfig {
        applicationId "com.example.administrator.oi"
        minSdkVersion 19
        targetSdkVersion 26
        versionCode 1
        versionName "1.0"
        testInstrumentationRunner "android.support.test.runner.AndroidJUnitRunner"
        externalNativeBuild {
            cmake {
                cppFlags "-std=c++11 -frtti -fexceptions"
                abiFilters 'armeabi', 'armeabi-v7a'
            }
        }
    }
    buildTypes {
        release {
            minifyEnabled false
            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
        }
    }

    sourceSets {
        main {
            jniLibs.srcDirs = ["C:\\Users\\Administrator\\AndroidStudioProjects\\oi\\app\\openssl_resouce\\lib"]
        }
    }

    externalNativeBuild {
        cmake {
            path "CMakeLists.txt"
        }
    }
}

dependencies {
    implementation fileTree(dir: 'libs', include: ['*.jar'])
    implementation 'com.android.support:appcompat-v7:26.1.0'
    implementation 'com.android.support.constraint:constraint-layout:1.0.2'
    testImplementation 'junit:junit:4.12'
    androidTestImplementation 'com.android.support.test:runner:1.0.1'
    androidTestImplementation 'com.android.support.test.espresso:espresso-core:3.0.1'
}

```

然后修改 `CMakeLists.txt`， 中文注释的地方就是修改的地方。

```
# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# 设置头文件加载的目录
include_directories(C:/Users/Administrator/AndroidStudioProjects/oi/app/openssl_resouce/include)


#动态方式加载
add_library(openssl SHARED IMPORTED )
add_library(ssl SHARED IMPORTED )

#引入第三方.so库，根据${ANDROID_ABI} 引用不同的库
set_target_properties(openssl PROPERTIES IMPORTED_LOCATION C:/Users/Administrator/AndroidStudioProjects/oi/app/openssl_resouce/lib/${ANDROID_ABI}/libcrypto.so)
set_target_properties(ssl PROPERTIES IMPORTED_LOCATION C:/Users/Administrator/AndroidStudioProjects/oi/app/openssl_resouce/lib/${ANDROID_ABI}/libssl.so)



# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
             native-lib

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             src/main/cpp/native-lib.cpp )

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

find_library( # Sets the name of the path variable.
              log-lib

              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

# Specifies libraries CMake should link to your target library. You
# can link multiple libraries, such as libraries you define in this
# build script, prebuilt third-party libraries, or system libraries.

# 设置链接选项
target_link_libraries( # Specifies the target library.
                       native-lib
                       openssl
                       ssl

                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib} )
```

然后就可以使用了。

项目路径

https://gitee.com/hac425/android_openssl/