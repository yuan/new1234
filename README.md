How to build using Cygwin
=========================

下载安装Cygwin
-----------------
安装Cygwin过程中，需要安装下面这些依赖的Package。

- autoconf
- automake
- pkg-config
- make
- mingw64-x86_64-gcc-core
- mingw64-x86_64-g++
- mingw64-x86_64-openssl

Go开发包安装
-----------------
下载地址： https://golang.org/dl/

编译生成可执行文件
-----

### 先编译Go源码文件

1. cd ${path to open-vpn-netease}
2. go get -v -u golang.org/x/net/html
3. go get -v -u golang.org/x/sys/windows/registry
4. go build -buildmode=c-archive -o auto_connect.a auto_connect.go

### 接下来编译打包整个工程
	
1. 打开Cygwin终端
2. cd ${path to open-vpn-netease}
3. autoreconf -iv
4. ./configure --host=x86_64-w64-mingw32
5. make
6. make命令会报错，无视
7. x86_64-w64-mingw32-gcc -municode -g -O2 -pedantic -Wall -Wextra -mwindows  -o openvpn-gui.exe main.o openvpn.o localization.o tray.o viewlog.o service.o options.o passphrase.o proxy.o registry.o scripts.o manage.o misc.o openvpn_config.o access.o save_pass.o openvpn-gui-res.o auto_connect.a -lcrypto -lws2_32 -lgdi32 -lcrypt32 -lz -lws2_32 -lcomctl32 -lwinhttp -lwtsapi32 -lcrypt32 -lnetapi32 -lole32 -lshlwapi -lsecur32 -lWinMM -lntdll -lWS2_32

如果成功会在工程目录下生成openvpn-gui.exe文件，你把它拷贝到任何地方就可以双击运行了。






