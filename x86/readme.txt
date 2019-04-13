动态库编译方式：

1、获取get-machine-id和动态库文件liblicense.so：
在agent_license/keytool/目录下执行命令：make

2、获取libnet_monitor.so：
获取源代码net_monitor.c，执行编译命令：gcc -c -o net_monitor.o -fPIC net_monitor.c
生成动态库文件：gcc -shared -o libnet_monitor.so net_monitor.o

