# mysslaudit
Decrypt the content of SSL based on eBPF and obtain the IP information of the client address.

本项目借助 eBPF 应用层的 hook 机制，在 openssl 完成解密后获取流量内容，同时溯源客户端的 IP 地址端口及相关信息。
项目主要参考：[bpf-developer-tutorial/src/30-sslsniff at main · eunomia-bpf/bpf-developer-tutorial](https://github.com/eunomia-bpf/bpf-developer-tutorial/tree/main/src/30-sslsniff)

## 编译步骤
eBPF 相关的编译环境及开发框架可参照此教程：https://eunomia.dev/zh/tutorials/

1.编译https测试代码

```shell
cd myhttpsserver
make
```

2.编译eBPF代码  

```shell
cd mysslaudit
make
```



## 测试运行
1.

```shell
sudo ./mysslaudit 
```

 

2.

```shell
./httpserver  
```

3.使用浏览器,curl,或者wget访问curl https://192.168.99.249:8443/

```shell
wget https://192.168.99.249:8443/ --no-check-certificate
```



```shell
curl https://192.168.99.249:8443/ -k
```

3.观察sudo ./mysslaudit 程序输出

## 已测试平台
1.深度系统 deepin 23

## TODO
1.支持其他ssl库，例如GnuTLS  

2.适配更多linux发行版本  

3.更加动态化，支持https server，或者数据库服务器  
