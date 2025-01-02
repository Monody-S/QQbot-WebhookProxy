# QQbot-WebhookProxy

用于QQ官方机器人的webhook反向代理，实现一套ssl给多个bot使用，转发给多个服务器。

## 适用场景

1. 机器人在大陆服务器上，自己又不想备案，可以在非大陆服务器上部署该脚本，转发给大陆服务器
2. 同一个域名想给多个机器人使用，不想折腾
3. 不想让机器人占用80, 443, 8080, 8443端口
（等）

## 使用方式

> 在使用之前，请确保你的域名解析到一个不会被拦截的服务器上（例如非大陆服务器，或者直接备案）

1. 购买域名
2. 在腾讯云服务器中申请你购买的域名的ssl证书
3. 下载适用于Nginx的证书，将其中的`crt`文件和`key`文件放置到与本程序相同目录下，且分别命名为`ssl.crt`和`ssl.key`文件
4. 将本仓库中的`py`文件和`yml`文件放于服务器同一目录下，打开`config.yml`文件，填写转发的目标服务器与接收路径以及QQ机器人的secret即可
5. 配置好后，直接`python proxy.py`启动即可
6. 设置回调地址（以path: "/qq/webhook"与target_address: "http://127.0.0.1:8442/qq/webhook" ，域名为"test.com"举例），将你的QQ机器人接受端口设置为8442，且为本地，回调地址填写为“https://test.com/qq/webhook” 即可

## 多转发

想转发多个端口，只需在config的groups下填写多组即可