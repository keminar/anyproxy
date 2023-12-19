#!/bin/bash
SCRIPT=$(readlink -f $0)
ROOT_DIR=$(dirname $SCRIPT)/../
cd $ROOT_DIR
ulimit -n 65536

if ! (sudo cat /etc/passwd|grep ^anyproxy: > /dev/null); then
    echo "添加账号"
    sudo useradd -M -s /sbin/nologin anyproxy
fi

# 要启动的端口
port=3000
if ! (sudo iptables -t nat -L|grep "redir ports $port" > /dev/null); then
    echo "添加iptables"
    # anyproxy 账号不走代理直接请求
    sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner anyproxy -j RETURN

    # 注:如果有虚拟机，虚拟机的启动账号不要走代理端口，会导致虚拟机里的浏览器设置的代理无效果
    #    如果有本地账号要连mysql等服务，也不要走代理端口,会一直卡住(目前发现mysql协议不兼容)

    #指定root账号走代理
    sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT -d 192.168.0.0/16 -m owner --uid-owner 0 -j RETURN
    sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT -d 172.17.0.0/16 -m owner --uid-owner 0 -j RETURN
    sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT -m multiport --dport 80,443 -m owner --uid-owner 0 --to-port $port

    #sudo iptables -t nat -L -n --line-number
    #sudo iptables -t nat -D OUTPUT 3
fi
echo "启动anyproxy"
sudo -u anyproxy ./anyproxy -daemon -l $port
