# nat-punch：最小化的 UDP 打洞验证工具

[derp-nat](../derp-nat/) 只能回答"derphole 那一整套机制最后有没有拿到直连"，中间套了太多层(DERP 信令 → 4 条并行 UDP lane → 1.2 秒打洞窗口 → 2 条 lane 的最低门槛 → QUIC 握手)，一旦失败根本分不清是哪一层的问题。这个工具把所有中间层全部剥掉，只测最底下那个问题：**两台各自在 NAT 后面的机器，能不能让一个 UDP 包互相到达。**

顺带也替代了之前用 `tcpdump` + `nc` 判断 NAT 类型的土办法，Windows 和 Linux 上用法完全一样(不需要 `nc`)。

零外部依赖，直接用仓库根模块，没有单独的 `go.mod`。

## 用法

需要**一到两台公网 VPS** 当反射器(reflector)。两台(且是**不同的公网 IP**)才能判断 NAT 类型，一台只能拿到自己的公网地址。

```bash
# 1. 在公网 VPS 上起反射器(有两台就都起，端口随意)
go run . -mode=reflect -listen=:3478

# 2. 在两台被测机器上分别运行(A 和 C 各跑一次)
go run . -mode=punch -reflect=<vps1-ip>:3478,<vps2-ip>:3478
```

第 2 步会先打印你的公网地址和 NAT 类型判定，然后停下来等你粘贴对端地址：

```
Your public address: 1.2.3.4:54321
NAT type: CONE (endpoint-independent mapping) — same mapping toward every reflector, punchable

Paste the peer's public address (ip:port) and press Enter:
```

**两台机器都要先跑到这一步**，然后把各自打印的公网地址粘贴到对方那边、几秒内先后回车——打洞必须双方**同时**发包才有意义，各自发出去的包正是给对方在自己 NAT 上开返回通道的东西。晚太多(超过十几秒)就可能一边已经发完了另一边才开始。

最后两边各自打印：

```
=== punch result ===
sent:     150
received: 143
verdict:  SUCCESS — a direct UDP path exists between these two hosts
```

`received > 0` 就是打通了。

## 关键设计：全程只用一个 socket

反射器观测到的地址、和后面真正打洞用的地址，必须是**同一个 NAT 映射**才有意义，所以整个流程(问反射器 → 等你粘贴 → 打洞)都在同一个 UDP socket 上跑，中途不退出。进程一旦重启，NAT 映射就变了，之前记下来的地址随即作废——这也是为什么工具设计成"停下来等粘贴"而不是"跑两次命令"。

## NAT 类型判定的原理和局限

同一个本地 socket 分别向两个**不同 IP** 的反射器发包，看两边观测到的外部端口：

- **端口一样** → 端点无关映射(Endpoint-Independent Mapping)，即 cone 型，可打洞
- **端口不同** → 对称型(Symmetric)，提前告诉对方的端口跟实际发包用的端口对不上，打洞基本没戏

**局限(重要)**：这个测试只验证了"映射(Mapping)"这一半，没验证"过滤(Filtering)"那一半——即映射建立之后，是不是**任何人**都能往这个端口发包进来(Full Cone)，还是**必须是你主动发过包的那个地址**才放行(Restricted / Port-Restricted Cone)。两边都测出 cone 但实际还是打不通，往往就是卡在过滤这一层，它对双方发包的时序要求更严。所以真正的结论要看 `punch result` 那一步的实测结果，NAT 类型判定只是辅助信息。

## Windows 注意

Windows 防火墙可能拦截入站 UDP。如果 NAT 类型判定正常(说明出站没问题)但 `received: 0`，先试试临时关闭防火墙、或者给这个程序放行入站 UDP，排除这个变量之后再下结论。
