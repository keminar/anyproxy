# geoip / geosite 分流

按「 IP 段 / 域名类别」分流，方便配「国内直连、国外走代理」这类默认行为。数据源支持两种格式：

- **`.dat`**：`geoip.dat` / `geosite.dat`（protobuf 数据集，一个文件含多类别）。
- **纯文本列表**：每个文件一个类别，如域名列表 `direct-list.txt`、CIDR 列表 `china-cidr.txt`。

## 配置：类别 → 文件

`geo.ip` / `geo.site` 是「**类别名 → 文件**」映射，文件按扩展名区分：`.dat` 取其中同名类别，其它当**文本列表**（整个文件即该类别）。

```yaml
geo:
  ip:
    cn: ./geoip-cn.dat        # .dat: 取其中的 cn 类别
    # cn: ./china-cidr.txt    # 或文本 CIDR 列表(整文件=cn), 每行一个 CIDR/IP
  site:
    cn: ./direct-list.txt     # 文本域名列表(整文件=cn)
    google: ./geosite.dat     # .dat: 取其中的 google 类别

default:
  target: remote              # 默认走代理
hosts:
  - name: geoip:cn            # 目标 IP 命中 geoip 类别 cn → 直连
    target: local
  - name: geosite:cn          # 目标域名命中 geosite 类别 cn → 直连
    target: local
```

效果：国内 IP / 国内域名直连，其余走代理。`geoip:`/`geosite:` 后面是**类别名**（大小写不敏感），就是你在 `geo.ip`/`geo.site` 里配的键。同一类别可由**多个文件合并**（`.dat` + 文本都行）。

### 文本列表格式

- **geoip 文本**：每行一个 `CIDR`（如 `1.2.0.0/16`）或裸 IP；`#` 注释；行内空格后的属性忽略。
- **geosite 文本**（域名列表）：每行一个域名，前缀：
  - 无前缀 或 `domain:` → **后缀**（根域及所有子域）
  - `full:` → 精确
  - `keyword:` / `regexp:` → **丢弃**（当国外域名）
  - `#` 注释；`域名 @attr` 的属性部分忽略。

### `.dat` 离线提取小文件（可选）

全量 `.dat` 含所有类别、较大。可用内置命令**离线提取**所需类别成小 `.dat` 随发布携带（运行时只读小文件）：

```bash
anyproxy -geo-extract -geo-in geosite.dat -geo-cat cn,google -geo-out geosite-cn.dat
```

`-geo-cat` 逗号分隔可一次提多个；geoip.dat/geosite.dat 外层一致，同命令通用；提取完即退出。全量 `geoip.dat` / `geosite.dat` 请自行获取。换新全量 `.dat` 后需**重新提取**（程序不做缓存/自动更新，避免陈旧数据）。

## 匹配语义

- **geoip:xx**：目标 IP 落在该类别的任一 CIDR 内即命中。内部是排序 CIDR + 二分查找，O(log n)。v4/v6 都支持。
- **geosite:xx**：只用两种域名类型（`.dat` 的 Domain/Full、文本的 无前缀·domain/full）——
  - **Domain（后缀）**：如 `baidu.com` 命中 `baidu.com` 及其**所有子域** `www.baidu.com`、`a.b.baidu.com`。
  - **Full（精确）**：只命中完整域名本身。
  - **keyword（子串）/ regex（正则）一律丢弃、当国外域名处理**（这两类少、不确定性高）。

## 说明

- `geo` 数据在**启动时加载一次**，不随配置热重载（`.dat` 换了需重启）。`hosts` 里 `geoip:`/`geosite:` 规则本身可热加载，但依赖启动时已加载的数据。
- 用了 `geoip:`/`geosite:` 规则但没配对应 `geo.ip`/`geo.site` 时，该规则**永不命中**（会打印提示），流量落到 `default`。
- geoip 匹配的是**目标 IP**：透明代理/TUN 天然有目标 IP；普通代理请求也有解析后的 IP。geosite 匹配的是**域名**：透明代理/TUN 靠首包嗅探 TLS SNI / HTTP Host 还原（见 [routing.md](routing.md)、[usage.md](usage.md)），嗅不到则只能靠 geoip。
- 实现零第三方依赖：内置最小 protobuf 解析器读 `.dat`，不引入 protobuf 库、不依赖任何第三方规则库代码（`utils/geo/`）。文本列表也在同包解析。

## 与其它规则的关系

`geoip:`/`geosite:` 就是 `hosts[].name` 的一种取值，和普通域名规则、`*` 通配一样按 `hosts` **顺序**匹配，第一条命中即用其 `target`/`proxy`/`dns` 等。放前面的优先。出口决策见 [proxy-decision.md](proxy-decision.md)。
