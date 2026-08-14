//go:build darwin
// +build darwin

package tun

import (
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
)

// pfAnchor 挂在 com.apple/* 下: macOS 主 pf 规则集自带 `anchor "com.apple/*"` 通配,
// 加载到这个命名空间的子 anchor 会被自动求值, 无需改动主规则集(/etc/pf.conf)。
// 只 flush/加载我们这个子 anchor, 不影响 com.apple 本体或其它 anchor。
const pfAnchor = "com.apple/anyproxy"

// pfEnableToken 保存 `pfctl -E` 返回的 token; 退出时 `pfctl -X <token>` 释放引用,
// 只撤销我们这次加的启用引用, 不会把别人也在用的 pf 关掉。空=我们没成功启用。
var pfEnableToken string

// setupInboundPF 用 pf 的 reply-to 让指定入站端口(TCP)的回包沿物理网卡原路返回,
// 绕开 utun 的 0/1 路由(否则外网 SSH 等入站服务的回包会被 TUN 吸走而断)。
//
// macOS 没有 Linux 那种源地址策略路由(ip rule)/多路由表, 只能靠 pf。best-effort:
// 任何一步失败都记日志、不影响 TUN 主流程。需 root(TUN 本就需要)。
func setupInboundPF(dev, gw string, ports []int) {
	portList := make([]string, 0, len(ports))
	for _, p := range ports {
		if p > 0 && p < 65536 {
			portList = append(portList, strconv.Itoa(p))
		}
	}
	if len(portList) == 0 {
		return
	}
	if dev == "" || gw == "" {
		log.Printf("inboundPF: 缺物理网卡(dev=%q)或网关(gw=%q), 跳过; 入站服务回包可能被 TUN 吸走", dev, gw)
		return
	}

	// pass in quick on en0 reply-to (en0 GW) inet proto tcp from any to (en0) port { 22 443 } flags S/SA keep state
	rule := fmt.Sprintf(
		"pass in quick on %s reply-to (%s %s) inet proto tcp from any to (%s) port { %s } flags S/SA keep state\n",
		dev, dev, gw, dev, strings.Join(portList, " "))

	// 先以引用计数方式启用 pf(拿 token 便于退出时精确释放, 不动别人的规则)
	if tok, err := pfEnable(); err != nil {
		log.Printf("inboundPF: 启用 pf 失败: %v; 若 pf 已开则仍尝试加载 anchor", err)
	} else {
		pfEnableToken = tok
	}

	// 加载规则到子 anchor(从 stdin 读, 不落临时文件)
	cmd := exec.Command("pfctl", "-a", pfAnchor, "-f", "-")
	cmd.Stdin = strings.NewReader(rule)
	if out, err := cmd.CombinedOutput(); err != nil {
		log.Printf("inboundPF: 加载 anchor 失败: %v: %s", err, strings.TrimSpace(string(out)))
		return
	}
	log.Printf("inboundPF: 已放行入站端口 %s 的回包(pf reply-to via %s %s); 验证: sudo pfctl -a %s -sr",
		strings.Join(portList, ","), dev, gw, pfAnchor)
}

// cleanupInboundPF 清空子 anchor 规则并释放我们持有的 pf 启用引用。
func cleanupInboundPF() {
	_ = exec.Command("pfctl", "-a", pfAnchor, "-F", "rules").Run()
	if pfEnableToken != "" {
		_ = exec.Command("pfctl", "-X", pfEnableToken).Run()
		pfEnableToken = ""
	}
}

// pfEnable 执行 `pfctl -E`, 解析其打印的 "Token : <n>" 供退出时 `pfctl -X <token>`
// 释放。拿不到 token 时返回空串(退出时便不强制关闭 pf, 避免误关别人依赖的 pf)。
func pfEnable() (string, error) {
	out, err := exec.Command("pfctl", "-E").CombinedOutput()
	s := string(out) // pfctl -E 把 "Token : N" 打到 stderr, CombinedOutput 已合并
	if err != nil {
		return "", fmt.Errorf("%v: %s", err, strings.TrimSpace(s))
	}
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "Token"); i == 0 {
			if j := strings.Index(line, ":"); j >= 0 {
				return strings.TrimSpace(line[j+1:]), nil
			}
		}
	}
	return "", nil
}
