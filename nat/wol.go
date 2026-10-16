package nat

import (
	"fmt"
	"net"
)

const (
	// wolDefaultAddr 未指定目标时的兜底地址: 255.255.255.255 是受限广播, 只在本机
	// 所在链路内扩散、不经路由器转发, 因此不需要预先知道对方所在网段。
	wolDefaultAddr = "255.255.255.255"

	// wolDefaultPort 魔术包的传统端口(discard 协议), 与常见 WOL 工具/网关转发规则一致。
	wolDefaultPort = "9"
)

// buildMagicPacket 组装标准 WOL 魔术包: 6 字节 0xFF 之后跟 16 遍目标 MAC。
func buildMagicPacket(mac string) ([]byte, error) {
	hw, err := net.ParseMAC(mac)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", mac, err)
	}
	if len(hw) != 6 {
		return nil, fmt.Errorf("%s: expect a 6-byte MAC, got %d bytes", mac, len(hw))
	}
	packet := make([]byte, 0, 6+16*len(hw))
	for i := 0; i < 6; i++ {
		packet = append(packet, 0xff)
	}
	for i := 0; i < 16; i++ {
		packet = append(packet, hw...)
	}
	return packet, nil
}

// wolTarget 把用户填的目标补成 host:port: 空则用默认广播地址和端口, 只给地址不给
// 端口时补默认端口, 已带端口的原样返回。
func wolTarget(target string) string {
	if target == "" {
		return net.JoinHostPort(wolDefaultAddr, wolDefaultPort)
	}
	if _, _, err := net.SplitHostPort(target); err != nil {
		return net.JoinHostPort(target, wolDefaultPort)
	}
	return target
}

// WakeOnLAN 依次向 target 广播 macs 对应的魔术包, 用于唤醒支持 WOL 的内网机器。
//
// target 留空则用受限广播 255.255.255.255:9(见 wolDefaultAddr/wolDefaultPort); 只填
// 地址不填端口时补默认端口。Go 的 net 包对所有 UDP socket 默认已经开了 SO_BROADCAST
// (见 net 包 setDefaultSockopts), 这里不需要再手工设置, 三平台通用。
//
// 先把 macs 全部校验一遍再发送: 列表里一个格式错就整批都不发, 避免"发出去一半才
// 报错"这种不上不下的状态。魔术包走 UDP, 写成功只代表包已经离开本机, 不代表对方
// 真的醒了——网卡/BIOS 没开 WOL、交换机不转发广播都会让包石沉大海, 这一层没有
// 办法探测/确认结果。
func WakeOnLAN(macs []string, target string) error {
	packets := make([][]byte, 0, len(macs))
	for _, mac := range macs {
		packet, err := buildMagicPacket(mac)
		if err != nil {
			return fmt.Errorf("invalid mac %w", err)
		}
		packets = append(packets, packet)
	}

	addr, err := net.ResolveUDPAddr("udp4", wolTarget(target))
	if err != nil {
		return fmt.Errorf("resolve %s: %w", target, err)
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	for i, packet := range packets {
		if _, err := conn.Write(packet); err != nil {
			return fmt.Errorf("send to %s for %s: %w", addr, macs[i], err)
		}
	}
	return nil
}
