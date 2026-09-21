package nat

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// 远程网络唤醒: 让 -wol-at 指定的订阅方在**它自己**的局域网里广播一次 WOL 魔术包,
// 而不是在发起这条命令的本机广播(见 nat/wol.go 的本机版 WakeOnLAN)。这个动作
// 只有一个目的地——要唤醒的机器本来就没开机, 没法自己接这条命令, 必须请同一个
// 局域网里另一台已经开着、跑着 anyproxy 的机器代劳。
//
// 只走服务端中继(见 nat/file_relay.go 的 FileRelayOpen/Op), 不支持 -send 那种打洞
// 直连或经 VPS 盲转发打洞: 魔术包只有 102 字节, 一来一回就结束, 打洞那一套(反射、
// 端口映射、握手竞速)带来的连接建立开销和复杂度完全划不来, 直接经 B 转发一次就好。
// 鉴权沿用 onFileRelayOpen 里对 client.receive.allow 的 uuid 核对, 与"这个人能不能
// 给我发文件"是同一条信任边界——能让对方在自己磁盘上写文件的人, 让他顺手广播一个
// 网络包不构成额外的风险。

// wolRequest 请求对端广播的内容, 语义与本机 -wol/-wol-to 完全一致。
type wolRequest struct {
	Macs   []string `json:"macs"`
	Target string   `json:"target,omitempty"`
}

// wolReply 对端执行结果, 非空 Err 表示广播失败或请求被拒绝。
type wolReply struct {
	Err string `json:"err"`
}

// serveWolOver 处理一条已通过鉴权的 wol 请求: 读请求、在本机执行广播、回结果。
// 身份核对由调用方(onFileRelayOpen)在此之前完成, 这里不再重复核对。
//
// 不在这里关 conn: 与 servePull 的 list/hash 分支同一个约定——用完由调用方就地
// fileRelayPipes.Delete, 不需要额外发一次中继的 METHOD_CLOSE(那是给可能中途出错、
// 对端还卡在等确认的大文件传输准备的, 这里一问一答就结束, 用不上)。
func serveWolOver(conn fileConn, fromEmail, remote string, logf func(string, ...interface{})) {
	// 请求帧要有超时: 开了流却不发请求的对端会一直占着它, 与 file_pull.go 的
	// filePullReplyTimeout 同一考虑, 直接复用它的时限。
	_ = conn.SetReadDeadline(time.Now().Add(filePullReplyTimeout))
	var req wolRequest
	if err := readFrame(conn, &req, fileFrameMax); err != nil {
		logf("wol from %s (%s): bad request: %v", remote, fromEmail, err)
		_ = writeFrame(conn, wolReply{Err: fmt.Sprintf("bad wol request: %v", err)})
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if err := WakeOnLAN(req.Macs, req.Target); err != nil {
		logf("wol from %s (%s): %v", remote, fromEmail, err)
		_ = writeFrame(conn, wolReply{Err: err.Error()})
		return
	}
	logf("wol from %s (%s): sent magic packet to %d mac(s)", remote, fromEmail, len(req.Macs))
	_ = writeFrame(conn, wolReply{})
}

// sendWolOver 在一条已建立的中继连接(msgPipe, 实现 fileConn)上发一次 wol 请求并等
// 对端回应。用完即关, 与 sendFileOverRange 的约定一致。
func sendWolOver(conn fileConn, macs []string, target string) error {
	defer conn.Close()
	if err := writeFrame(conn, wolRequest{Macs: macs, Target: target}); err != nil {
		return fmt.Errorf("send wol request: %w", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(filePullReplyTimeout))
	var resp wolReply
	err := readFrame(conn, &resp, fileFrameMax)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("no answer from peer: %w", err)
	}
	if resp.Err != "" {
		return errors.New(resp.Err)
	}
	return nil
}

// sendWolViaRelay 经服务端中继(不打洞)请求 toEmail 广播一次 wol 魔术包。
func sendWolViaRelay(client *Client, toEmail string, macs []string, target string) error {
	secured, _, err := openRelayConn(client, toEmail, fileRelayOpWol)
	if err != nil {
		return err
	}
	return sendWolOver(secured, macs, target)
}

// ---------- 一次性命令行入口 ----------

// SendWol 请求 at 对应的订阅方在它自己的局域网内广播 macs 的 WOL 魔术包并退出。
// target 是对方执行广播时使用的目标地址, 语义与本机 -wol/-to 完全一致(留空即对方的
// 默认受限广播 255.255.255.255:9)。固定走服务端中继, 见文件头部的说明; at 复用
// -send/-recv 的 -via flag, 因此必须是订阅方 email, 不接受它那两个专用关键字。
func SendWol(cfg conf.WsClient, at string, macs []string, target string) error {
	if cfg.Connect == "" {
		return fmt.Errorf("websocket.client.connect is empty, cannot reach the server")
	}
	if at == "" {
		return fmt.Errorf("-via is required: which subscriber (on the target machine's LAN) should broadcast the magic packet")
	}
	if at == ViaDirect || at == ViaRelay {
		return fmt.Errorf("-via %s is not meaningful for -wol: give the email of the subscriber who should broadcast instead", at)
	}
	if at == cfg.Email {
		return fmt.Errorf("-via %s is this machine's own email", at)
	}

	sender, err := dialSender(cfg, "wol")
	if err != nil {
		return err
	}
	defer sender.close()

	if err := sendWolViaRelay(sender.client, at, macs, target); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wol: asked %s to broadcast a magic packet to %d mac(s)\n", at, len(macs))
	return nil
}
