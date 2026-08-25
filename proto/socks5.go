package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/keminar/anyproxy/utils/trace"
)

type socks5Stream struct {
	req *Request
}

func newSocks5Stream(req *Request) *socks5Stream {
	c := &socks5Stream{
		req: req,
	}
	return c
}

func (that *socks5Stream) validHead() bool {
	if that.req.reader.Buffered() < 2 {
		return false
	}

	tmpBuf, err := that.req.reader.Peek(2)
	if err != nil {
		return false
	}

	isSocks5 := len(tmpBuf) >= 2 && tmpBuf[0] == 0x05
	if isSocks5 {
		// 如果是SOCKS5则把已读信息从缓存区释放掉
		that.req.reader.UnreadBuf(-1)
	}
	return isSocks5
}

func (that *socks5Stream) readRequest(from string) (canProxy bool, err error) {
	if err = that.ParseHeader(); err != nil {
		return false, err
	}
	return true, nil
}

func (that *socks5Stream) response() error {
	tunnel := newTunnel(that.req)

	var err error
	// 发送socks5应答
	_, err = that.req.conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		log.Println(trace.ID(that.req.ID), "write err", err.Error())
		return err
	}

	that.showIP()
	// socks5 原样透传原始字节, 走 http 上级代理时须用 CONNECT 隧道(见 tunnel.go)
	that.req.Raw = true
	// 探测首包应用层协议(https/http), 让 socks5 与 TUN 一致地按 default.target 分流,
	// 而非一律当裸 tcp 只按 default.tcpTarget。探不出时保持 tcp。
	proto, closed := that.sniffProto()
	if closed {
		// 客户端未发数据即关闭(如浏览器放弃的预连接), 无需拨后端
		return nil
	}
	that.req.Proto = proto
	err = tunnel.handshake(proto, that.req.DstName, that.req.DstIP, that.req.DstPort)
	if err != nil {
		log.Println(trace.ID(that.req.ID), "handshake err", err.Error())
		return err
	}

	tunnel.transfer(-1)
	return nil
}

// sniffProto 在回复 socks5 成功应答后、握手前, 探测客户端首包判定应用层协议(https/http)。
// 与 TUN(forward.go sniffClientHead)对齐:
//   - 按端口给不同读超时: 80/443 一定客户端先说话, 等 5s(覆盖预连接静默); 其余端口大量是
//     "服务端先说话"协议(SSH/MySQL 等), 只等 200ms, 超时即按 tcp 继续, 不卡它们的握手。
//   - 区分超时与客户端已关: 超时 -> 无首包按 tcp 继续拨后端(closed=false);
//     EOF/RST -> 客户端放弃连接, closed=true, 调用方直接结束不拨后端。
//
// 用带缓冲的 Peek, 不消费数据, 缓冲里的首包随后由 transfer 原样转发, 无需像 TUN 那样补发。
func (that *socks5Stream) sniffProto() (proto string, closed bool) {
	timeout := sniffTimeout
	if that.req.DstPort == 80 || that.req.DstPort == 443 {
		timeout = sniffTimeoutHTTP
	}
	_ = that.req.conn.SetReadDeadline(time.Now().Add(timeout))
	_, err := that.req.reader.Peek(1) // 阻塞到首字节到达; fill 会顺带把整段首包读进缓冲
	_ = that.req.conn.SetReadDeadline(time.Time{})
	if err != nil {
		that.req.reader.ResetErr() // 清掉探测超时留下的挂起错误, 不影响后续正常转发
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return protoTCP, false // 超时: 静默/服务端先说话, 继续
		}
		return protoTCP, true // EOF/RST: 客户端已关, 不拨后端
	}
	head, _ := that.req.reader.Peek(that.req.reader.Buffered())
	return sniffProto(head), false
}

func (that *socks5Stream) showIP() {
	if that.req.DstName != "" {
		log.Println(trace.ID(that.req.ID), fmt.Sprintf("%s %s -> %s:%d", "Socks5", that.req.conn.RemoteAddr().String(), that.req.DstName, that.req.DstPort))
	} else {
		log.Println(trace.ID(that.req.ID), fmt.Sprintf("%s %s -> %s:%d", "Socks5", that.req.conn.RemoteAddr().String(), that.req.DstIP, that.req.DstPort))
	}
}

// parsing socks5 header, and return address and parsing error
func (that *socks5Stream) ParseHeader() error {
	// response to socks5 client
	// see rfc 1982 for more details (https://tools.ietf.org/html/rfc1928)
	n, err := that.req.conn.Write([]byte{0x05, 0x00}) // version and no authentication required
	if err != nil {
		return err
	}

	// step2: process client Requests and does Reply
	/**
	  +----+-----+-------+------+----------+----------+
	  |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	  +----+-----+-------+------+----------+----------+
	  | 1  |  1  | X'00' |  1   | Variable |    2     |
	  +----+-----+-------+------+----------+----------+
	*/
	var buffer [1024]byte
	n, err = that.req.reader.Read(buffer[:])
	if err != nil {
		return err
	}
	if n < 6 {
		return errors.New("not a socks protocol")
	}

	switch buffer[3] {
	case 0x01:
		// ipv4 address
		ipv4 := make([]byte, 4)
		if _, err := io.ReadAtLeast(bytes.NewReader(buffer[4:]), ipv4, len(ipv4)); err != nil {
			return err
		}
		//fmt.Println(1)
		that.req.DstIP = net.IP(ipv4).String()
	case 0x04:
		// ipv6
		ipv6 := make([]byte, 16)
		if _, err := io.ReadAtLeast(bytes.NewReader(buffer[4:]), ipv6, len(ipv6)); err != nil {
			return err
		}
		that.req.DstIP = net.IP(ipv6).String()
	case 0x03:
		// domain
		addrLen := int(buffer[4])
		domain := make([]byte, addrLen)
		if _, err := io.ReadAtLeast(bytes.NewReader(buffer[5:]), domain, addrLen); err != nil {
			return err
		}
		//fmt.Println(2)
		that.req.DstName = string(domain)
	}

	port := make([]byte, 2)
	err = binary.Read(bytes.NewReader(buffer[n-2:n]), binary.BigEndian, &port)
	if err != nil {
		return err
	}

	portStr := strconv.Itoa((int(port[0]) << 8) | int(port[1]))
	c, err := strconv.ParseUint(portStr, 0, 16)
	if err != nil {
		return err
	}
	that.req.DstPort = uint16(c)
	return nil
}
