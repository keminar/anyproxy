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
	err = tunnel.handshake(protoTCP, that.req.DstName, that.req.DstIP, that.req.DstPort)
	if err != nil {
		log.Println(trace.ID(that.req.ID), "handshake err", err.Error())
		return err
	}

	tunnel.transfer(-1)
	return nil
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
