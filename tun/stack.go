//go:build !windows
// +build !windows

package tun

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"syscall"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/grace"
	"github.com/keminar/anyproxy/proto"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const (
	nicID = 1
	// forwarder 允许的最大半连接数
	maxInFlight = 2048
	// channel endpoint 出向队列长度(每个包最大约一个MTU)。
	// 512*1500≈768KB 上限，足够缓冲，比默认省内存
	channelQueue = 512

	// TCP 收发缓冲区大小。gVisor 默认 Default=1MB/Max=4MB，客户端代理场景
	// 单连接就占 2MB 基线、峰值 8MB，连接一多内存暴涨。这里大幅调小:
	// Default 64KB 砍掉 16 倍基线，配合接收缓冲自动调节(moderate)按需增长，
	// Max 1MB 兼顾高带宽时延链路吞吐，同时把单连接峰值内存压到 1/4。
	tcpBufMin     = 4 * 1024        // 4KB
	tcpBufDefault = 64 * 1024       // 64KB
	tcpBufMax     = 1 * 1024 * 1024 // 1MB

	// TIME_WAIT/Linger 定时器时长，默认各 60s，缩短以加快连接资源回收
	tcpTimeWait = 5 * time.Second
)


// runStack 在TUN设备上运行 gVisor 用户态协议栈，把捕获到的TCP连接交给
// proto.ForwardTCP 复用已有代理路由逻辑。阻塞直到 ctx 结束或设备关闭。
func runStack(ctx context.Context, dev Device) error {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol, ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol, udp.NewProtocol,
		},
	})
	tuneStackMemory(s)

	ep := channel.New(channelQueue, dev.MTU(), "")

	if tcpErr := s.CreateNIC(nicID, ep); tcpErr != nil {
		return fmt.Errorf("create nic: %v", tcpErr)
	}
	// 接管发往任意目标地址的流量(目标并非本机NIC地址)
	if tcpErr := s.SetPromiscuousMode(nicID, true); tcpErr != nil {
		return fmt.Errorf("set promiscuous: %v", tcpErr)
	}
	if tcpErr := s.SetSpoofing(nicID, true); tcpErr != nil {
		return fmt.Errorf("set spoofing: %v", tcpErr)
	}

	// 全量路由: v4/v6 均导入该NIC
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nicID},
		{Destination: header.IPv6EmptySubnet, NIC: nicID},
	})

	// TCP 转发器: 每个新连接触发回调。
	// rcvWnd 传 tcpBufDefault(而非0，0会用gVisor硬编码的1MB)，与调小后的默认缓冲一致
	fwd := tcp.NewForwarder(s, tcpBufDefault, maxInFlight, func(r *tcp.ForwarderRequest) {
		handleTCP(ctx, r)
	})
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, fwd.HandlePacket)

	udpFwd := newUDPForwarder(dev)
	// 设备 -> 协议栈（UDP 提前拦截）
	go devToStack(ctx, dev, ep, udpFwd)
	// 协议栈 -> 设备 (阻塞)
	stackToDev(ctx, dev, ep)
	return nil
}

// tuneStackMemory 调小 TCP 收发缓冲，并开启接收缓冲自动调节，
// 显著降低多连接下的内存占用(选项设置失败不致命，仅记日志)。
func tuneStackMemory(s *stack.Stack) {
	sndOpt := tcpip.TCPSendBufferSizeRangeOption{Min: tcpBufMin, Default: tcpBufDefault, Max: tcpBufMax}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sndOpt); err != nil {
		log.Printf("tun tune send buffer err: %v\n", err)
	}
	rcvOpt := tcpip.TCPReceiveBufferSizeRangeOption{Min: tcpBufMin, Default: tcpBufDefault, Max: tcpBufMax}
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &rcvOpt); err != nil {
		log.Printf("tun tune recv buffer err: %v\n", err)
	}
	// 接收缓冲按实际吞吐自动增长，空闲/低速连接保持小内存
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate); err != nil {
		log.Printf("tun tune moderate recv buffer err: %v\n", err)
	}
	// 缩短 TIME_WAIT/Linger 定时器(默认各 60s)。大量短连接压测时，关闭的连接
	// endpoint 会驻留 60s 占内存，100 个连接就攒下大量残留。缩到 5s 让内核态
	// 连接资源快速回收，本机代理无需长 TIME_WAIT 防旧包
	timeWait := tcpip.TCPTimeWaitTimeoutOption(tcpTimeWait)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &timeWait); err != nil {
		log.Printf("tun tune timewait err: %v\n", err)
	}
	linger := tcpip.TCPLingerTimeoutOption(tcpTimeWait)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &linger); err != nil {
		log.Printf("tun tune linger err: %v\n", err)
	}
}

// handleTCP 处理协议栈捕获到的一个TCP连接请求
func handleTCP(ctx context.Context, r *tcp.ForwarderRequest) {
	id := r.ID()
	dstIP := id.LocalAddress.String()
	dstPort := id.LocalPort
	srcIP := id.RemoteAddress.String()
	srcPort := id.RemotePort

	// 抓包诊断: 源地址若为物理网卡 IP(而非 TUN 网段)则是本进程出向被回灌的环路迹象。
	if config.DebugLevel >= config.LevelDebug {
		log.Printf("tun capture tcp %s:%d -> %s:%d\n", srcIP, srcPort, dstIP, dstPort)
	}

	var wq waiter.Queue
	tcpEP, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		log.Printf("tun create endpoint %s:%d err: %v\n", dstIP, dstPort, tcpErr)
		r.Complete(true) // 发送RST
		return
	}
	r.Complete(false)

	conn := gonet.NewTCPConn(&wq, tcpEP)
	reqID := grace.NextTraceID()
	cctx := context.WithValue(ctx, grace.TraceIDContextKey, reqID)

	go func() {
		defer conn.Close()
		_ = proto.ForwardTCP(cctx, reqID, conn, srcIP, dstIP, dstPort)
	}()
}

// devToStack 从TUN设备读IP包注入协议栈；UDP 包直接转发，不经 gVisor。
func devToStack(ctx context.Context, dev Device, ep *channel.Endpoint, fwd *udpForwarder) {
	for {
		pkt, err := dev.ReadPacket()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, os.ErrClosed) || errors.Is(err, syscall.EBADF) {
				return
			}
			log.Println("tun read err:", err)
			return
		}
		if len(pkt) == 0 {
			continue
		}
		// UDP：在进 gVisor 之前拦截，直接走物理网卡转发
		if isUDP(pkt) {
			fwd.handle(pkt)
			select {
			case <-ctx.Done():
				return
			default:
			}
			continue
		}
		var proto tcpip.NetworkProtocolNumber
		switch pkt[0] >> 4 {
		case 4:
			proto = header.IPv4ProtocolNumber
		case 6:
			proto = header.IPv6ProtocolNumber
		default:
			continue
		}
		pb := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(pkt),
		})
		ep.InjectInbound(proto, pb)
		pb.DecRef()

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}

// stackToDev 从协议栈取出向IP包写回TUN设备
func stackToDev(ctx context.Context, dev Device, ep *channel.Endpoint) {
	for {
		pb := ep.ReadContext(ctx)
		if pb == nil {
			// ctx 结束或 endpoint 关闭
			return
		}
		buf := pb.ToView().AsSlice()
		err := dev.WritePacket(buf)
		pb.DecRef()
		if err != nil {
			log.Println("tun write err:", err)
		}
	}
}
