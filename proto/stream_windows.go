package proto

import (
	"errors"
	"net"
)

// GetOriginalDstAddr 目标
func GetOriginalDstAddr(tcpConn *net.TCPConn) (dstIP string, dstPort uint16, newTCPConn *net.TCPConn, err error) {
	err = errors.New("ERR: windows can not work")
	return
}
