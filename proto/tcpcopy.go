package proto

import (
	"errors"
	"log"

	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/trace"
)

type tcpCopy struct {
	req *Request
}

func newTCPCopy(req *Request) *tcpCopy {
	c := &tcpCopy{
		req: req,
	}
	return c
}

func (that *tcpCopy) validHead() bool {
	return true
}
func (that *tcpCopy) readRequest(from string) (canProxy bool, err error) {
	return true, nil
}

func (that *tcpCopy) response() error {
	tunnel := newTunnel(that.req)
	if ip, ok := tunnel.isAllowed(); !ok {
		return errors.New(ip + " is not allowed")
	}
	var err error
	that.req.DstIP = conf.RouterConfig.TcpCopy.IP
	that.req.DstPort = conf.RouterConfig.TcpCopy.Port

	network, connAddr := tunnel.buildAddress("", that.req.DstIP, that.req.DstPort)
	if connAddr == "" {
		err = errors.New("target address is empty")
		return err
	}
	tunnel.registerCounter("", that.req.DstIP, that.req.DstPort)
	err = tunnel.dail(network, connAddr)
	if err != nil {
		log.Println(trace.ID(that.req.ID), "dail err", err.Error())
		return err
	}
	tunnel.curState = stateNew

	tunnel.transfer(-1)
	return nil
}
