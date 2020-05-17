package proto

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
)

type Client struct {
	req *Request
}

func NewClient() *Client {
	c := &Client{}
	return c
}

func (that *Client) Handler(tcpConn *net.TCPConn) error {
	that.req = NewRequest(tcpConn)
	err := that.req.ReadRequest()
	if err != nil {
		return err
	}
	log.Println(that.req.IsHTTP, that.req.Method, that.req.RequestURI)
	log.Println(that.req.URL.Scheme, that.req.URL.Host, that.req.URL.Port(), that.req.Header)

	if that.req.Method == "CONNECT" {
		_, err := tcpConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if err != nil {
			log.Println("write err", err.Error())
			return err
		}
		_, dstIP, dstPort := getNameIPPort(that.req.URL.Scheme, that.req.Host, that.req.URL.Port())
		log.Println(dstIP, dstPort)
		rightConn, err := dail(dstIP, dstPort)
		if err != nil {
			log.Println("dail err", err.Error())
			return err
		}
		transfer(tcpConn, rightConn)
	} else {
		_, dstIP, dstPort := getNameIPPort(that.req.URL.Scheme, that.req.Host, that.req.URL.Port())
		if dstIP == "" || dstPort == 0 {
			fmt.Println("GetOriginalDstAddr")
			dstIP, dstPort, tcpConn, err = GetOriginalDstAddr(tcpConn)
			if err != nil {
				log.Println("GetOriginalDstAddr err", err.Error())
				return err
			}
		}
		log.Println(dstIP, dstPort)
		rightConn, err := dail(dstIP, dstPort)
		if err != nil {
			log.Println("dail err", err.Error())
			return err
		}

		tmp := fmt.Sprintf("%s %s %s\r\n", that.req.Method, that.req.RequestURI, that.req.Proto)
		rightConn.Write([]byte(tmp))
		that.req.Header.Write(rightConn)
		/*
			for k, kv := range that.req.Header {
				for _, v := range kv {
					tmp = fmt.Sprintf("%s: %s\r\n", k, v)
					log.Print(tmp)
					rightConn.Write([]byte(tmp))
				}
			}
		*/
		rightConn.Write([]byte("\r\n"))

		transfer(tcpConn, rightConn)

	}
	return nil
}

func getNameIPPort(scheme, host, port string) (string, string, uint16) {
	var dstIP string
	var dstPort uint16
	splitStr := strings.Split(host, ":")
	dstName := splitStr[0]
	upIPs, _ := net.LookupIP(splitStr[0])
	if len(upIPs) > 0 {
		dstIP = upIPs[0].String()
		c, _ := strconv.ParseUint(port, 0, 16)
		dstPort = uint16(c)
	}
	if dstPort == 0 {
		if scheme == "http" {
			dstPort = 80
		} else if scheme == "https" {
			dstPort = 443
		}
	}
	return dstName, dstIP, dstPort
}
