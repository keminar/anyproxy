package nat

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/tools"

	"github.com/gorilla/websocket"
	"github.com/keminar/anyproxy/config"
)

// ClientHub 客户端的ws信息
var ClientHub *Hub

// LocalBridge 客户端的ws与http关系
var LocalBridge *BridgeHub

// ConnectServer 连接到websocket服务
func ConnectServer(addr *string) {
	interruptClose = false
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	ClientHub = newHub()
	go ClientHub.run()
	LocalBridge = newBridgeHub()
	go LocalBridge.run()

	addrs := strings.Split(*addr, "://")
	if addrs[0] == "ws" && len(addrs) == 2 {
		*addr = addrs[1]
	}
	for {
		connect(addr, interrupt)
		if interruptClose {
			break
		}
	}
}

// 连接本地Proxy服务
func dialProxy() net.Conn {
	connTimeout := time.Duration(5) * time.Second
	var err error
	localProxy := fmt.Sprintf("%s:%d", "127.0.0.1", config.ListenPort)
	proxyConn, err := net.DialTimeout("tcp", localProxy, connTimeout)
	if err != nil {
		log.Println("dial local proxy", err)
	}
	log.Printf("local websocket connecting to %s", localProxy)
	return proxyConn
}

// 认证连接并交换数据
func connect(addr *string, interrupt chan os.Signal) {
	u := url.URL{Scheme: "ws", Host: *addr, Path: "/ws"}
	log.Printf("connecting to %s", u.String())

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		log.Println("dial:", err)
		time.Sleep(time.Duration(3) * time.Second)
		return
	}
	defer c.Close()

	w := newClientHandler(c)
	err = w.auth(conf.RouterConfig.Websocket.User, conf.RouterConfig.Websocket.Pass)
	if err != nil {
		log.Println("auth:", err)
		time.Sleep(time.Duration(3) * time.Second)
		return
	}
	err = w.subscribe(conf.RouterConfig.Websocket.Subscribe)
	if err != nil {
		log.Println("subscribe:", err)
		time.Sleep(time.Duration(3) * time.Second)
		return
	}
	log.Println("websocket auth and subscribe ok")

	client := &Client{hub: ClientHub, conn: c, send: make(chan *Message, SEND_CHAN_LEN)}
	client.hub.register <- client
	defer func() {
		client.hub.unregister <- client
	}()

	go client.writePump()
	done := make(chan struct{})
	go func() { //客户端的client.readRump
		defer close(done)
		client.localReadPump()
	}()

	for {
		select {
		case <-done:
			return
		case <-interrupt:
			log.Println("interrupt")
			interruptClose = true

			// Cleanly close the connection by sending a close message and then
			// waiting (with timeout) for the server to close the connection.
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("write close:", err)
				return
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}

// ClientHandler 认证助手
type ClientHandler struct {
	c *websocket.Conn
}

func newClientHandler(c *websocket.Conn) *ClientHandler {
	return &ClientHandler{c: c}
}

// auth 认证
func (h *ClientHandler) auth(user string, pass string) error {
	xtime := time.Now().Unix()
	token, err := tools.Md5Str(fmt.Sprintf("%s|%s|%d", user, pass, xtime))
	if err != nil {
		return err
	}
	msg := AuthMessage{User: user, Token: token, Xtime: xtime}
	return h.ask(&msg)
}

// subscribe 订阅
func (h *ClientHandler) subscribe(sub []conf.Subscribe) error {
	msg := []SubscribeMessage{}
	for _, s := range sub {
		msg = append(msg, SubscribeMessage{Key: s.Key, Val: s.Val})
	}
	return h.ask(&msg)
}

func (h *ClientHandler) ask(v interface{}) error {
	err := h.c.WriteJSON(v)
	if err != nil {
		return err
	}
	ticker := time.NewTicker(3 * time.Second)
	defer func() {
		ticker.Stop()
	}()

	send := make(chan []byte)
	go func() {
		defer close(send)
		_, message, _ := h.c.ReadMessage()
		send <- message
	}()
	select {
	case message, ok := <-send: //ok为判断channel是否关闭
		if !ok {
			return errors.New("fail")
		}
		if string(message) != "ok" {
			return errors.New("fail, " + string(message))
		}
	case <-ticker.C:
		return errors.New("timeout")
	}
	return nil
}

// md5
func md5Byte(data []byte) (string, error) {
	h := md5.New()
	h.Write(data)
	cipherStr := h.Sum(nil)
	return hex.EncodeToString(cipherStr), nil
}
