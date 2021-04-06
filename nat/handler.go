package nat

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/tools"

	"github.com/gorilla/websocket"
	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/utils/trace"
)

var ClientHub *Hub
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

	client := &Client{hub: ClientHub, conn: c, send: make(chan *Message, 100)}

	go client.writePump()
	done := make(chan struct{})
	go func() { //客户端的client.readRump
		defer close(done)
		for {
			// 使用普通形式读，可以读到类似连接已关闭等的错误
			_, message, err := c.ReadMessage()
			if err != nil {
				log.Println("nat_local_debug_read_error", err.Error())
				return
			}

			msg := &Message{}
			err = json.Unmarshal(message, &msg)
			if err != nil {
				log.Println("nat_local_debug_json_error", err.Error())
				return
			}
			if config.DebugLevel >= config.LevelDebugBody {
				log.Println("nat_local_read_from_websocket_message", msg.ID, msg.Method, string(msg.Body))
			}

			if msg.Method == METHOD_CREATE {
				proxConn := dialProxy()
				b := LocalBridge.Register(client, msg.ID, proxConn.(*net.TCPConn))
				go func() {
					written, err := b.WritePump()
					logCopyErr("nat_local_debug websocket->local", err)
					log.Println(trace.ID(msg.ID), "nat debug response size", written)
				}()

				// 从tcp返回数据到ws
				go func() {
					defer func() {
						b.bridgeHub.unregister <- b
					}()
					readSize, err := b.CopyBuffer(b, proxConn, "local")
					logCopyErr("nat_local_debug local->websocket", err)
					log.Println(trace.ID(msg.ID), "nat debug request body size", readSize)
					b.CloseWrite()
				}()
			} else {
				LocalBridge.broadcast <- msg
			}
		}
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

func logCopyErr(name string, err error) {
	if err == nil {
		return
	}
	if config.DebugLevel >= config.LevelLong {
		log.Println(name, err.Error())
	} else if err != io.EOF {
		log.Println(name, err.Error())
	}
}
