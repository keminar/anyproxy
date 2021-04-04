package nat

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/utils/trace"
)

var interruptClose bool

// Client is a middleman between the websocket connection and the hub.
type Client struct {
	hub *Hub

	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan *Message

	User      string
	Subscribe SubscribeMessage
}

// write to pc client
func (c *Client) writePump() {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()
	for {
		select {
		case message, ok := <-c.send: //ok为判断channel是否关闭
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if !ok {
				// The hub closed the channel.
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			c.conn.WriteJSON(message)
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

var LocalBridge *BridgeHub

func ConnectServer(addr *string) {
	interruptClose = false
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	LocalBridge = newBridgeHub()
	go LocalBridge.run()

	for {
		conn(addr, interrupt)
		if interruptClose {
			break
		}
	}
}

func dialProxy() net.Conn {
	connTimeout := time.Duration(5) * time.Second
	var err error
	localProxy := fmt.Sprintf("%s:%d", "127.0.0.1", config.ListenPort)
	proxyConn, err := net.DialTimeout("tcp", localProxy, connTimeout)
	if err != nil {
		fmt.Println("dial local proxy", err)
	}
	log.Printf("websocket connecting to %s", localProxy)
	return proxyConn
}

func copyBuffer(dst io.Writer, src io.Reader, srcname string) (written int64, err error) {
	//如果设置过大会耗内存高，4k比较合理
	size := 4 * 1024
	buf := make([]byte, size)
	i := 0
	for {
		i++
		nr, er := src.Read(buf)
		if nr > 0 {
			fmt.Println("test", string(buf[0:nr]))
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

type ClientHandler struct {
	c *websocket.Conn
}

func newClientHandler(c *websocket.Conn) *ClientHandler {
	return &ClientHandler{c: c}
}

func (h *ClientHandler) Auth(user string, token string) error {
	msg := AuthMessage{User: user, Token: token}
	return h.ask(&msg)
}

func (h *ClientHandler) Subscribe(key string, val string) error {
	msg := SubscribeMessage{Key: key, Val: val}
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

func conn(addr *string, interrupt chan os.Signal) {

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
	err = w.Auth("111", "test")
	if err != nil {
		log.Println("auth:", err)
		time.Sleep(time.Duration(3) * time.Second)
		return
	}
	err = w.Subscribe("aa", "bb")
	if err != nil {
		log.Println("subscribe:", err)
		time.Sleep(time.Duration(3) * time.Second)
		return
	}
	log.Println("websocket auth and subscribe ok")

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			msg := &Message{}
			err := w.c.ReadJSON(msg)
			if err != nil {
				break
			}
			if msg.Method == "create" {
				proxConn := dialProxy()
				b := LocalBridge.Register(msg.ID, proxConn.(*net.TCPConn))
				go b.ReadPump()

				// 从tcp返回数据到ws
				go func() {
					readSize, err := copyBuffer(b, proxConn, "server")
					logCopyErr("local->websocket", err)
					log.Println(trace.ID(msg.ID), "request body size", readSize)
					// close
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
