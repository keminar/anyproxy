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
	"github.com/keminar/anyproxy/proto/tcp"
)

var interruptClose bool

var proxyConn net.Conn
var proxyBool bool

func NewClient(addr *string) {
	interruptClose = false
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	proxyBool = false
	for {
		conn(addr, interrupt)
		if interruptClose {
			break
		}
	}
}

func dial() {
	connTimeout := time.Duration(5) * time.Second
	var err error
	localProxy := fmt.Sprintf("%s:%d", "127.0.0.1", config.ListenPort)
	proxyConn, err = net.DialTimeout("tcp", localProxy, connTimeout)
	if err != nil {
		fmt.Println("dial local proxy", err)
	}
	log.Printf("websocket connecting to %s", localProxy)
	proxyBool = true
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
			if srcname == "client" && string(buf[0:nr]) == "ok" {
				fmt.Println("recv ok")
				break
			}
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

func (h *ClientHandler) Read(p []byte) (n int, err error) {
	_, message, err := h.c.ReadMessage()
	n = copy(p, message)
	return n, err
}

func (h *ClientHandler) Write(p []byte) (n int, err error) {
	h.c.SetWriteDeadline(time.Now().Add(writeWait))

	w, err := h.c.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}
	w.Write(p)
	if err := w.Close(); err != nil {
		return 0, err
	}
	return len(p), nil
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
	case message := <-send:
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
			if proxyBool == false {
				dial()
			}
			// 如果与服务器断开，需要重连
			reConn := false
			done2 := make(chan int, 1)
			go func() {
				defer func() {
					done2 <- 1
					close(done2)
				}()
				readSize, err := copyBuffer(proxyConn.(*net.TCPConn), w, "client")
				log.Println("request body size", readSize)
				logCopyErr("websocket->client", err)
				proxyConn.(*net.TCPConn).CloseWrite()
				proxyBool = false
				if err != nil {
					reConn = true
				}
			}()
			writeSize, err := copyBuffer(w, tcp.NewReader(proxyConn.(*net.TCPConn)), "websocket")
			log.Println("websocket transfer finished, response size", writeSize)
			logCopyErr("client->websocket", err)
			w.Write([]byte("ok"))
			<-done2
			if reConn {
				break
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
