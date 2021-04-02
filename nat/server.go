package nat

import (
	"log"
	"net/http"
)

var WsHub *Hub
var Bridges *BridgeHub

func NewServer(addr *string) {
	WsHub = newHub()
	go WsHub.run()
	Bridges = newBridgeHub()
	go Bridges.run()

	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(WsHub, w, r)
	})
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
