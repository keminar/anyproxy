package nat

import (
	"log"
	"net/http"
)

var WsHub *Hub

func NewServer(addr *string) {
	WsHub = newHub()
	go WsHub.run()
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(WsHub, w, r)
	})
	err := http.ListenAndServe(*addr, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
