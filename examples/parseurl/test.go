package main

import (
	"fmt"
	"net/url"
)

func main() {
	rawurl := "http://www.example.com:443"
	xx, _ := url.ParseRequestURI(rawurl)
	fmt.Println(xx.Host, xx.Port())
	fmt.Println(xx.String())

	rawurl = "http://www.example.com:80"
	xx, _ = url.ParseRequestURI(rawurl)
	fmt.Println(xx.Host, xx.Port())
	fmt.Println(xx.String())

	rawurl = "http:///test.html"
	xx, _ = url.ParseRequestURI(rawurl)
	fmt.Println("test", xx.Host, xx.Port())
}
