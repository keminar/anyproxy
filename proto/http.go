package proto

import "regexp"

/*
OPTIONS
GET
HEAD
POST
PUT
DELETE
TRACE
CONNECT
*/

var HTTPReqExp = regexp.MustCompile("^[a-zA-Z]+\\s+([^\\s]+)\\s+HTTP/1.\\d")
