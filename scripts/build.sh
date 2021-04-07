#!/bin/bash
SCRIPT=$(readlink -f $0)
ROOT_DIR=$(dirname $SCRIPT)/../
cd $ROOT_DIR

mkdir -p dist/

# anyproxy
echo "build anyproxy"
# for linux
echo "  for linux"
go build -o dist/anyproxy  anyproxy.go

# for mac
echo "  for mac"
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o dist/anyproxy-darwin anyproxy.go

# for windows
echo "  for windows"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o dist/anyproxy-windows.exe anyproxy.go

# for alpine
echo "  for alpine"
go build -tags netgo -o dist/anyproxy-alpine  anyproxy.go

# tunneld
echo "build tunneld"
echo "  for linux"
go build -o dist/tunneld tunnel/tunneld.go

# for alpine
echo "  for alpine"
go build -tags netgo -o dist/tunneld-alpine  tunnel/tunneld.go