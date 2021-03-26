#!/bin/bash
SCRIPT=$(readlink -f $0)
ROOT_DIR=$(dirname $SCRIPT)/../
cd $ROOT_DIR


# anyproxy
echo "build anyproxy"
# for linux
echo "  for linux"
go build -o anyproxy  anyproxy.go

# for mac
echo "  for mac"
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o anyproxy.mac anyproxy.go

# for windows
echo "  for windows"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o anyproxy.exe anyproxy.go

# for alpine
echo "  for alpine"
go build -tags netgo -o anyproxy.netgo  anyproxy.go

# tunneld
echo "build tunneld"
go build -o tunnel/tunneld tunnel/tunneld.go