#!/bin/bash
SCRIPT=$(readlink -f $0)
ROOT_DIR=$(dirname $SCRIPT)/../
cd $ROOT_DIR

mkdir -p dist/

# 版本号
VER=`git describe --tags $(git rev-list --tags --max-count=1)`
GOVER=`go version`
COMMIT_SHA1=`git rev-parse HEAD`
HELP_PRE="github.com/keminar/anyproxy/utils/help"
LDFLAGS="-X '${HELP_PRE}.goVersion=${GOVER}'" 
LDFLAGS="${LDFLAGS} -X '${HELP_PRE}.gitHash=${COMMIT_SHA1}'" 
LDFLAGS="${LDFLAGS} -X '${HELP_PRE}.version=${VER}'" 

# anyproxy
echo "build anyproxy"
# for linux
echo "  for linux"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o dist/anyproxy-${VER}  anyproxy.go

# for mac
echo "  for mac"
CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAGS" -o dist/anyproxy-darwin-${VER} anyproxy.go

# for windows
echo "  for windows"
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAGS" -o dist/anyproxy-windows-${VER}.exe anyproxy.go

# for alpine
echo "  for alpine"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags netgo -ldflags "$LDFLAGS" -o dist/anyproxy-alpine-${VER}  anyproxy.go

# tunneld
echo "build tunneld"
echo "  for linux"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAGS" -o dist/tunneld-${VER} tunnel/tunneld.go

# for alpine
echo "  for alpine"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -tags netgo -ldflags "$LDFLAGS" -o dist/tunneld-alpine-${VER}  tunnel/tunneld.go