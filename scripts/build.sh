#!/bin/bash
SCRIPT=$(readlink -f $0)
ROOT_DIR=$(dirname $SCRIPT)/../
cd $ROOT_DIR

mkdir -p dist/

# 路径
GOCMD="go"
GITCMD="git"

# 目标文件前缀
BIN="anyproxy"

# 版本号
ARCH="amd64"

#组装变量
GOBUILD="${GOCMD} build"
VER=`${GITCMD} describe --tags $(${GITCMD} rev-list --tags --max-count=1)`
GOVER=`${GOCMD} version`
COMMIT_SHA1=`${GITCMD} rev-parse HEAD`
HELP_PRE="github.com/keminar/anyproxy/utils/help"
LDFLAGS="-X '${HELP_PRE}.goVersion=${GOVER}'" 
LDFLAGS="${LDFLAGS} -X '${HELP_PRE}.gitHash=${COMMIT_SHA1}'" 
LDFLAGS="${LDFLAGS} -X '${HELP_PRE}.version=${VER}'" 

# 编译
echo "build ..."
if [ "$1" == "all" ] || [ "$1" == "linux" ] ;then
    echo "  for linux"
    CGO_ENABLED=0 GOOS=linux GOARCH=${ARCH} ${GOBUILD} -trimpath -ldflags "$LDFLAGS" -o dist/${BIN}-${ARCH}-${VER}  anyproxy.go
fi

if [ "$1" == "all" ] || [ "$1" == "mac" ] ;then
    echo "  for mac"
    CGO_ENABLED=0 GOOS=darwin GOARCH=${ARCH} ${GOBUILD} -trimpath -ldflags "$LDFLAGS" -o dist/${BIN}-darwin-${ARCH}-${VER} anyproxy.go
fi

if [ "$1" == "all" ] || [ "$1" == "windows" ] ;then
    echo "  for windows"
    CGO_ENABLED=0 GOOS=windows GOARCH=${ARCH} ${GOBUILD} -trimpath -ldflags "$LDFLAGS" -o dist/${BIN}-windows-${ARCH}-${VER}.exe anyproxy.go
fi

if [ "$1" == "all" ] || [ "$1" == "alpine" ] ;then
    echo "  for alpine"
    CGO_ENABLED=0 GOOS=linux GOARCH=${ARCH} ${GOBUILD} -tags netgo -trimpath -ldflags "$LDFLAGS" -o dist/${BIN}-alpine-${ARCH}-${VER}  anyproxy.go
fi