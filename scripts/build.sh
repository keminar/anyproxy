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
    CGO_ENABLED=0 GOOS=linux GOARCH=${ARCH} ${GOBUILD} -trimpath -ldflags "$LDFLAGS" -o dist/${BIN}-${ARCH}-${VER}  .
fi

if [ "$1" == "all" ] || [ "$1" == "mac" ] ;then
    echo "  for mac"
    CGO_ENABLED=0 GOOS=darwin GOARCH=${ARCH} ${GOBUILD} -trimpath -ldflags "$LDFLAGS" -o dist/${BIN}-darwin-${ARCH}-${VER} .
fi

if [ "$1" == "all" ] || [ "$1" == "windows" ] ;then
    # 每个架构打成独立成套的包目录 dist/<BIN>-windows-<arch>-<VER>/:
    # exe 与它自己的 WinDivert 运行时放在一起。WinDivert.dll 是固定文件名且
    # 64/32 位内容不同, 若都拷进同一扁平目录会互相覆盖, 故按架构分目录隔离。
    # "arch:windivert子目录" 映射: amd64 用 x64, 386 用 x86。
    for pair in "amd64:x64" "386:x86"; do
        warch=${pair%%:*}
        wddir=${pair##*:}
        echo "  for windows/${warch} -> ${BIN}-windows-${warch}-${VER}.exe"
        out="dist/${BIN}-windows-${warch}-${VER}"
        mkdir -p "${out}"
        CGO_ENABLED=0 GOOS=windows GOARCH=${warch} ${GOBUILD} -trimpath -ldflags "$LDFLAGS" -o "${out}/${BIN}-windows-${warch}-${VER}.exe" .
        # WinDivert 运行时(需与 exe 同目录, 或用 tun.windows.windivertDir 指定)。
        cp -f WinDivert-2.2.2-A/${wddir}/* "${out}/" 2>/dev/null || true
    done
fi

if [ "$1" == "all" ] || [ "$1" == "alpine" ] ;then
    echo "  for alpine"
    CGO_ENABLED=0 GOOS=linux GOARCH=${ARCH} ${GOBUILD} -tags netgo -trimpath -ldflags "$LDFLAGS" -o dist/${BIN}-alpine-${ARCH}-${VER}  .
fi

# MIPS(路由器等). GOMIPS=softfloat: 多数 MIPS 设备无硬件 FPU, 用软浮点避免非法指令崩溃。
# mips=大端, mipsle=小端(按设备选)。
if [ "$1" == "all" ] || [ "$1" == "mips" ] ;then
    echo "  for mips (softfloat)"
    CGO_ENABLED=0 GOOS=linux GOARCH=mips   GOMIPS=softfloat ${GOBUILD} -trimpath -ldflags "$LDFLAGS" -o dist/${BIN}-mips   .
    echo "  for mipsle (softfloat)"
    CGO_ENABLED=0 GOOS=linux GOARCH=mipsle GOMIPS=softfloat ${GOBUILD} -trimpath -ldflags "$LDFLAGS" -o dist/${BIN}-mipsle .
fi