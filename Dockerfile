# 参考 https://studygolang.com/articles/26823
FROM golang:1.13.11-alpine AS builder

WORKDIR /go/src/github.com/keminar/anyproxy
# Go 版本>=1.13 设置GOPROXY
RUN go env -w GOPROXY=https://goproxy.cn,direct
COPY go.mod .
COPY go.sum .
# 缓存下载依赖包
RUN go mod download

COPY . .

RUN go build -o /go/bin/anyproxy anyproxy.go
RUN go build -o /go/bin/tunneld tunnel/tunneld.go

# debian比centos和golang镜像更小
# FROM debian:9 AS final
# alpine 镜像是最小的，大部分时间也够用
FROM alpine:3.11 AS final

WORKDIR /go
COPY --from=builder /go/bin/anyproxy /go/bin/anyproxy
COPY --from=builder /go/bin/tunneld /go/bin/tunneld

# 避免使用container的用户root
RUN adduser -u 1000 -D appuser
RUN mkdir logs/ && chown appuser logs/

USER appuser

# CMD 和 ENTRYPOINT 区别用法参考 https://blog.csdn.net/u010900754/article/details/78526443
ENTRYPOINT [ "/go/bin/anyproxy" ]