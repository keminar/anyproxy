# 参考 https://studygolang.com/articles/26823
FROM golang:1.13.11-alpine AS builder

WORKDIR /go/src/github.com/keminar/anyproxy
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
USER appuser

# 不用ENTRYPOINT的原因是docker run不方便覆盖 
# 具体参考 https://blog.csdn.net/u010900754/article/details/78526443
CMD [ "/go/bin/anyproxy" ]