FROM golang:1.12.7 AS builder

COPY . .

RUN go build anyproxy.go
RUN  go build tunnel/tunneld.go

FROM golang:1.12.7 AS final

WORKDIR /go
COPY --from=builder anyproxy /go/anyproxy
COPY --from=builder tunneld /go/tunneld

ENTRYPOINT [ "/go/anyproxy" ]