FROM golang:1.13.11-stretch AS builder

COPY . .

RUN go build anyproxy.go
RUN  go build tunnel/tunneld.go

FROM golang:1.13.11-stretch AS final

WORKDIR /go
COPY --from=builder anyproxy /go/anyproxy
COPY --from=builder tunneld /go/tunneld

ENTRYPOINT [ "/go/anyproxy" ]