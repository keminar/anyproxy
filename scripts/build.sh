# for alpine
go build -tags netgo -o anyproxy.netgo  anyproxy.go

# common
go build -o anyproxy  anyproxy.go
go build -o tunnel/tunneld tunnel/tunneld.go