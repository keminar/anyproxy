CGO_ENABLED=0 GOOS=windows go build -o nat-punch.exe .
CGO_ENABLED=0 GOOS=linux go build -o nat-punch .
