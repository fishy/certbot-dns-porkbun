.phony: build
build: main.go
	GODEBUG=netdns=go+1 go build -trimpath
