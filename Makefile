PROTOSRC=$(HOME)/go/src

all: test protobuf server/server client/client

server/server: server/server.go
	go build -o server/server server/server.go 

client/client: client/client.go
	go build -o client/client client/client.go 

protobuf: proto/whitelist.proto
	mkdir -p $(PROTOSRC)
	protoc -I proto/ proto/whitelist.proto --go_out=plugins=grpc:$(PROTOSRC)

test_http:
	curl -d 'password=test' http://localhost:8080/login

test:
	go test ./...

clean:
	rm -f server/server client/client

