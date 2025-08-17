package main

import (
	"context"
	"gopacket-example/server"
	"os/signal"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	server.StartServer(ctx)
}
