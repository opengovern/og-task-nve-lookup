package main

import (
	"fmt"
	"github.com/opengovern/og-task-nve-lookup/worker"
	"golang.org/x/net/context"
	"os"
	"os/signal"
	"syscall"
)

var (
	// Stream name
	StreamName = os.Getenv("STREAM_NAME")
	// Queue name
	QueueName = os.Getenv("QUEUE_NAME")
	// Topic name Reciever
	TopicNameReciever = os.Getenv("TOPIC_NAME")
	// Nats server url
	NatsURL = os.Getenv("NATS_URL")
	// Topic name Sender
	TopicNameSender = os.Getenv("TOPIC_NAME_SENDER")
	// GRPC server url
	GRPCServerURL = os.Getenv("GRPC_SERVER_URL")
)

func main() {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(c)
		cancel()
	}()

	go func() {
		select {
		case <-c:
			cancel()
		case <-ctx.Done():
		}
	}()

	if err := worker.WorkerCommand().ExecuteContext(ctx); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
