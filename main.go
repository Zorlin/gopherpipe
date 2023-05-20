package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"

	kcp "github.com/xtaci/kcp-go"
)

const (
	bufferSize = 134217728 // 128 MB
)

var (
	serverMode = flag.Bool("server", false, "run in server mode")
	debug      = flag.Bool("debug", false, "enable debug mode")
	port       = flag.String("port", "51115", "port number to use")
	address    = flag.String("addr", "", "address for client mode")
)

func main() {
	flag.Parse()

	if *serverMode {
		startServer(*port, *debug)
	} else {
		startClient(*address, *debug)
	}
}

func startServer(port string, debug bool) {
	listener, err := kcp.ListenWithOptions(":"+port, nil, 10, 3)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to start server:", err)
		return
	}
	fmt.Fprintf(os.Stderr, "Now listening for KCP connections on 0.0.0.0:%s\n", port)

	for {
		conn, err := listener.AcceptKCP()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to accept connection:", err)
			continue
		}
		fmt.Fprintf(os.Stderr, "Accepted connection from %s\n", conn.RemoteAddr())

		go handleConnection(conn, debug)
	}
}

func handleConnection(conn *kcp.UDPSession, debug bool) {
	defer conn.Close()

	buffer := make([]byte, bufferSize)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "Connection with %s failed: %s\n", conn.RemoteAddr(), err)
			}
			return
		}

		if debug {
			fmt.Fprintf(os.Stderr, "Received data: %s\n", string(buffer[:n]))
		}

		_, err = os.Stdout.Write(buffer[:n])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to write data to stream: %s, retrying...\n", err)
		}
	}
}

func startClient(addr string, debug bool) {
	conn, err := kcp.DialWithOptions(addr, nil, 10, 3)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to connect:", err)
		return
	}
	defer conn.Close()

	reader := bufio.NewReader(os.Stdin)
	buffer := make([]byte, bufferSize)

	for {
		n, err := reader.Read(buffer)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintln(os.Stderr, "Failed to read from stdin:", err)
			}
			return
		}

		if debug {
			fmt.Fprintf(os.Stderr, "Read data: %s\n", string(buffer[:n]))
		}

		_, err = conn.Write(buffer[:n])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to send data: %s, retrying...\n", err)
		}
	}
}
