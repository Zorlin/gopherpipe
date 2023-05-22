package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"os"
	"sync"

	quic "github.com/lucas-clemente/quic-go"
)

const (
	defaultBufferSize = 134217728               // 128 MB
	maxBufferSize     = 16 * 1024 * 1024 * 1024 // 16 GiB
	maxChannels       = 4096
)

var (
	serverMode  = flag.Bool("server", false, "run in server mode")
	debug       = flag.Bool("debug", false, "enable debug mode")
	port        = flag.String("port", "51115", "port number to use")
	address     = flag.String("addr", "", "address for client mode")
	certFile    = flag.String("cert", "", "certificate file")
	keyFile     = flag.String("key", "", "private key file")
	bufferSize  = flag.Uint64("buffer", defaultBufferSize, "buffer size in bytes (max 16GiB)")
	numChannels = flag.Uint("channels", 1, "number of transmission channels")
)

func main() {
	flag.Parse()

	if *bufferSize > maxBufferSize {
		fmt.Fprintln(os.Stderr, "Buffer size exceeds the maximum limit (16GiB). Using the default buffer size.")
		*bufferSize = defaultBufferSize
	}

	if *numChannels > maxChannels {
		fmt.Fprintln(os.Stderr, "Number of channels exceeds the maximum limit (4096). Using the default number of channels.")
		*numChannels = 1
	}

	tlsConfig := &tls.Config{
		NextProtos: []string{"quic-echo-example"},
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			return nil // Always return nil, to skip certificate validation
		},
	}

	if *certFile != "" && *keyFile != "" {
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to load certificate and key:", err)
			return
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	} else {
		tlsConfig.InsecureSkipVerify = true // Disable encryption
	}

	if *serverMode {
		startServer(*port, *debug, tlsConfig)
	} else {
		startClient(*address, *debug, tlsConfig)
	}
}

func startServer(port string, debug bool, tlsConfig *tls.Config) {
	listener, err := quic.ListenAddr(":"+port, tlsConfig, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to start server:", err)
		return
	}
	fmt.Fprintf(os.Stderr, "Now listening for QUIC connections on 0.0.0.0:%s\n", port)

	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to accept connection:", err)
			continue
		}
		fmt.Fprintf(os.Stderr, "Accepted connection from %s\n", session.RemoteAddr())

		go handleConnection(session, debug, *numChannels)
	}
}

func handleConnection(session quic.Session, debug bool, numChannels uint) {
	defer session.CloseWithError(0, "")

	wg := sync.WaitGroup{}
	wg.Add(int(numChannels))

	streams := make([]quic.Stream, numChannels)
	buffers := make([][]byte, numChannels)

	for i := uint(0); i < numChannels; i++ {
		go func(index uint) {
			stream, err := session.AcceptStream(context.Background())
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to accept stream for channel %d: %s\n", index, err)
				wg.Done()
				return
			}
			streams[index] = stream
			buffers[index] = make([]byte, *bufferSize)
			wg.Done()
		}(i)
	}

	wg.Wait()

	for {
		for i, stream := range streams {
			buffer := buffers[i]
			n, err := stream.Read(buffer)
			if err != nil {
				if err != io.EOF {
					fmt.Fprintf(os.Stderr, "Connection with %s failed: %s\n", session.RemoteAddr(), err)
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
}

func startClient(addr string, debug bool, tlsConfig *tls.Config) {
	session, err := quic.DialAddr(addr, tlsConfig, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to connect:", err)
		return
	}
	defer session.CloseWithError(0, "")

	streams := make([]quic.Stream, *numChannels)
	buffers := make([][]byte, *numChannels)

	for i := uint(0); i < *numChannels; i++ {
		stream, err := session.OpenStreamSync(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open stream for channel %d: %s\n", i, err)
			return
		}
		streams[i] = stream
		buffers[i] = make([]byte, *bufferSize)
	}

	reader := bufio.NewReader(os.Stdin)

	go func() {
		buffer := make([]byte, *bufferSize)
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

			for i, stream := range streams {
				_, err = stream.Write(buffer[:n])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to send data on channel %d: %s, retrying...\n", i, err)
				}
			}
		}
	}()

	// Keep the main goroutine running until the child goroutine finishes.
	select {}
}
