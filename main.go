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
	DefaultBufferSize = 4096 // 4 KB
)

var (
	serverMode  = flag.Bool("server", false, "run in server mode")
	debug       = flag.Bool("debug", false, "enable debug mode")
	port        = flag.String("port", "51115", "port number to use")
	address     = flag.String("addr", "", "address for client mode")
	certFile    = flag.String("cert", "", "certificate file")
	keyFile     = flag.String("key", "", "private key file")
	bufferSize  = flag.Int("bufferSize", 4096, "buffer size for data transfer")
	channels    *int
)

func main() {
	flag.Parse()

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
		channels = flag.Int("channels", 1, "number of channels to use")
		flag.Parse()
		startClient(*address, *debug, tlsConfig, *channels)
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

		go handleConnection(session, debug)
	}
}

func handleConnection(session quic.Session, debug bool) {
	defer session.CloseWithError(0, "")

	for {
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to accept stream:", err)
			return
		}

		go func(stream quic.Stream) {
			buffer := make([]byte, *bufferSize)
			for {
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
					fmt.Fprintf(os.Stderr, "Failed to write data to stream: %s\n", err)
				}
			}
		}(stream)
	}
}

func startClient(addr string, debug bool, tlsConfig *tls.Config, channelNums int) {
	session, err := quic.DialAddr(addr, tlsConfig, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to connect:", err)
		return
	}
	defer session.CloseWithError(0, "")

	var wg sync.WaitGroup

	for i := 0; i < channelNums; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			stream, err := session.OpenStreamSync(context.Background())
			if err != nil {
				fmt.Fprintln(os.Stderr, "Failed to open stream:", err)
				return
			}

			reader := bufio.NewReader(os.Stdin)
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

				_, err = stream.Write(buffer[:n])
				if err != nil {
					fmt.Fprintf(os.Stderr, "Failed to send data: %s\n", err)
				}
			}
		}()
	}

	wg.Wait()
}
