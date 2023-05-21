package main

import (
	"bufio"
	"container/heap"
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
	bufferSize = 134217728 // 128 MB
	chanNum    = 8         // Number of channels
)

var (
	serverMode = flag.Bool("server", false, "run in server mode")
	debug      = flag.Bool("debug", false, "enable debug mode")
	port       = flag.String("port", "51115", "port number to use")
	address    = flag.String("addr", "", "address for client mode")
	certFile   = flag.String("cert", "", "certificate file")
	keyFile    = flag.String("key", "", "private key file")
)

type channelData struct {
	data   []byte
	order  int64
}

type PriorityQueue []*channelData

func (pq PriorityQueue) Len() int { return len(pq) }

func (pq PriorityQueue) Less(i, j int) bool {
	return pq[i].order < pq[j].order
}

func (pq PriorityQueue) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
}

func (pq *PriorityQueue) Push(x interface{}) {
	item := x.(*channelData)
	*pq = append(*pq, item)
}

func (pq *PriorityQueue) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	*pq = old[0 : n-1]
	return item
}

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

		go handleConnection(session, debug)
	}
}

func handleConnection(session quic.Session, debug bool) {
	defer session.CloseWithError(0, "")

	var wg sync.WaitGroup
	chData := make(chan channelData, chanNum)

	for i := 0; i < chanNum; i++ {
		wg.Add(1)
		go handleStream(i, session, debug, &wg, chData)
	}

	go handleWrite(chData)

	wg.Wait()
	close(chData)
}

func handleStream(id int, session quic.Session, debug bool, wg *sync.WaitGroup, chData chan<- channelData) {
	defer wg.Done()

	stream, err := session.AcceptStream(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to accept stream:", err)
		return
	}

	buffer := make([]byte, bufferSize)
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

		chData <- channelData{
			data:  buffer[:n],
			order: int64(id),
		}
	}
}

func handleWrite(chData <-chan channelData) {
	defer wg.Done()

	priorityQueue := make(PriorityQueue, 0, bufferSize)
	heap.Init(&priorityQueue)

	for chData := range chData {
		heap.Push(&priorityQueue, chData)
		for priorityQueue.Len() > 0 && priorityQueue[0].order == lastOrder+1 {
			lastOrder++
			item := heap.Pop(&priorityQueue).(channelData)
			_, err := os.Stdout.Write(item.data)
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

	wg := &sync.WaitGroup{}
	chData := make(chan channelData, chanNum)

	go func() {
		defer close(chData)
		reader := bufio.NewReader(os.Stdin)
		buffer := make([]byte, bufferSize)
		var order int64 = 0
		for {
			n, err := reader.Read(buffer)
			if err != nil {
				if err != io.EOF {
					fmt.Fprintln(os.Stderr, "Failed to read from stdin:", err)
				}
				return
			}

			chData <- channelData{
				data:  buffer[:n],
				order: order,
			}
			order++
		}
	}()

	for i := 0; i < chanNum; i++ {
		wg.Add(1)
		go handleClientConnection(i, session, debug, wg, chData)
	}

	wg.Wait()
}

func handleClientConnection(id int, session quic.Session, debug bool, wg *sync.WaitGroup, chData <-chan channelData) {
	defer wg.Done()

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to open stream:", err)
		return
	}

	for chData := range chData {
		if chData.order%chanNum == int64(id) {
			if debug {
				fmt.Fprintf(os.Stderr, "Read data: %s\n", string(chData.data))
			}

			_, err = stream.Write(chData.data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to send data: %s, retrying...\n", err)
			}
		}
	}
}
