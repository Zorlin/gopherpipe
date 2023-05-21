package main

import (
	"bufio"
	"container/heap"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"

	quic "github.com/lucas-clemente/quic-go"
)

var (
	serverMode  = flag.Bool("server", false, "run in server mode")
	debug       = flag.Bool("debug", false, "enable debug mode")
	port        = flag.String("port", "51115", "port number to use")
	address     = flag.String("addr", "", "address for client mode")
	certFile    = flag.String("cert", "", "certificate file")
	keyFile     = flag.String("key", "", "private key file")
	chanNum     = flag.Int("channels", 8, "number of parallel channels")
	bufferSize  = flag.Int("bufferSize", 134217728, "buffer size in bytes")
)

type channelData struct {
	data  []byte
	order int64
	index int
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
	item.index = len(*pq)
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
			return nil // Always return nil to skip certificate validation
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
		startServer(*port, *debug, tlsConfig, *chanNum, *bufferSize)
	} else {
		startClient(*address, *debug, tlsConfig, *chanNum, *bufferSize)
	}
}

func startServer(port string, debug bool, tlsConfig *tls.Config, chanNum, bufferSize int) {
	listener, err := quic.ListenAddr(":"+port, tlsConfig, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to start server:", err)
		return
	}
	fmt.Fprintf(os.Stderr, "Now listening for QUIC connections on 0.0.0.0:%s\n", port)

	for {
		session, err := listener.Accept(context.Background())
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				fmt.Fprintf(os.Stderr, "Temporary accept error: %s\n", err)
				continue
			} else if err == io.EOF {
				fmt.Fprintln(os.Stderr, "Accept loop ended")
				break
			}
			fmt.Fprintf(os.Stderr, "Failed to accept connection: %s\n", err)
			continue
		}
		fmt.Fprintf(os.Stderr, "Accepted connection from %s\n", session.RemoteAddr())

		go handleConnection(session, debug, chanNum, bufferSize)
	}
}

func handleConnection(session quic.Session, debug bool, chanNum, bufferSize int) {
	defer session.CloseWithError(0, "")

	var wg sync.WaitGroup
	chData := make(chan channelData, chanNum)

	for i := 0; i < chanNum; i++ {
		wg.Add(1)
		go handleStream(i, session, debug, &wg, chData, bufferSize)
	}

	go handleWrite(chData)

	wg.Wait()
	close(chData)
}

func handleStream(id int, session quic.Session, debug bool, wg *sync.WaitGroup, chData chan<- channelData, bufferSize int) {
	defer wg.Done()

	for {
		stream, err := session.AcceptStream(context.Background())
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				fmt.Fprintf(os.Stderr, "Temporary stream accept error for ID %d: %s\n", id, err)
				continue
			} else if err == io.EOF {
				fmt.Fprintf(os.Stderr, "Stream accept loop ended for ID %d\n", id)
				break
			}
			fmt.Fprintf(os.Stderr, "Failed to accept stream for ID %d: %s\n", id, err)
			break
		}

		handleStreamRead(id, stream, debug, chData, bufferSize)
	}
}

func handleStreamRead(id int, stream quic.Stream, debug bool, chData chan<- channelData, bufferSize int) {
	buffer := make([]byte, bufferSize+8) // Create the buffer with the specified bufferSize

	for {
		n, err := stream.Read(buffer)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "Stream read error for ID %d: %s\n", id, err)
			}
			break
		}

		if debug {
			fmt.Fprintf(os.Stderr, "Received data from ID %d: %s\n", id, string(buffer[8:n])) // Print the actual data, excluding the order value
		}

		order := binary.BigEndian.Uint64(buffer[:8]) // Extract the order value from the buffer

		chData <- channelData{
			data:  buffer[8:n],
			order: int64(order),
		}
	}

	stream.Close()
}

func handleWrite(chData <-chan channelData) {
	priorityQueue := make(PriorityQueue, 0)
	heap.Init(&priorityQueue)
	var lastOrder int64 = -1

	for data := range chData {
		item := &data
		heap.Push(&priorityQueue, item)
		for priorityQueue.Len() > 0 && priorityQueue[0].order == lastOrder+1 {
			lastOrder++
			item := heap.Pop(&priorityQueue).(*channelData)
			_, err := os.Stdout.Write(item.data)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write data to stream: %s\n", err)
			}
		}
	}
}

func readFull(reader io.Reader, buffer []byte) (int, error) {
	var total int
	for total < len(buffer) {
		n, err := reader.Read(buffer[total:])
		if n == 0 || err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

func startClient(addr string, debug bool, tlsConfig *tls.Config, chanNum, bufferSize int) {
	session, err := quic.DialAddr(addr, tlsConfig, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to connect:", err)
		return
	}
	defer session.CloseWithError(0, "")

	streams := make([]quic.Stream, chanNum)
	for i := 0; i < chanNum; i++ {
		stream, err := session.OpenStreamSync(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr, "Failed to open stream:", err)
			return
		}
		streams[i] = stream
	}

	reader := bufio.NewReader(os.Stdin)
	buffer := make([]byte, bufferSize-8) // Leave room for the order value

	var order int64 = 0
	for {
		n, err := readFull(reader, buffer)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintln(os.Stderr, "Failed to read from stdin:", err)
			}
			return
		}

		orderBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(orderBytes, uint64(order))
		data := append(orderBytes, buffer[:n]...)

		stream := streams[order%int64(chanNum)]

		if debug {
			fmt.Fprintf(os.Stderr, "Read data: %s\n", string(data[8:]))
		}

		_, err = stream.Write(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to send data: %s, retrying...\n", err)
		}

		order++
	}
}