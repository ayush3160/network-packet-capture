package replay

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

/* -------------------------- NEW TYPES / HELPERS -------------------------- */

type direction int

const (
	dirToProxy   direction = iota // App -> Proxy  (DstPort == proxyPort)
	dirFromProxy                  // Proxy -> App  (SrcPort == proxyPort)
)

type flowKeyDup struct {
	srcIP   string
	dstIP   string
	srcPort uint16
	dstPt   uint16
	payload []byte
	ts      time.Time
	dir     direction
}

// responseFeeder feeds proxy→app payloads to the :16790 server in order.
type responseFeeder struct {
	mu    sync.Mutex
	queue [][]byte
	cond  *sync.Cond
	// when closed, server should stop
	done chan struct{}
}

type streamSeq struct {
	port    uint16
	events  []flowKeyDup
	firstTS time.Time
}

var streams []streamSeq

func newResponseFeeder() *responseFeeder {
	r := &responseFeeder{done: make(chan struct{})}
	r.cond = sync.NewCond(&r.mu)
	return r
}

func (r *responseFeeder) push(p []byte) {
	r.mu.Lock()
	r.queue = append(r.queue, append([]byte(nil), p...))
	r.mu.Unlock()
	r.cond.Broadcast()
}

func (r *responseFeeder) pop(ctxDone <-chan struct{}) ([]byte, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for {
		if len(r.queue) > 0 {
			p := r.queue[0]
			r.queue = r.queue[1:]
			return p, true
		}
		// If either the server or the stream is shutting down, exit.
		select {
		case <-ctxDone:
			return nil, false
		case <-r.done:
			return nil, false
		default:
		}
		r.cond.Wait() // will be woken by push() or close()
	}
}

func (r *responseFeeder) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	select {
	case <-r.done:
		// already closed
	default:
		close(r.done)
	}
	// Wake up any goroutines blocked in cond.Wait()
	r.cond.Broadcast()
}

/*
startAppSideServer starts a TCP server on :16790.
Protocol:
  - For each incoming connection, it will read a request (any bytes) from the client.
  - After a read (or even a zero-length read if client just connects and writes later),
    it pops the next "fromProxy" payload and writes it back as the response.
  - It keeps doing this (read -> respond) in sequence until the feeder is closed.
*/
func startAppSideServer(listenAddr string, feeder *responseFeeder) (stop func(), err error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", listenAddr, err)
	}
	log.Printf("[SERVER] listening on %s", listenAddr)

	var wg sync.WaitGroup
	shutdown := make(chan struct{})

	serveConn := func(c net.Conn) {
		defer c.Close()
		br := bufio.NewReader(c)
		for {
			// Block until client sends a request
			// We read whatever they send, up to a delimiter or short timeout.
			// For simplicity, read what's available (non-framing).
			c.SetReadDeadline(time.Now().Add(5 * time.Minute))
			_, err := br.Peek(1)
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					continue
				}
				if errors.Is(err, io.EOF) {
					return
				}
				// other error -> close conn
				return
			}
			// Drain available bytes (request). We don't need them; we just need the event.
			c.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
			buf := make([]byte, 4096)
			totalRead := 0
			for {
				n, er := br.Read(buf)
				if n > 0 {
					totalRead += n // accumulate bytes read
				}
				if er != nil {
					if ne, ok := er.(net.Error); ok && ne.Timeout() {
						break
					}
					if errors.Is(er, io.EOF) {
						break
					}
					break
				}
				if n < len(buf) {
					break
				}
			}
			log.Printf("[SERVER] received request of length %d bytes", totalRead)

			// Pop next response and write it
			select {
			case <-shutdown:
				return
			case <-feeder.done:
				return
			default:
			}
			resp, ok := feeder.pop(shutdown)
			if !ok {
				return
			}
			c.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := c.Write(resp); err != nil {
				log.Printf("[SERVER] write error: %v", err)
				return
			}
			log.Printf("[SERVER] proxy→app wrote response of length %d bytes", len(resp))
		}
	}

	acceptLoop := func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				select {
				case <-shutdown:
					return
				default:
				}
				log.Printf("[SERVER] accept error: %v", err)
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				serveConn(conn)
			}()
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptLoop()
	}()

	stop = func() {
		close(shutdown)
		err = ln.Close()
		if err != nil {
			log.Printf("[SERVER] close error: %v", err)
		}
		// Wake any handlers waiting in pop()
		feeder.close()
		log.Printf("[SERVER] stopped")
	}
	return stop, nil
}

/*
replaySequence sequentially executes:
- If event.dir == dirToProxy: write payload to the live proxyConn
- If event.dir == dirFromProxy: enqueue payload so the :16790 server returns it on next client request
Optionally respects preserveTiming and writeDelay using the original timestamps.
*/
func replaySequence(
	events []flowKeyDup,
	proxyAddr string,
	preserveTiming bool,
	writeDelay time.Duration,
) error {
	// Start server on :16790
	feeder := newResponseFeeder()
	stopServer, err := startAppSideServer(":16790", feeder)
	if err != nil {
		return err
	}
	defer func() { fmt.Printf("Stopping the server"); stopServer() }()

	// Connect to proxy
	if proxyAddr == "" {
		proxyAddr = "127.0.0.1:16789"
	}
	proxyConn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}
	defer proxyConn.Close()
	log.Printf("[REPLAY] connected to proxy at %s", proxyAddr)

	// For graceful half-close later
	var tcpC *net.TCPConn
	if tc, ok := proxyConn.(*net.TCPConn); ok {
		tcpC = tc
	}

	// Sort by original time to preserve order
	sort.Slice(events, func(i, j int) bool { return events[i].ts.Before(events[j].ts) })

	var prev time.Time
	// lastToProxyIdx := -1
	for i, ev := range events {
		// Timing controls
		if preserveTiming {
			if !prev.IsZero() {
				if d := ev.ts.Sub(prev); d > 0 {
					time.Sleep(d)
				}
			}
			prev = ev.ts
		}
		if writeDelay > 0 {
			time.Sleep(writeDelay)
		}

		switch ev.dir {
		case dirToProxy:
			_, err := proxyConn.Write(ev.payload)
			if err != nil {
				return fmt.Errorf("write to proxy (event %d): %w", i+1, err)
			}
			// lastToProxyIdx = i
			log.Printf("[REPLAY %03d] →proxy wrote %d bytes", i+1, len(ev.payload))

		case dirFromProxy:
			// Enqueue for :16790 server so proxy can fetch it,
			// but ALSO read the same number of bytes back from proxyConn,
			// otherwise we might close early and the proxy gets RST.
			feeder.push(ev.payload)
			log.Printf("[REPLAY %03d] proxy→app queued %d bytes (server will respond on next request)", i+1, len(ev.payload))

			// Read/discard exactly len(ev.payload) from proxyConn
			// (proxy forwards server’s response back to this client).
			need := len(ev.payload)
			buf := make([]byte, 32<<10) // 32KB scratch
			deadline := time.Now().Add(30 * time.Second)
			_ = proxyConn.SetReadDeadline(deadline)
			readTotal := 0
			for readTotal < need {
				n, rerr := proxyConn.Read(buf)
				if n > 0 {
					readTotal += n
				}
				if rerr != nil {
					return fmt.Errorf("read from proxy (expect %d, got %d): %w", need, readTotal, rerr)
				}
			}
			// Clear read deadline for subsequent events
			_ = proxyConn.SetReadDeadline(time.Time{})
			log.Printf("[CLIENT] drained %d/%d bytes from proxy", readTotal, need)
		}
	}

	// Tell proxy we’re done sending, but keep reading until it closes (if it wants).
	if tcpC != nil {
		_ = tcpC.CloseWrite()
	}

	log.Printf("[REPLAY] sequence finished")
	return nil
}

/* ------------------------------ MAIN LOGIC ------------------------------- */

func StartReplay2() {
	var (
		pcapPath       string
		proxyAddr      string
		mongoAddr      string
		proxyPort      int
		mongoPort      int
		preserveTiming bool
		connectTimeout time.Duration
		writeDelay     time.Duration
		concurrency    int
	)

	flag.StringVar(&pcapPath, "pcap", "", "Path to pcap file (Ethernet or Linux SLL)")
	flag.StringVar(&proxyAddr, "proxyAddr", "", "Where to send App→Proxy L7 bytes (e.g., 127.0.0.1:16789). Empty to use default 127.0.0.1:16789.")
	flag.IntVar(&proxyPort, "proxyPort", 16789, "Destination port in pcap considered 'proxy' (0 to disable)")
	flag.StringVar(&mongoAddr, "mongoAddr", "", "Where to send Proxy→Mongo L7 bytes (unused here)")
	flag.IntVar(&mongoPort, "mongoPort", 27017, "Destination port in pcap considered 'mongo' (unused here)")
	flag.BoolVar(&preserveTiming, "preserveTiming", false, "Sleep according to inter-packet gaps per stream")
	flag.DurationVar(&connectTimeout, "connectTimeout", 5*time.Second, "Dial timeout for live sockets")
	flag.DurationVar(&writeDelay, "writeDelay", 0, "Fixed delay between packet writes (added after preserveTiming)")
	flag.IntVar(&concurrency, "concurrency", 1, "Max parallel stream replays per direction")
	flag.Parse()

	_ = mongoAddr
	_ = mongoPort
	_ = connectTimeout
	_ = concurrency

	if pcapPath == "" {
		log.Fatal("missing -pcap")
	}
	if proxyPort == 0 {
		log.Fatal("proxyPort is 0; nothing to replay")
	}

	// Open PCAP
	f, err := os.Open(pcapPath)
	if err != nil {
		log.Fatalf("open pcap: %v", err)
	}
	defer f.Close()

	r, err := pcapgo.NewReader(f)
	if err != nil {
		log.Fatalf("pcap reader: %v", err)
	}
	link := r.LinkType()
	log.Printf("PCAP link type: %s", link)

	// srcPorts will contain exactly ONE stream in your case, ordered later by ts.
	srcPorts := make(map[uint16][]flowKeyDup)

	packetCount := 0
	for {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			if errors.Is(err, os.ErrClosed) || err == io.EOF || strings.Contains(strings.ToLower(err.Error()), "eof") {
				break
			}
			log.Printf("[DEBUG] read err: %v", err)
			break
		}
		packetCount++

		// Linux SLL2 is common in containers; adjust if your pcap is Ethernet etc.
		pkt := gopacket.NewPacket(data, layers.LayerTypeLinuxSLL2, gopacket.NoCopy)
		tl := pkt.TransportLayer()
		if tl == nil {
			continue
		}
		ip := pkt.NetworkLayer()
		if ip == nil {
			continue
		}

		tcp, ok := tl.(*layers.TCP)
		if !ok {
			continue
		}

		// Filter to only the proxy side of the world
		if !(uint16(tcp.SrcPort) == uint16(proxyPort) || uint16(tcp.DstPort) == uint16(proxyPort)) {
			continue
		}
		if len(tcp.Payload) == 0 {
			continue
		}

		srcIP := ip.NetworkFlow().Src().String()
		dstIP := ip.NetworkFlow().Dst().String()

		ev := flowKeyDup{
			srcIP:   srcIP,
			dstIP:   dstIP,
			srcPort: uint16(tcp.SrcPort),
			dstPt:   uint16(tcp.DstPort),
			payload: append([]byte(nil), tcp.Payload...), // copy
			ts:      ci.Timestamp,
		}
		if int(tcp.DstPort) == proxyPort {
			ev.dir = dirToProxy
		} else if int(tcp.SrcPort) == proxyPort {
			ev.dir = dirFromProxy
		} else {
			continue
		}

		// Store under the *non-proxy* port to group a stream (as you were doing)
		if ev.srcPort != uint16(proxyPort) {
			srcPorts[ev.srcPort] = append(srcPorts[ev.srcPort], ev)
		} else {
			// For responses, also index by the peer's port so they end up in the same slice
			srcPorts[ev.dstPt] = append(srcPorts[ev.dstPt], ev)
		}

		log.Printf("[DEBUG] add ev ts=%s dir=%v len=%d src=%s:%d dst=%s:%d",
			ev.ts.Format(time.RFC3339Nano), ev.dir, len(ev.payload),
			ev.srcIP, ev.srcPort, ev.dstIP, ev.dstPt)
	}

	// For simplicity, pick the first stream (you mentioned there's one)
	if len(srcPorts) == 0 {
		log.Fatalf("no proxy-related payloads found in pcap")
	}

	for port, seq := range srcPorts {
		if len(seq) == 0 {
			continue
		}
		// Sort each stream strictly by original packet time
		sort.Slice(seq, func(i, j int) bool { return seq[i].ts.Before(seq[j].ts) })

		first := seq[0].ts
		streams = append(streams, streamSeq{
			port:    port,
			events:  seq,
			firstTS: first,
		})
	}
	// Sort strictly by original packet time
	sort.Slice(streams, func(i, j int) bool { return streams[i].firstTS.Before(streams[j].firstTS) })

	log.Printf("Discovered %d stream(s). Replaying sequentially.", len(streams))

	for sidx, st := range streams {
		log.Printf("---- Stream %d (peer port %d) ----", sidx+1, st.port)
		log.Printf("Sequence length: %d", len(st.events))
		for i, ev := range st.events {
			dirStr := "→proxy"
			if ev.dir == dirFromProxy {
				dirStr = "proxy→app"
			}
			log.Printf("  [%03d] %s t=%s bytes=%d", i+1, dirStr, ev.ts.Format(time.RFC3339Nano), len(ev.payload))
		}

		// REPLAY this stream (sequential as captured)
		if err := replaySequence(st.events, proxyAddr, preserveTiming, writeDelay); err != nil {
			log.Fatalf("replay failed for stream %d (port %d): %v", sidx+1, st.port, err)
		}

		// Optional: tiny gap between streams so the proxy/app can settle
		time.Sleep(100 * time.Millisecond)
	}

	log.Printf("Done.")
}
