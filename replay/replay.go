// l7replay.go
// Replays L7 (application) payloads from a PCAP to live endpoints.
// - Flows with dst port == proxyPort -> write to proxyAddr (new TCP connection)
// - Flows with dst port == mongoPort -> write to mongoAddr (new TCP connection)
//
// Usage examples:
//
//	go run l7replay.go -pcap capture.pcap -proxyAddr 127.0.0.1:16789 -proxyPort 16789 -mongoAddr 172.18.0.2:27017 -mongoPort 27017 -preserveTiming
//
//	# Only replay App->Proxy
//	go run l7replay.go -pcap capture.pcap -proxyAddr 127.0.0.1:16789 -proxyPort 16789 -mongoPort 0
//
//	# Only replay Proxy->Mongo
//	go run l7replay.go -pcap capture.pcap -mongoAddr 172.18.0.2:27017 -mongoPort 27017 -proxyPort 0
package replay

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
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

type pkt struct {
	ts   time.Time
	data []byte // tcp payload only
}

type flowKey struct {
	srcIP, dstIP   string
	srcPort, dstPt uint16
}

type flowKeyDup2 struct {
	srcIP, dstIP   string
	srcPort, dstPt uint16
	payload        []byte // TCP payload only; used for matching
}

type stream struct {
	key   flowKey
	pkts  []pkt     // in capture order (see NOTE about tcpassembly)
	total int       // total bytes in pkts
	first time.Time // first ts
	last  time.Time // last ts
}

// simple collector keyed by exact 5-tuple
type flows struct {
	mu    sync.Mutex
	items map[flowKey]*stream
}

func newFlows() *flows {
	return &flows{items: make(map[flowKey]*stream)}
}
func (f *flows) add(k flowKey, ts time.Time, payload []byte) {
	if len(payload) == 0 {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.items[k]
	if s == nil {
		s = &stream{key: k, first: ts}
		f.items[k] = s
	}
	s.pkts = append(s.pkts, pkt{ts: ts, data: append([]byte(nil), payload...)})
	s.total += len(payload)
	s.last = ts
}

func StartReplay() {
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
	flag.StringVar(&proxyAddr, "proxyAddr", "", "Where to send App→Proxy L7 bytes (e.g., 127.0.0.1:16789). Empty to skip.")
	flag.IntVar(&proxyPort, "proxyPort", 16789, "Destination port in pcap considered 'proxy' (0 to disable)")
	flag.StringVar(&mongoAddr, "mongoAddr", "", "Where to send Proxy→Mongo L7 bytes (e.g., 172.18.0.2:27017). Empty to skip.")
	flag.IntVar(&mongoPort, "mongoPort", 27017, "Destination port in pcap considered 'mongo' (0 to disable)")
	flag.BoolVar(&preserveTiming, "preserveTiming", false, "Sleep according to inter-packet gaps per stream")
	flag.DurationVar(&connectTimeout, "connectTimeout", 5*time.Second, "Dial timeout for live sockets")
	flag.DurationVar(&writeDelay, "writeDelay", 0, "Fixed delay between packet writes (added after preserveTiming)")
	flag.IntVar(&concurrency, "concurrency", 1, "Max parallel stream replays per direction")
	flag.Parse()

	if pcapPath == "" {
		log.Fatal("missing -pcap")
	}
	if proxyPort == 0 && mongoPort == 0 {
		log.Fatal("both -proxyPort and -mongoPort are 0; nothing to replay")
	}

	// Open PCAP
	f, err := os.Open(pcapPath)
	if err != nil {
		log.Fatalf("open pcap: %v", err)
	}
	defer f.Close()

	// pcapgo will detect link type from header
	r, err := pcapgo.NewReader(f)
	if err != nil {
		log.Fatalf("pcap reader: %v", err)
	}
	link := r.LinkType()
	log.Printf("PCAP link type: %s", link)
	// dc := newDecCtx(link)

	// Decode loop: collect payloads for the 2 directions of interest
	col := newFlows()

	srcPorts := make(map[uint16][]flowKeyDup) // src ports seen in the capture

	packetCount := 0
	for {
		data, ci, err := r.ReadPacketData()
		if err != nil {
			log.Printf("[DEBUG] Error reading packet data: %v", err)
			if errors.Is(err, os.ErrClosed) {
				break
			}
			if err.Error() == "EOF" {
				break
			}
			if strings.Contains(err.Error(), "EOF") {
				break
			}
			// non-fatal: stop on EOF
			break
		}
		packetCount++
		// log.Printf("[DEBUG] Packet #%d read at %v, length=%d", packetCount, ci.Timestamp, len(data))

		// Decode the layers (IPv4, TCP, etc.)
		pkt := gopacket.NewPacket(data, layers.LayerTypeLinuxSLL2, gopacket.NoCopy)
		tl := pkt.TransportLayer()

		if tl == nil {
			continue // Ignore non-transport layer packets
		}

		switch t := tl.(type) {
		case *layers.TCP:
			if !(uint16(t.SrcPort) == uint16(proxyPort) || uint16(t.DstPort) == uint16(proxyPort)) {
				continue // Filter by the port
			}
			// Extract the payload
			payload := t.Payload
			if len(payload) == 0 {
				// log.Printf("[DEBUG] No TCP payload in packet #%d, skipping", packetCount)
				continue
			}

			// Collect payload for replay
			srcIP, dstIP := pkt.NetworkLayer().NetworkFlow().Src().String(), pkt.NetworkLayer().NetworkFlow().Dst().String()
			dstPort := uint16(t.DstPort)
			k := flowKeyDup{srcIP: srcIP, dstIP: dstIP, srcPort: uint16(t.SrcPort), dstPt: dstPort, payload: payload}

			if t.SrcPort != 16789 {
				if srcPorts[uint16(t.SrcPort)] == nil {
					srcPorts[uint16(t.SrcPort)] = []flowKeyDup{k}
				} else {
					srcPorts[uint16(t.SrcPort)] = append(srcPorts[uint16(t.SrcPort)], k)
				}
			}

			if t.DstPort != 16789 {
				if srcPorts[uint16(t.DstPort)] == nil {
					srcPorts[uint16(t.DstPort)] = []flowKeyDup{k}
				} else {
					srcPorts[uint16(t.DstPort)] = append(srcPorts[uint16(t.DstPort)], k)
				}
			}

			// col.add(k, ci.Timestamp, payload)

			log.Printf("[DEBUG] Added payload for flowKey=%+v, ts=%v, payloadLen=%d", k, ci.Timestamp, len(payload))

		default:
			continue // Only process TCP/UDP packets
		}
	}

	// Partition streams by destination port
	var toProxy, fromProxy []*stream
	for _, s := range col.items {
		log.Printf("[DEBUG] Partitioning stream: flowKey=%+v, totalBytes=%d", s.key, s.total)
		if int(s.key.dstPt) == proxyPort && proxyPort > 0 {
			toProxy = append(toProxy, s)
			log.Printf("[DEBUG] Stream toProxy: flowKey=%+v", s.key)
		}
		if int(s.key.srcPort) == proxyPort && proxyPort > 0 {
			fromProxy = append(fromProxy, s)
			log.Printf("[DEBUG] Stream fromProxy: flowKey=%+v", s.key)
		}
	}

	// Sort each set by first timestamp (nice to have)
	sort.Slice(toProxy, func(i, j int) bool { return toProxy[i].first.Before(toProxy[j].first) })
	sort.Slice(fromProxy, func(i, j int) bool { return fromProxy[i].first.Before(fromProxy[j].first) })

	log.Printf("Collected streams: toProxy=%d fromProxy=%d", len(toProxy), len(fromProxy))

	streamNumber := 1

	for _, flowKeys := range srcPorts {
		fmt.Printf("Stream #%d:\n", streamNumber)
		for i, fk := range flowKeys {
			fmt.Printf("  FlowKey #%d: srcIP=%s, dstIP=%s, srcPort=%d, dstPt=%d, payloadLen=%d\n",
				i+1, fk.srcIP, fk.dstIP, fk.srcPort, fk.dstPt, len(fk.payload))
			if len(fk.payload) > 0 {
				fmt.Printf("    Payload (first 32 bytes): %x\n", fk.payload[:32])
			}
		}
		streamNumber++
	}

	// ctx := context.Background()

	// // additionally serve the fromProxy responses to any incoming TCP client:
	// if len(fromProxy) > 0 {
	// 	log.Printf("Starting serveFromProxy on :16790 with %d streams", len(fromProxy))
	// 	go func() {
	// 		if err := serveFromProxy(ctx, ":16790", fromProxy, preserveTiming); err != nil {
	// 			log.Fatalf("serveFromProxy: %v", err)
	// 		}
	// 	}()
	// }

	// time.Sleep(5 * time.Second) // Give the server some time to start

	// // Replay helpers
	// replaySet := func(label, addr string, set []*stream) {
	// 	if addr == "" || len(set) == 0 {
	// 		return
	// 	}
	// 	log.Printf("Replaying %d streams %s to %s", len(set), label, addr)
	// 	sem := make(chan struct{}, max(1, concurrency))
	// 	var wg sync.WaitGroup
	// 	for _, s := range set {
	// 		sem <- struct{}{}
	// 		wg.Add(1)
	// 		go func(s *stream) {
	// 			defer wg.Done()
	// 			defer func() { <-sem }()
	// 			fmt.Printf("Replaying %s %v -> %s\n", label, s.key, addr)
	// 			if err := replayStream(ctx, addr, s, preserveTiming, connectTimeout, writeDelay); err != nil {
	// 				log.Printf("replay %s %v -> %s: %v", label, s.key, addr, err)
	// 			}
	// 		}(s)
	// 	}
	// 	wg.Wait()
	// }

	// // Run
	// replaySet("App→Proxy", proxyAddr, toProxy)
	// replaySet("Proxy→Mongo", mongoAddr, fromProxy)
	log.Printf("Done.")
}

func replayStream(ctx context.Context, addr string, s *stream, preserve bool, dialTO, writeDelay time.Duration) error {
	d := net.Dialer{Timeout: dialTO}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	defer conn.Close()

	bw := bufio.NewWriter(conn)
	start := time.Now()
	var base time.Time
	if preserve && len(s.pkts) > 0 {
		base = s.pkts[0].ts
	}
	fmt.Printf("→ %s | %s:%d → %s:%d | %d chunks, %d bytes\n",
		addr, s.key.srcIP, s.key.srcPort, s.key.dstIP, s.key.dstPt, len(s.pkts), s.total)

	for i, p := range s.pkts {
		if preserve {
			// sleep to match inter-packet gaps relative to first packet
			want := p.ts.Sub(base)
			have := time.Since(start)
			if want > have {
				time.Sleep(want - have)
			}
		}
		if writeDelay > 0 && i > 0 {
			time.Sleep(writeDelay)
		}
		if _, err := bw.Write(p.data); err != nil {
			return fmt.Errorf("write chunk %d/%d: %w", i+1, len(s.pkts), err)
		}
		if err := bw.Flush(); err != nil {
			return fmt.Errorf("flush chunk %d/%d: %w", i+1, len(s.pkts), err)
		}
	}

	// Wait for a reply from the server.
	// Set a read deadline to avoid waiting indefinitely.
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		log.Printf("Failed to set read deadline for stream %v: %v", s.key, err)
	}

	// Read the response from the server.
	br := bufio.NewReader(conn)
	response, err := br.ReadString('\n')
	if err != nil {
		if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
			log.Printf("Timeout waiting for reply for stream %v", s.key)
			return nil
		}
		if err.Error() == "EOF" {
			log.Printf("Connection closed by server for stream %v (EOF)", s.key)
			return nil
		}
		return fmt.Errorf("reading reply for stream %v: %w", s.key, err)
	}
	log.Printf("← %s | Received reply for stream %v: %s", addr, s.key, strings.TrimSpace(response))

	return nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// buildParser returns a decoding parser and the set of reusable layer structs
// matching the PCAP's link type.
type decCtx struct {
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType

	eth  layers.Ethernet
	sll  layers.LinuxSLL
	sll2 layers.LinuxSLL2
	null layers.Loopback
	ip4  layers.IPv4
	ip6  layers.IPv6
	tcp  layers.TCP
	udp  layers.UDP

	first gopacket.LayerType
}

func newDecCtx(link layers.LinkType) *decCtx {
	d := &decCtx{decoded: make([]gopacket.LayerType, 0, 10)}

	switch link {
	case layers.LinkTypeEthernet:
		d.first = layers.LayerTypeEthernet
		d.parser = gopacket.NewDecodingLayerParser(d.first,
			&d.eth, &d.ip4, &d.ip6, &d.tcp, &d.udp)

	case layers.LinkTypeLinuxSLL:
		fmt.Println("Using Linux SLL link type")
		d.first = layers.LayerTypeLinuxSLL
		d.parser = gopacket.NewDecodingLayerParser(d.first,
			&d.sll, &d.ip4, &d.ip6, &d.tcp, &d.udp)

	case layers.LinkTypeLinuxSLL2:
		fmt.Println("Using Linux SLL 2 link type")
		// Use the SLL2 layer type explicitly; if your gopacket version
		// doesn’t have LayerTypeLinuxSLL2, fall back to LinuxSLL here.
		d.first = layers.LayerTypeLinuxSLL2
		d.parser = gopacket.NewDecodingLayerParser(d.first,
			&d.sll2, &d.ip4, &d.ip6, &d.tcp, &d.udp)

	case layers.LinkTypeNull:
		d.first = layers.LayerTypeLoopback
		d.parser = gopacket.NewDecodingLayerParser(d.first,
			&d.null, &d.ip4, &d.ip6, &d.tcp, &d.udp)

	case layers.LinkTypeRaw:
		// starts directly at IP; we’ll pick v4/v6 per-packet below
		d.first = layers.LayerTypeIPv4
		d.parser = gopacket.NewDecodingLayerParser(d.first,
			&d.ip4, &d.ip6, &d.tcp, &d.udp)

	default:
		log.Fatalf("unsupported link type: %v", link)
	}
	return d
}

func decodeWithSLL2Fallback(link layers.LinkType, dc *decCtx, data []byte, decoded *[]gopacket.LayerType) bool {
	// 1) normal path
	*decoded = (*decoded)[:0]
	if err := dc.parser.DecodeLayers(data, decoded); err == nil {
		// Already got [Linux SLL2 IPv4 TCP] or similar
		return true
	}

	// 2) fallback: if SLL2 didn’t route to IP, try after SLL2 header
	if link != layers.LinkTypeLinuxSLL2 && link != layers.LinkTypeLinuxSLL {
		return false
	}
	off := 20 // SLL2 header length (v1 SLL is 16)
	if len(data) <= off {
		return false
	}

	// detect IPv4/IPv6 at byte 0 of payload (after SLL2)
	v := data[off] >> 4
	var first gopacket.LayerType
	switch v {
	case 4:
		first = layers.LayerTypeIPv4
	case 6:
		first = layers.LayerTypeIPv6
	default:
		return false
	}

	tmp := gopacket.NewDecodingLayerParser(first, &dc.ip4, &dc.ip6, &dc.tcp, &dc.udp)
	*decoded = (*decoded)[:0]
	return tmp.DecodeLayers(data[off:], decoded) == nil
}

// serveFromProxy starts a TCP server that replies with the next captured
// Proxy→Client chunk every time *any* connected client sends a request.
// Chunks are consumed globally (never per-connection). When the last chunk
// is sent, the listener is closed.
//
// addr            - listen address, e.g. ":16790"
// fromProxy       - the streams you already collected (Proxy→Client)
// preserveTiming  - if true, sleep original inter-chunk gaps before replying
// serveFromProxy starts a TCP server that replies with the next captured
// Proxy→Client stream every time *any* connected client sends a request.
// Streams are consumed globally (one per request). When the last stream
// is sent, the listener is closed.
//
// addr            - listen address, e.g. ":16790"
// fromProxy       - the streams you already collected (Proxy→Client)
// preserveTiming  - if true, sleep original inter-chunk gaps before replying
func serveFromProxy(ctx context.Context, addr string, fromProxy []*stream, preserveTiming bool) error {
	// 1) fromProxy is already a time-ordered sequence of streams.
	log.Printf("[serveFromProxy] collected %d streams", len(fromProxy))
	if len(fromProxy) == 0 {
		return errors.New("serveFromProxy: no streams in fromProxy")
	}

	// 2) Start listener.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	log.Printf("[serveFromProxy] listening on %s; %d reply streams ready", addr, len(fromProxy))

	// Close listener on ctx cancel.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	// 3) Global sequencing state (shared across all conns).
	var (
		mu        sync.Mutex // serialize access to stream index
		streamIdx int        // next stream to send
		exhaust   bool
		exhOnce   sync.Once
		closeLsn  = func() {
			exhOnce.Do(func() {
				exhaust = true
				_ = ln.Close()
			})
		}
	)

	// 4) Accept loop.
	for {
		c, err := ln.Accept()
		if err != nil {
			if exhaust || errors.Is(err, net.ErrClosed) {
				return nil
			}
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("accept: %w", err)
			}
		}

		// 5) Per-connection goroutine: any read triggers "next global reply stream".
		go func(conn net.Conn) {
			defer conn.Close()
			log.Printf("[serveFromProxy] client %s connected", conn.RemoteAddr())
			buf := make([]byte, 64<<10)

			for {
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
				n, rerr := conn.Read(buf)
				if rerr != nil {
					if !errors.Is(rerr, os.ErrDeadlineExceeded) && !strings.Contains(rerr.Error(), "timeout") {
						log.Printf("[serveFromProxy] client %s read error: %v", conn.RemoteAddr(), rerr)
					}
					return
				}
				if n == 0 {
					continue
				}

				log.Printf("[serveFromProxy] client %s sent request payload: %x", conn.RemoteAddr(), buf[:n])

				// Lock to get the next stream to send.
				mu.Lock()
				if streamIdx >= len(fromProxy) {
					mu.Unlock()
					closeLsn()
					log.Printf("[serveFromProxy] client %s: all streams exhausted; closing", conn.RemoteAddr())
					return
				}

				// Get the stream and advance the index.
				s := fromProxy[streamIdx]
				streamIdx++

				// If that was the last stream, prepare to close the listener.
				isLastStream := streamIdx >= len(fromProxy)
				mu.Unlock()

				// Now, write all chunks of the selected stream.
				start := time.Now()
				var base time.Time
				if preserveTiming && len(s.pkts) > 0 {
					base = s.pkts[0].ts
				}

				for i, p := range s.pkts {
					if preserveTiming {
						// sleep to match inter-packet gaps relative to first packet
						want := p.ts.Sub(base)
						have := time.Since(start)
						if want > have {
							time.Sleep(want - have)
						}
					}

					log.Printf("[serveFromProxy] about to write chunk %d/%d of stream %v (%d bytes) to %s",
						i+1, len(s.pkts), s.key, len(p.data), conn.RemoteAddr())

					if _, werr := conn.Write(p.data); werr != nil {
						log.Printf("[serveFromProxy] client %s write error on stream %v chunk %d: %v",
							conn.RemoteAddr(), s.key, i+1, werr)
						return // End this connection's goroutine on write error.
					}
				}
				log.Printf("[serveFromProxy] finished writing all %d chunks of stream %v to %s", len(s.pkts), s.key, conn.RemoteAddr())

				if isLastStream {
					closeLsn()
					log.Printf("[serveFromProxy] all streams sent; listener closing (%d streams)", len(fromProxy))
				}

				// After sending one full stream, we are done with this request.
				// The client must send another request to get the next stream.
				return
			}
		}(c)
	}
}
