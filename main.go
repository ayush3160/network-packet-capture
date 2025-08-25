package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

func main() {
	var (
		iface        string
		outPath      string
		snaplen      int
		portFlag     int
		includeLo    bool
		pollTO       time.Duration
		blockTO      time.Duration
		frameSizePow int
		numBlocks    int
	)

	flag.StringVar(&iface, "i", "", `Interface to capture on (e.g., "eth0"). Use "any" for all UP interfaces.`)
	flag.StringVar(&outPath, "out", "capture.pcap", "Output pcap file path")
	flag.IntVar(&snaplen, "snaplen", 65535, "Snapshot length (max bytes per packet)")
	flag.IntVar(&portFlag, "port", 16789, "TCP/UDP port to match (src or dst)")
	flag.BoolVar(&includeLo, "include-lo", false, `Include loopback ("lo") when using -i any`)
	flag.DurationVar(&pollTO, "poll-timeout", 300*time.Millisecond, "AF_PACKET poll timeout")
	flag.DurationVar(&blockTO, "block-timeout", 200*time.Millisecond, "AF_PACKET block timeout")
	flag.IntVar(&frameSizePow, "frame-pow2", 11, "AF_PACKET frame size as 2^N bytes (e.g., 11 => 2048)")
	flag.IntVar(&numBlocks, "blocks", 64, "AF_PACKET number of blocks")
	flag.Parse()

	// Resolve target interfaces
	targets, err := resolveTargets(iface, includeLo)
	if err != nil {
		log.Fatalf("interfaces: %v", err)
	}
	if len(targets) == 0 {
		log.Fatalf("no interfaces to capture on (use -i <name> or -i any)")
	}
	log.Printf("capturing on: %v", targets)

	// Prepare output file (pure Go PCAP writer; no libpcap)
	f, err := os.Create(outPath)
	if err != nil {
		log.Fatalf("creating output pcap: %v", err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(uint32(snaplen), layers.LinkTypeEthernet); err != nil {
		log.Fatalf("writing pcap header: %v", err)
	}
	log.Printf("✳️ writing packets to %s", outPath)

	// Build TPACKET config
	frameSize := 1 << frameSizePow
	blockSize := 1 << 20 // 1 MiB per block (must be multiple of frameSize)
	if blockSize%frameSize != 0 {
		log.Fatalf("block size (%d) must be multiple of frame size (%d)", blockSize, frameSize)
	}

	var seen uint64

	// Open one TPacket per interface
	type capJob struct {
		name string
		tp   *afpacket.TPacket
	}
	var jobs []capJob
	for _, name := range targets {
		tp, err := afpacket.NewTPacket(
			afpacket.OptInterface(name),
			afpacket.OptFrameSize(frameSize),
			afpacket.OptBlockSize(blockSize),
			afpacket.OptNumBlocks(numBlocks),
			afpacket.OptBlockTimeout(blockTO),
			afpacket.OptPollTimeout(pollTO),
			afpacket.OptAddVLANHeader(false),
			afpacket.SocketRaw, // L2 frames
			afpacket.OptTPacketVersion(afpacket.TPacketVersion3),
		)
		if err != nil {
			log.Printf("skip %s: %v", name, err)
			continue
		}
		jobs = append(jobs, capJob{name: name, tp: tp})
	}
	if len(jobs) == 0 {
		log.Fatalf("no capture sockets opened")
	}
	defer func() {
		for _, j := range jobs {
			j.tp.Close()
		}
	}()

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		s := <-ch
		log.Printf("👋 received %s, stopping...", s)
		cancel()
	}()

	var (
		wg        sync.WaitGroup
		writeMu   sync.Mutex // protects pcap writer
		total     uint64     // atomic
		matchPort = uint16(portFlag)
		start     = time.Now()
	)

	// One goroutine per interface
	for _, j := range jobs {
		j := j
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				data, ci, err := j.tp.ZeroCopyReadPacketData()
				atomic.AddUint64(&seen, 1)

				if err != nil {
					// Ignore benign timeouts
					if errors.Is(err, afpacket.ErrTimeout) || errors.Is(err, syscall.EAGAIN) {
						continue
					}
					select {
					case <-ctx.Done():
						return
					default:
						log.Printf("[%s] read error: %v", j.name, err)
						continue
					}
				}

				// Decode just enough to test ports
				pkt := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.NoCopy)
				tl := pkt.TransportLayer()
				if tl == nil {
					continue
				}
				switch t := tl.(type) {
				case *layers.TCP:
					if !(uint16(t.SrcPort) == matchPort || uint16(t.DstPort) == matchPort) {
						continue
					}
				case *layers.UDP:
					if !(uint16(t.SrcPort) == matchPort || uint16(t.DstPort) == matchPort) {
						continue
					}
				default:
					continue
				}

				// Optional: print concise line (guard against nil network layer)
				if nl := pkt.NetworkLayer(); nl != nil {
					var srcPort, dstPort uint16
					switch t := tl.(type) {
					case *layers.TCP:
						srcPort = uint16(t.SrcPort)
						dstPort = uint16(t.DstPort)
					case *layers.UDP:
						srcPort = uint16(t.SrcPort)
						dstPort = uint16(t.DstPort)
					}
					fmt.Printf("[%s] %s:%d -> %s:%d len=%d\n", j.name, nl.NetworkFlow().Src(), srcPort, nl.NetworkFlow().Dst(), dstPort, len(data))
				} else {
					fmt.Printf("[%s] (no net layer) len=%d\n", j.name, len(data))
				}

				// Enforce snaplen
				if len(data) > snaplen {
					data = data[:snaplen]
				}

				// Copy into stable slice for pcapgo
				// writeData := make([]byte, len(data))
				// copy(writeData, data)

				// Write
				writeMu.Lock()
				if err := w.WritePacket(ci, data); err != nil {
					log.Printf("pcap write error: %v", err)
				}
				writeMu.Unlock()

				if n := atomic.AddUint64(&total, 1); n%10000 == 0 {
					elapsed := time.Since(start).Truncate(time.Second)
					log.Printf("… captured %d matching packets (%d total seen) in %s", n, atomic.LoadUint64(&seen), elapsed)
				}
			}
		}()
	}

	wg.Wait()

	log.Printf("value seen: %d", atomic.LoadUint64(&seen))

	// Per-socket stats (best-effort)
	for _, j := range jobs {
		if stats, err := j.tp.Stats(); err == nil {
			log.Printf("📊 [%s] received=%d (dropped N/A w/TPACKETv3)", j.name, stats.Packets)
		}
	}
	log.Printf("✅ done. total packets written: %d", atomic.LoadUint64(&total))
}

// resolveTargets returns the list of interface names to capture on.
// - If name == "any": all UP interfaces (optionally including loopback).
// - If name == "": error.
// - Else: just that name.
func resolveTargets(name string, includeLo bool) ([]string, error) {
	if name == "" {
		return nil, errors.New(`no interface specified; use -i <name> or -i any`)
	}
	if name != "any" {
		return []string{name}, nil
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, in := range ifs {
		up := in.Flags&net.FlagUp != 0
		lb := in.Flags&net.FlagLoopback != 0
		if !up {
			continue
		}
		if !includeLo && lb {
			continue
		}
		out = append(out, in.Name)
	}
	return out, nil
}
