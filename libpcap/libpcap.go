package libpcap

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func Libpcap() {
	// Create a context that is canceled on a SIGINT or SIGTERM signal.
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup

	// wg.Add(1)
	// go func() {
	// 	defer wg.Done()
	// 	replayCapturedTraffic()
	// }()

	// Start packet capture in a separate goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		capturePackets(ctx)
	}()

	// Wait for a shutdown signal.
	<-ctx.Done()

	// Wait for all goroutines to finish.
	log.Println("Waiting for goroutines to finish...")
	wg.Wait()
	log.Println("All goroutines finished. Exiting.")
}

// capturePackets captures network traffic on port 8080 and saves it to a file.
// It stops when the provided context is canceled.
func capturePackets(ctx context.Context) {
	// Open the network interface for capturing traffic.
	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Could not open network interface: %v", err)
		return
	}
	defer handle.Close()

	// Create a new pcap file to dump the captured packets.
	file, err := os.Create("captured_app_traffic.pcap")
	if err != nil {
		log.Printf("Could not create pcap file: %v", err)
		return
	}
	defer file.Close()

	// Create a pcap writer.
	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(1600, handle.LinkType()); err != nil {
		log.Printf("Could not write pcap file header: %v", err)
		return
	}

	// Start packet capture.
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	log.Println("Starting packet capture...")

	// Loop through the packets and filter by port (e.g., 8080).
	for {
		select {
		case <-ctx.Done():
			log.Println("Stopping packet capture.")
			fmt.Println("Capture complete. Packets saved to 'captured_app_traffic.pcap'")
			return
		case packet := <-packetSource.Packets():
			if packet == nil {
				return
			}
			// Check if the packet contains a transport layer (e.g., TCP/UDP).
			if transportLayer := packet.TransportLayer(); transportLayer != nil {
				// Check if the packet's source or destination port is 26789.
				if tcp, ok := transportLayer.(*layers.TCP); ok {

					if tcp.SrcPort == layers.TCPPort(16789) || tcp.DstPort == layers.TCPPort(16789) { // For a specific port
						// Log the packet details.
						log.Printf("Captured packet: %s %s from %s to %s", tcp.SrcPort, tcp.DstPort, packet.NetworkLayer().NetworkFlow().Src(), packet.NetworkLayer().NetworkFlow().Dst())
					}

					if tcp.SrcPort == layers.TCPPort(16789) || tcp.DstPort == layers.TCPPort(16789) { // For a specific port
						// Write the captured packet to the file.
						if err := writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()); err != nil {
							log.Printf("Failed to write packet: %v", err)
						} else {
							fmt.Println("Packet captured and written to file.")
						}
					}
				}
			}
		}
	}
}

func replayCapturedTraffic() {
	// Open the pcap file
	handle, err := pcap.OpenOffline("captured_app_traffic.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Create an HTTP client for sending requests
	client := &http.Client{}

	// Process each packet in the pcap file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Check if the packet contains an IP and TCP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if ipLayer == nil || tcpLayer == nil {
			continue
		}

		// Parse the TCP payload to extract HTTP data
		tcp, _ := tcpLayer.(*layers.TCP)
		if len(tcp.Payload) == 0 {
			continue
		}

		// Create an HTTP request from the TCP payload (HTTP Request)
		httpReq := extractHTTPRequest(tcp.Payload)
		if httpReq != nil {
			// Send the HTTP request
			resp, err := client.Do(httpReq)
			if err != nil {
				fmt.Printf("Error sending HTTP request: %v\n", err)
				continue
			}
			defer resp.Body.Close()
			fmt.Printf("Sent HTTP request to %s, received status: %s\n", httpReq.URL, resp.Status)
		}
	}
}

// Extracts an HTTP request from the TCP payload (simple HTTP parsing)
func extractHTTPRequest(payload []byte) *http.Request {
	// Assuming the payload contains a simple HTTP request
	// We extract the method, URL, and headers (this is a very basic approach)
	if len(payload) < 4 {
		return nil
	}

	// Extract the HTTP method, URL, and headers (assuming HTTP/1.1 request format)
	reqLine := string(payload)
	fmt.Println("Request Line:", reqLine)
	var method string

	// A very simple check for "GET", "POST", etc.
	if len(reqLine) > 4 {
		if reqLine[:3] == "GET" {
			method = "GET"
			// urlStr = reqLine[4 : len(reqLine)-2] // Extracting URL from GET request (example)
		}
	} else {
		return nil
	}

	// Construct the HTTP request (assuming the URL is localhost)
	req, err := http.NewRequest(method, "http://127.0.0.1:8080", nil)
	if err != nil {
		return nil
	}

	// Add simple headers (you may need to extract these from the pcap if available)
	req.Header.Set("User-Agent", "Go HTTP Client")
	req.Header.Set("Accept", "application/json")

	// Return the constructed HTTP request
	return req
}
