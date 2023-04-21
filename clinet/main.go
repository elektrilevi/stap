package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var (
	deviceName        = flag.String("device", "\\Device\\NPF_{FFFFFFFF-DDDD-CCCC-EEEE-TTTTTTTTTTTT}", "Specify the device to capture packets from")
	serverIP          = flag.String("server", "192.168.1.1", "Specify the server IP address")
	serverPort        = flag.String("port", "65445", "Specify the server port")
	snapshotLen int32 = 65536
	err         error
	handle      *pcap.Handle
	packetCount int = 0
)

func main() {
	flag.Parse()
	// Open the device for capturing
	handle, err = pcap.OpenLive(*deviceName, snapshotLen, true, pcap.BlockForever)
	if err != nil {
		fmt.Printf("Error opening device %s: %v", *deviceName, err)
		os.Exit(1)
	}
	defer handle.Close()

	filter := fmt.Sprintf("not ((dst host %s and dst port %s) or (src host %s and src port %s))", *serverIP, *serverPort, *serverIP, *serverPort)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		fmt.Printf("Error setting BPF filter: %s", err)
		os.Exit(1)
	}

	buffer := new(bytes.Buffer)
	buffer.Reset()
	w := pcapgo.NewWriter(buffer)
	err = w.WriteFileHeader(uint32(snapshotLen), handle.LinkType())
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Capturing packets on device", *deviceName, "for 10 seconds...")
	ticker := time.Tick(10 * time.Second)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		select {
		case <-ticker:
			err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("Sending %v packets\n", packetCount)

			// Prepare request body
			reqBody := new(bytes.Buffer)
			base64Enc := base64.NewEncoder(base64.StdEncoding, reqBody)
			base64Enc.Write(buffer.Bytes())
			base64Enc.Close()

			resp, err := func() (*http.Response, error) {
				req, err := http.NewRequest(http.MethodPost, "http://"+*serverIP+":"+*serverPort+"/upload", reqBody)
				if err != nil {
					return nil, err
				}
				return http.DefaultClient.Do(req)
			}()

			if err != nil {
				log.Fatalf("Error sending packet: %v", err)
			}
			defer resp.Body.Close()

			// Reset the buffer and packet count
			packetCount = 0
			buffer.Reset()
			// Write the file header again
			err = w.WriteFileHeader(uint32(snapshotLen), handle.LinkType())
			if err != nil {
				log.Fatal(err)
			}

		default:
			err = w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Fatal(err)
			}
			packetCount++
		}
	}
}
