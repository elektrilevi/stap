package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var bytesSent int

var iface = flag.String("i", "dummy0", "Interface to read packets from")
var bind = flag.String("b", "65445", "Address to bind to")

func main() {

	flag.Parse()

	// Open up a pcap handle for packet writes.
	handleWrite, err := pcap.OpenLive(*iface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal("PCAP OpenLive error (handle to write packet):", err)
	}
	defer handleWrite.Close()

	http.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Only POST method allowed", http.StatusBadRequest)
			return
		}

		base64Decoder := base64.NewDecoder(base64.StdEncoding, r.Body)
		decodedBody := new(bytes.Buffer)
		decodedBody.ReadFrom(base64Decoder)

		packetReader, err := pcapgo.NewReader(decodedBody)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
		}

		if err != nil {
			log.Printf("Failed to create packet reader: %s\n", err)
			http.Error(w, "Invalid pcap data", http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))

		for {
			data, ci, err := packetReader.ReadPacketData()
			switch {
			case err == io.EOF:
				return
			case err != nil:
				log.Printf("Failed to read packet: %s\n", err)
			default:
				writePacketDelayed(handleWrite, data, ci)
				bytesSent += len(data)
			}
		}
	})

	log.Fatal(http.ListenAndServe(":"+*bind, nil))
}

func writePacketDelayed(handle *pcap.Handle, buf []byte, ci gopacket.CaptureInfo) {
	if ci.CaptureLength != ci.Length {
		// do not write truncated packets
		return
	}
	err := writePacket(handle, buf)
	if err != nil {
		log.Printf("Failed to send packet: %s\n", err)
	}
}

func writePacket(handle *pcap.Handle, buf []byte) error {
	if len(buf) == 0 {
		fmt.Println("Empty packet, skipping...")
		return nil
	}
	if err := handle.WritePacketData(buf); err != nil {
		log.Printf("Failed to send packet: %s\n", err)
		return err
	}
	return nil
}
