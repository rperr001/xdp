/*
sendudp pre-generates a frame with a UDP packet with a payload of the given
size and starts sending it in and endless loop to given destination as fast as
possible.
*/
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"time"

	"github.com/asavie/xdp"
	"github.com/vishvananda/netlink"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var NIC string
var QueueID int
var SrcMAC string
var DstMAC string
var SrcIP string
var DstIP string
var SrcPort uint
var DstPort uint
var PayloadSize uint

func main() {
	flag.StringVar(&NIC, "interface", "ens9", "Network interface to attach to.")
	flag.IntVar(&QueueID, "queue", 0, "The queue on the network interface to attach to.")
	flag.StringVar(&SrcMAC, "srcmac", "b2968175b211", "Source MAC address to use in sent frames.")
	flag.StringVar(&DstMAC, "dstmac", "ffffffffffff", "Destination MAC address to use in sent frames.")
	flag.StringVar(&SrcIP, "srcip", "192.168.111.10", "Source IP address to use in sent frames.")
	flag.StringVar(&DstIP, "dstip", "192.168.111.1", "Destination IP address to use in sent frames.")
	flag.UintVar(&SrcPort, "srcport", 1234, "Source UDP port.")
	flag.UintVar(&DstPort, "dstport", 1234, "Destination UDP port.")
	flag.UintVar(&PayloadSize, "payloadsize", 1400, "Size of the UDP payload.")
	flag.IntVar(&xdp.DefaultNumRxDescs, "rxringcap", 128, "Capacity of Rx ring queue.")
	flag.IntVar(&xdp.DefaultNumTxDescs, "txringcap", 128, "Capacity of Tx ring queue.")
	flag.Parse()

	// Initialize the XDP socket.

	link, err := netlink.LinkByName(NIC)
	if err != nil {
		panic(err)
	}

	xsk, err := xdp.NewSocket(link.Attrs().Index, QueueID)
	if err != nil {
		panic(err)
	}
	defer xsk.Close()

	// Pre-generate a frame containing a DNS query.

	srcMAC, _ := hex.DecodeString(SrcMAC)
	dstMAC, _ := hex.DecodeString(DstMAC)

	eth := &layers.Ethernet{
		SrcMAC: net.HardwareAddr(srcMAC),
		DstMAC: net.HardwareAddr(dstMAC),
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version: 4,
		IHL: 5,
		TTL: 64,
		Id: 0,
		Protocol: layers.IPProtocolUDP,
		SrcIP: net.ParseIP(SrcIP).To4(),
		DstIP: net.ParseIP(DstIP).To4(),
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(SrcPort),
		DstPort: layers.UDPPort(DstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)
	payload := make([]byte, PayloadSize)
	for i := 0; i < len(payload); i++ {
		payload[i] = byte(i)
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths: true,
		ComputeChecksums: true,
	}
	err = gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(payload))
	if err != nil {
		panic(err)
	}
	frameLen := len(buf.Bytes())

	// Fill all the frames in UMEM with the pre-generated UDP packet.

	// FIXME add NumDescs method to xsk?
	descs := xsk.GetDescs(xsk.NumFreeTxSlots())
	for i, _ := range descs {
		frameLen = copy(xsk.GetFrame(descs[i]), buf.Bytes())
	}

	// Start sending the pre-generated frame as quickly as possible in an
	// endless loop printing statistics of the number of sent frames and
	// the number of sent bytes every second.

	fmt.Printf("sending UDP packets from %v (%v) to %v (%v)...\n", ip.SrcIP, eth.SrcMAC, ip.DstIP, eth.DstMAC)

	go func(){
		var err error
		var prev xdp.Stats
		var cur xdp.Stats
		for i := uint64(0); ; i++ {
			time.Sleep(time.Duration(1)*time.Second)
			cur, err = xsk.Stats()
			if err != nil {
				panic(err)
			}
			numFilled := cur.Filled - prev.Filled
			numRx := cur.Received - prev.Received
			numTx := cur.Transmitted - prev.Transmitted
			numComplete := cur.Completed - prev.Completed
			numPkts := numComplete
			fmt.Printf("%d packets/s (%d Mb/s)\n", numPkts, (numPkts * uint64(frameLen) * 8)/(1000*1000))
			fmt.Printf("  numFilled=%d numRx=%d numTx=%d numComplete=%d (%d Mb/s)\n", numFilled, numRx, numTx, numComplete, (numComplete * uint64(frameLen) * 8)/(1000*1000))
			fmt.Printf("  Rx_dropped=%d Rx_invalid_descs=%d Tx_invalid_descs=%d\n", cur.KernelStats.Rx_dropped, cur.KernelStats.Rx_invalid_descs, cur.KernelStats.Tx_invalid_descs)
			prev = cur
		}
	}()

	var i int
	for {
		descs = xsk.GetDescs(xsk.NumFreeTxSlots())
		for i = 0; i < len(descs); i++ {
			descs[i].Len = uint32(frameLen)
		}
		xsk.Transmit(descs)

		_, _, err := xsk.Poll(-1)
		if err != nil {
			panic(err)
		}
	}
}
