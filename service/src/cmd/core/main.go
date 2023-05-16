package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"phreaking/internal/core"
)

func serveClient(conn net.Conn, bufsize int) error {
	for {
		buf := make([]byte, bufsize+128) // add overhead of SCTPSndRcvInfoWrappedConn
		n, err := conn.Read(buf)
		if err != nil {
			log.Printf("read failed: %v", err)
			return err
		}
		log.Printf("read: %d", n)

		data := buf[32:n] // remove excess bytes
		log.Printf("Packet contents: %s", hex.Dump(data))
		core.HandleNGAP(conn, data)

	}
}
func handleConnection(c net.Conn) {
	fmt.Printf("Serving %s\n", c.RemoteAddr().String())

	for {
		buf := make([]byte, 1024)

		//len, err := c.Read(buf)
		_, err := c.Read(buf)
		if err != nil {
			fmt.Printf("Error reading: %#v\n", err)
			return
		}
		core.HandleNGAP(c, buf)
	}
	c.Close()
}

/*
func main() {
	fmt.Println("Hello world!")
	crypto.PrintCrypto()

	var ip = flag.String("ip", "0.0.0.0", "")
	var port = flag.Int("port", 3399, "")
	var bufsize = flag.Int("bufsize", 256, "")
	var sndbuf = flag.Int("sndbuf", 0, "")
	var rcvbuf = flag.Int("rcvbuf", 0, "")

	flag.Parse()

	ips := []net.IPAddr{}

	for _, i := range strings.Split(*ip, ",") {
		if a, err := net.ResolveIPAddr("ip", i); err == nil {
			log.Printf("Resolved address '%s' to %s", i, a)
			ips = append(ips, *a)
		} else {
			log.Printf("Error resolving address '%s': %v", i, err)
		}
	}

	addr := &sctp.SCTPAddr{
		IPAddrs: ips,
		Port:    *port,
	}
	log.Printf("raw addr: %+v\n", addr.ToRawSockAddrBuf())

	// Run server

	ln, err := sctp.ListenSCTP("sctp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("Listen on %s", ln.Addr())

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalf("failed to accept: %v", err)
		}
		log.Printf("Accepted Connection from RemoteAddr: %s", conn.RemoteAddr())
		wconn := sctp.NewSCTPSndRcvInfoWrappedConn(conn.(*sctp.SCTPConn))
		if *sndbuf != 0 {
			err = wconn.SetWriteBuffer(*sndbuf)
			if err != nil {
				log.Fatalf("failed to set write buf: %v", err)
			}
		}
		if *rcvbuf != 0 {
			err = wconn.SetReadBuffer(*rcvbuf)
			if err != nil {
				log.Fatalf("failed to set read buf: %v", err)
			}
		}
		*sndbuf, err = wconn.GetWriteBuffer()
		if err != nil {
			log.Fatalf("failed to get write buf: %v", err)
		}
		*rcvbuf, err = wconn.GetReadBuffer()
		if err != nil {
			log.Fatalf("failed to get read buf: %v", err)
		}
		log.Printf("SndBufSize: %d, RcvBufSize: %d", *sndbuf, *rcvbuf)

		go serveClient(wconn, *bufsize)
	}

}

*/

func main() {
	l, err := net.Listen("tcp4", ":3399")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer l.Close()

	for {
		c, err := l.Accept()
		if err != nil {
			fmt.Println(err)
			return
		}
		go handleConnection(c)
	}
}
