package main

import (
	"bytes"
	"fmt"
	"net/rpc"
	"net/rpc/jsonrpc"
	"time"

	"github.com/ebfe/scard"
	"github.com/mit-dci/lit/btcutil"
	"github.com/mit-dci/lit/btcutil/btcec"
	"github.com/mit-dci/lit/sig64"
	"github.com/mit-dci/lit/wire"
	"golang.org/x/net/websocket"
)

type RCSendArgs struct {
	PeerIdx uint32
	Msg     []byte
}

type StatusReply struct {
	Status string
}

func main() {
	for {
		fmt.Println("Present your card to sign a request for pushing 30000 sats on channel 1")

		// generate the command to push 1 sat over channel 1
		wsConn, err := websocket.Dial("ws://localhost:8002/ws", "", "http://127.0.0.1/")
		if err != nil {
			fmt.Printf("Error connecting to LIT: %s", err.Error())
		}
		rpcConn := jsonrpc.NewClient(wsConn)

		msg := []byte("{\"method\":\"Push\", \"args\":{\"ChanIdx\":1, \"Amt\": 30000}}")
		hash := btcutil.Hash160(msg)

		// Establish a PC/SC context
		context, err := scard.EstablishContext()
		if err != nil {
			fmt.Println("Error EstablishContext:", err)
			return
		}

		// Release the PC/SC context (when needed)
		defer context.Release()

		// Wait for a card in one of the readers
		reader := ""
		var card *scard.Card

		attempt := 0
		for {
			attempt++
			if attempt > 100 {
				break
			}

			// List available readers
			readers, err := context.ListReaders()
			if err != nil {
				fmt.Println("Error ListReaders:", err)
				return
			}

			for _, r := range readers {
				card, err = context.Connect(r, scard.ShareShared, scard.ProtocolAny)
				if err != nil {
					continue
				}
				reader = r
				break
			}
			if reader != "" {
				break
			}
			time.Sleep(time.Millisecond * 1000)
		}

		if reader == "" {
			fmt.Println("No card found. Exiting")
			return
		} else {
			fmt.Printf("Using card in reader [%s]\n", reader)
		}

		// Disconnect (when needed)
		defer card.Disconnect(scard.LeaveCard)

		// Select our card applet
		var cmd_select = []byte{0x00, 0xa4, 0x04, 0x00, 0x0B, 0x4A,
			0x87, 0xAB, 0x57, 0x43, 0x61, 0x72, 0x64, 0x4F, 0x53, 0x04}
		rsp, err := card.Transmit(cmd_select)
		if err != nil {
			fmt.Println("Error Transmit:", err)
			return
		}
		if !(rsp[0] == 0x90 && rsp[1] == 0x00) {
			fmt.Println("Incompatible card found. Exiting")
			return
		}

		// Get pubkey from card
		pubKeyBytes, err := card.Transmit([]byte{0x80, 0x42, 0x00, 0x00})
		if err != nil {
			fmt.Println("Error Transmit:", err)
			return
		}

		nullBytes := [65]byte{}
		if bytes.Equal(pubKeyBytes[:65], nullBytes[:]) {
			fmt.Println("Key not initialized, initializing...")
			pubKeyBytes, err = card.Transmit([]byte{0x80, 0x41, 0x00, 0x00})
			if err != nil {
				fmt.Println("Error Transmit:", err)
				return
			}
		}

		pub, err := btcec.ParsePubKey(pubKeyBytes[:65], btcec.S256())
		if err != nil {
			fmt.Println("Error in parsing pubkey from card:", err)
			return
		}
		pubKeyCompressed := pub.SerializeCompressed()

		// Sign the digest on the card
		signMessage := []byte{0x80, 0x43, 0x00, 0x00, 0x14}
		signMessage = append(signMessage, hash...)
		signatureBytes, err := card.Transmit(signMessage)
		if err != nil {
			fmt.Println("Error in signature command:", err)
			return
		}
		sig, err := btcec.ParseSignature(signatureBytes, btcec.S256())
		if err != nil {
			fmt.Println("Error parsing signature:", err)
			return
		}
		sigDER := sig.Serialize()
		sig64, err := sig64.SigCompress(sigDER)
		if err != nil {
			fmt.Println("Error compressing signature:", err)
			return
		}

		var buf bytes.Buffer
		buf.WriteByte(0xB0)
		buf.Write(pubKeyCompressed)
		buf.Write(sig64[:])
		buf.Write([]byte{0x01}) //RipeMD Digest
		wire.WriteVarInt(&buf, 0, uint64(len(msg)))
		buf.Write(msg)
		request := buf.Bytes()
		fmt.Printf("Sending remote control command from node 2 to node 1: %x\n", request)
		RCSend(rpcConn, 1, request)

		time.Sleep(5 * time.Second)
	}
}

func RCSend(c *rpc.Client, peerIdx uint32, msg []byte) (*StatusReply, error) {
	args := new(RCSendArgs)
	args.PeerIdx = peerIdx
	args.Msg = msg

	reply := new(StatusReply)
	err := c.Call("LitRPC.RemoteControlSend", args, reply)
	if err != nil {
		return nil, err
	}
	return reply, nil
}
