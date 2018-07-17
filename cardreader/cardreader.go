package main

import (
	"bytes"
	"fmt"
	"time"

	"github.com/ebfe/scard"
)

func main() {
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
	rsp, err = card.Transmit([]byte{0x80, 0x42, 0x00, 0x00})
	if err != nil {
		fmt.Println("Error Transmit:", err)
		return
	}

	nullBytes := [65]byte{}
	if bytes.Equal(rsp[:65], nullBytes[:]) {
		fmt.Println("Key not initialized, initializing...")
		rsp, err = card.Transmit([]byte{0x80, 0x41, 0x00, 0x00})
		if err != nil {
			fmt.Println("Error Transmit:", err)
			return
		}
	}

	fmt.Printf("Card public key: [%x]", rsp)
}
