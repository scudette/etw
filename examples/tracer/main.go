//go:build windows
// +build windows

package main

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Velocidex/etw"
)

func main() {
	var (
		optSilent = flag.Bool("silent", false, "Stop sending logs to stderr")
		optHeader = flag.Bool("header", false, "Show event header in output")
		optBulk   = flag.Bool("bulk", false, "Use bulk mode")
		optID     = flag.Int("id", -1, "Capture only specified ID")
	)
	flag.Parse()

	if flag.NArg() != 1 && !*optBulk {
		log.Fatalf("Usage: %s [opts] <providerGUID>", filepath.Base(os.Args[0]))
	}
	if *optSilent {
		log.SetOutput(ioutil.Discard)
	}

	session, err := etw.NewSession("etw-test-" + randomName())
	if err != nil {
		log.Fatalf("Failed to create etw session; %s", err)
	}

	if *optBulk {
		smbServer, _ := windows.GUIDFromString("{D48CE617-33A2-4BC3-A5C7-11AA4F29619E}")
		smbClient, _ := windows.GUIDFromString("{988C59C5-0A1C-45B6-A555-0C62276E327E}")
		kProcess, _ := windows.GUIDFromString("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")
		kIO, _ := windows.GUIDFromString("{ABF1F586-2E50-4BA8-928D-49044E6F0DB7}")

		providers := []etw.SessionOptions{
			{
				Guid: smbServer,
			},
			{
				Guid: smbClient,
			},
			{
				Guid: kProcess,
			},
			{
				Guid: kIO,
			},
		}

		for _, provider := range providers {
			session.UpdateOptions(provider.Guid)
		}
	} else {
		guid, err := windows.GUIDFromString(flag.Arg(0))
		if err != nil {
			log.Fatalf("Incorrect GUID given; %s", err)
		}
		session.UpdateOptions(guid)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	cb := func(e *etw.Event) {
		log.Printf("[DBG] Event %d from %s\n", e.Header.ID, e.Header.TimeStamp)
		if *optID > 0 && *optID != int(e.Header.ID) {
			return
		}

		event := make(map[string]interface{})
		if *optHeader {
			event["Header"] = e.Header
		}
		if data, err := e.EventProperties(); err == nil {
			event["EventProperties"] = data
		} else {
			log.Printf("[ERR] Failed to enumerate event properties: %s", err)
		}
		_ = enc.Encode(event)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		log.Printf("[DBG] Starting to listen ETW events")

		// Block until .Close().
		if err := session.Process(cb); err != nil {
			log.Printf("[ERR] Got error processing events: %s", err)
		} else {
			log.Printf("[DBG] Successfully shut down")
		}

		wg.Done()
	}()

	// Trap cancellation (the only signal values guaranteed to be present in
	// the os package on all systems are os.Interrupt and os.Kill).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	// Wait for stop and shutdown gracefully.
	for range sigCh {
		log.Printf("[DBG] Shutting the session down")

		err = session.Close()
		if err != nil {
			log.Printf("[ERR] (!!!) Failed to stop session: %s\n", err)
		} else {
			break
		}
	}

	wg.Wait()
}

func randomName() string {
	if g, err := windows.GenerateGUID(); err == nil {
		return g.String()
	}

	// should be almost impossible, right?
	rand.Seed(time.Now().UnixNano())
	const alph = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = alph[rand.Intn(len(alph))]
	}
	return string(b)
}
