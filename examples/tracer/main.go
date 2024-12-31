//go:build windows
// +build windows

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"

	"github.com/Velocidex/etw"
)

var (
	optSilent  = flag.Bool("silent", false, "Stop sending logs to stderr")
	optSession = flag.String("session", "etw-test", "Session Name")
	optTimeout = flag.Int("timeout", 5, "Capture only for this timeout")
	optID      = flag.Int("id", -1, "Capture only specified ID")
	optEvents  = flag.String("events", "registry,process", "Any of these separated by ,: registry,process,image_load,network,driver,file")
	optStacks  = flag.String("stack", "", "To enable stack traces for these event types: Any of these separated by ,: registry,process,image_load,network,driver,file")
)

func main() {
	flag.Parse()

	if *optSilent {
		log.SetOutput(ioutil.Discard)
	}

	// Trap cancellation (the only signal values guaranteed to be present in
	// the os package on all systems are os.Interrupt and os.Kill).
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-sigCh
		cancel()
	}()

	var checkpoints int64 = 5

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	cb := func(e *etw.Event) {
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.Printf("[DBG] Event %d from %s %v\n", e.Header.ID, e.Header.TimeStamp, checkpoints)
		if *optID > 0 && *optID != int(e.Header.ID) {
			return
		}

		_ = enc.Encode(e.Parsed())

		// When the rundown is finished we exit.
		if e.Header.OpCode == 8 {
			value := atomic.AddInt64(&checkpoints, -1)
			if value <= 0 {
				cancel()
			}
		}
	}

	fmt.Printf("Session %v\n", etw.KernelTraceControlGUIDString)
	session, err := NewSession(flag.Arg(0), *optSession, cb)
	if err != nil {
		log.Fatalf("Failed to create etw session; %s", err)
		return
	}
	defer session.Close()

	for _, arg := range flag.Args() {
		guid, err := windows.GUIDFromString(arg)
		if err != nil {
			log.Fatalf("Incorrect GUID given; %s", err)
		}

		session.SubscribeToProvider(etw.SessionOptions{
			Guid:          guid,
			Level:         etw.TraceLevel(255),
			CaptureState:  true,
			EnableMapInfo: true,
		})
		defer session.UnsubscribeFromProvider(guid)
	}

	go func() {
		defer cancel()

		log.Printf("[DBG] Starting to listen to ETW events")

		// Block until .Close().
		if err := session.Process(); err != nil {
			log.Printf("[ERR] Got error processing events: %s", err)
		} else {
			log.Printf("[DBG] Successfully shut down")
		}
	}()

	go func() {
		time.Sleep(time.Second * time.Duration(*optTimeout))
		log.Printf("[DBG] Closing session %v due to timeout", *optSession)

		cancel()
	}()

	// Wait for stop and shutdown gracefully.
	<-ctx.Done()

	log.Printf("[DBG] Shutting the session down")
}

func NewSession(guid, name string, cb func(e *etw.Event)) (*etw.Session, error) {
	if strings.EqualFold(guid, etw.KernelTraceControlGUIDString) {
		opts, err := parseOpts(*optEvents)
		if err != nil {
			return nil, err
		}

		if *optStacks != "" {
			stack_opts, err := parseOpts(*optStacks)
			if err != nil {
				return nil, err
			}
			opts.StackTracing = stack_opts
		}

		session, err := etw.NewKernelTraceSession(*opts, cb)
		if err != nil {
			err = etw.KillSession(etw.KernelTraceSessionName)
			if err != nil {
				return nil, err
			}

			session, err = etw.NewKernelTraceSession(*opts, cb)
			if err != nil {
				return nil, err
			}
		}

		return session, nil
	}

	session, err := etw.NewSession(name, cb)
	if err != nil {
		err = etw.KillSession(name)
		if err != nil {
			return nil, err
		}

		session, err = etw.NewSession(name, cb)
		if err != nil {
			return nil, err
		}
	}

	return session, nil
}

func parseOpts(in string) (*etw.RundownOptions, error) {
	opts := &etw.RundownOptions{}

	for _, item := range strings.Split(in, ",") {
		switch item {
		case "registry":
			opts.Registry = true
		case "process":
			opts.Process = true
		case "image_load":
			opts.ImageLoad = true
		case "network":
			opts.Network = true
		case "driver":
			opts.Driver = true
		case "file":
			opts.File = true
		case "thread":
			opts.Thread = true
		default:
			return nil, fmt.Errorf("Invalid event type %v", item)
		}
	}

	return opts, nil
}
