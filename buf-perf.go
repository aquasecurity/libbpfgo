package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"

import (
	"fmt"
	"sync"
	"syscall"
)

//
// PerfBuffer
//

type PerfBuffer struct {
	pb         *C.struct_perf_buffer
	bpfMap     *BPFMap
	slot       uint
	eventsChan chan []byte
	lostChan   chan uint64
	stopped    bool
	closed     bool
	wg         sync.WaitGroup
	stopFlag   *C.atomic_int
}

// Poll will wait until timeout in milliseconds to gather
// data from the perf buffer.
func (pb *PerfBuffer) Poll(timeout int) {
	pb.wg.Add(1)
	go pb.poll(timeout)
}

// Deprecated: use PerfBuffer.Poll() instead.
func (pb *PerfBuffer) Start() {
	pb.Poll(300)
}

func (pb *PerfBuffer) Stop() {
	if pb.stopped {
		return
	}
	pb.stopped = true

	// Signal the poll goroutine to exit
	C.cgo_signal_buffer_stop(pb.stopFlag)

	// The event and lost channels should be drained here since the consumer
	// may have stopped at this point. Failure to drain it will
	// result in a deadlock: the channel will fill up and the poll
	// goroutine will block in the callback.
	go func() {
		// revive:disable:empty-block
		for range pb.eventsChan {
		}

		if pb.lostChan != nil {
			for range pb.lostChan {
			}
		}
		// revive:enable:empty-block
	}()

	// Wait for the poll goroutine to exit
	pb.wg.Wait()

	// Close the channel -- this is useful for the consumer but
	// also to terminate the drain goroutine above.
	close(pb.eventsChan)
	if pb.lostChan != nil {
		close(pb.lostChan)
	}
}

func (pb *PerfBuffer) Close() {
	if pb.closed {
		return
	}

	pb.Stop()
	C.cgo_destroy_buffer_stop_flag(pb.stopFlag)
	C.perf_buffer__free(pb.pb)
	eventChannels.remove(pb.slot)
	pb.closed = true
}

// todo: consider writing the perf polling in go as c to go calls (callback) are expensive
func (pb *PerfBuffer) poll(timeout int) error {
	defer pb.wg.Done()

	const maxRetries = 3
	var retries int

	for {
		ret := C.cgo_perf_buffer__poll(pb.pb, C.int(timeout), pb.stopFlag)
		if ret == 0 {
			// Clean exit (e.g., from stop fd)
			return nil
		}

		err := syscall.Errno(-ret)

		// Retryable errors
		if err == syscall.EINTR {
			continue
		}

		// Optional: retry on transient libbpf errors (negative return)
		if retries < maxRetries {
			retries++
			continue
		}

		return fmt.Errorf("error polling perf buffer (after %d retries): %w", retries, err)
	}
}
