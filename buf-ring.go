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
// RingBuffer
//

type RingBuffer struct {
	rb       *C.struct_ring_buffer
	bpfMap   *BPFMap
	slots    []uint
	stopped  bool
	closed   bool
	wg       sync.WaitGroup
	stopFlag *C.atomic_int
}

// Poll will wait until timeout in milliseconds to gather
// data from the ring buffer.
func (rb *RingBuffer) Poll(timeout int) {
	rb.wg.Add(1)
	go rb.poll(timeout)
}

// Deprecated: use RingBuffer.Poll() instead.
func (rb *RingBuffer) Start() {
	rb.Poll(300)
}

func (rb *RingBuffer) Stop() {
	if rb.stopped {
		return
	}

	rb.stopped = true

	// Signal the poll goroutine to exit
	C.cgo_signal_buffer_stop(rb.stopFlag)

	// The event channel should be drained here since the consumer
	// may have stopped at this point. Failure to drain it will
	// result in a deadlock: the channel will fill up and the poll
	// goroutine will block in the callback.
	for _, slot := range rb.slots {
		eventChan := eventChannels.get(slot).(chan []byte)
		go func() {
			// revive:disable:empty-block
			for range eventChan {
			}
			// revive:enable:empty-block
		}()
	}

	// Wait for the poll goroutine to exit
	rb.wg.Wait()

	// Close the channel -- this is useful for the consumer but
	// also to terminate the drain goroutine above.
	for _, slot := range rb.slots {
		eventChan := eventChannels.get(slot).(chan []byte)
		close(eventChan)
	}
}

func (rb *RingBuffer) Close() {
	if rb.closed {
		return
	}

	rb.Stop()
	C.cgo_destroy_buffer_stop_flag(rb.stopFlag)
	C.ring_buffer__free(rb.rb)
	for _, slot := range rb.slots {
		eventChannels.remove(slot)
	}
	rb.closed = true
}

func (rb *RingBuffer) poll(timeout int) error {
	defer rb.wg.Done()

	const maxRetries = 3
	var retries int

	for {
		ret := C.cgo_ring_buffer__poll(rb.rb, C.int(timeout), rb.stopFlag)
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

		return fmt.Errorf("error polling ring buffer (after %d retries): %w", retries, err)
	}
}
