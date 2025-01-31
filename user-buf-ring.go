package libbpfgo

/*
#cgo LDFLAGS: -lelf -lz
#include "libbpfgo.h"
*/
import "C"
import (
	"log"
	"sync"
	"unsafe"
)

//
// UserRingBuffer
//

type UserRingBuffer struct {
	rb     *C.struct_user_ring_buffer
	bpfMap *BPFMap
	closed bool
	stop   chan struct{}
	w      chan []byte
	wg     sync.WaitGroup
}

func (rb *UserRingBuffer) Start() {
	rb.stop = make(chan struct{})
	rb.wg.Add(1)
	go func() {
		defer rb.wg.Done()
		for {
			select {
			case b := <-rb.w:
				bpfBuffSizeC := C.uint(C.size_t(len(b)))
				entry := C.user_ring_buffer__reserve(rb.rb, bpfBuffSizeC)
				if entry == nil {
					log.Println("user_ring_buffer__reserve failed")
					continue
				}
				C.memcpy(entry, unsafe.Pointer(&b[0]), C.size_t(len(b)))

				C.user_ring_buffer__submit(rb.rb, entry)
			case <-rb.stop:
				return
			}
		}
	}()
}

func (rb *UserRingBuffer) Stop() {
	if rb.stop == nil {
		return
	}
	close(rb.stop)
	rb.wg.Wait()
}

func (rb *UserRingBuffer) Close() {
	if rb.closed {
		return
	}

	rb.Stop()
	C.user_ring_buffer__free(rb.rb)
	rb.closed = true
}
