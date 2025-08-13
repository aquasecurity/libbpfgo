package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/aquasecurity/libbpfgo/selftest/common"
)

func main() {
	bpfModule, err := bpf.NewModuleFromFileArgs(bpf.NewModuleArgs{
		BPFObjPath:     "main.bpf.o",
		KernelLogLevel: 0,
	})
	if err != nil {
		common.Error(err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		common.Error(err)
	}

	m := bpfModule

	var afterFunc func()

	iters := m.Iterator()
	for {
		m := iters.NextMap()
		if m == nil {
			break
		}
		if m.Type().String() == "BPF_MAP_TYPE_STRUCT_OPS" {
			var link *bpf.BPFLink
			if link, err = m.AttachStructOps(); err != nil {
				common.Error(err)
			}
			afterFunc = func() {
				if err := link.Destroy(); err != nil {
					common.Error(err)
				}
			}
		}
	}

	var statsMap *bpf.BPFMap
	if statsMap, err = bpfModule.GetMap("stats"); err != nil {
		common.Error(err)
	}
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
	wg.Add(1)
	go func(ctx context.Context) {
		for true {
			select {
			case <-ctx.Done():
				wg.Done()
				return
			default:
				res := getStat(statsMap)
				log.Printf("local: %d, global: %d", res[0], res[1])
			}
			time.Sleep(1 * time.Second)
		}
	}(ctx)
	time.Sleep(3 * time.Second)
	cancel()
	wg.Wait()
	afterFunc()
	log.Println("scheduler exit")
}

func getStat(m *bpf.BPFMap) []uint64 {
	cpuNum, err := bpf.NumPossibleCPUs()
	if err != nil {
		common.Error(err)
	}
	cnts := make([][]uint64, 2)
	cnts[0] = make([]uint64, cpuNum)
	cnts[1] = make([]uint64, cpuNum)
	stats := []uint64{0, 0}
	for i := 0; i < 2; i++ {
		v, err := m.GetValue(unsafe.Pointer(&i))
		if err != nil {
			common.Error(err)
		}
		for cpu := 0; cpu < cpuNum; cpu++ {
			n := v[cpu*8 : cpu*8+8]
			cnts[i][cpu] = common.ByteOrder().Uint64(n)
			stats[i] += cnts[i][cpu]
		}
	}
	return stats
}
