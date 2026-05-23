package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

const (
	bpfObjectPath = "ssl.bpf.o"
	libPath       = "/apex/com.android.conscrypt/lib64/libssl.so"
	symbolName    = "SSL_write"
	maxDataSize   = 256
)

type event struct {
	PID  uint32
	TID  uint32
	Len  uint32
	Comm [16]byte
	Data [maxDataSize]byte
}

func main() {
	log.SetFlags(0)

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("warning: remove memlock limit failed: %v", err)
	}

	var objs struct {
		TraceSSLWrite *ebpf.Program `ebpf:"trace_ssl_write"`
		Events        *ebpf.Map     `ebpf:"events"`
	}
	if err := loadObjects(bpfObjectPath, &objs); err != nil {
		log.Fatalf("load eBPF object: %v", err)
	}
	defer objs.TraceSSLWrite.Close()
	defer objs.Events.Close()

	uprobe, err := attachSSLWrite(libPath, symbolName, objs.TraceSSLWrite)
	if err != nil {
		log.Fatalf("attach uprobe %s:%s: %v", libPath, symbolName, err)
	}
	defer uprobe.Close()

	reader, err := perf.NewReader(objs.Events, os.Getpagesize()*8)
	if err != nil {
		log.Fatalf("open perf reader: %v", err)
	}
	defer reader.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		reader.Close()
	}()

	log.Printf("attached %s:%s, waiting for TLS plaintext...", libPath, symbolName)
	if err := readEvents(reader); err != nil && !errors.Is(err, perf.ErrClosed) {
		log.Fatalf("read events: %v", err)
	}
}

func loadObjects(path string, objs interface{}) error {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return err
	}
	return spec.LoadAndAssign(objs, nil)
}

func attachSSLWrite(path, symbol string, prog *ebpf.Program) (link.Link, error) {
	exe, err := link.OpenExecutable(path)
	if err != nil {
		return nil, err
	}
	return exe.Uprobe(symbol, prog, nil)
}

func readEvents(reader *perf.Reader) error {
	for {
		record, err := reader.Read()
		if err != nil {
			return err
		}
		if record.LostSamples > 0 {
			log.Printf("lost %d samples", record.LostSamples)
			continue
		}

		var ev event
		if err := binary.Read(bytes.NewReader(record.RawSample), nativeEndian(), &ev); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}
		printEvent(ev)
	}
}

func printEvent(ev event) {
	length := int(ev.Len)
	if length > len(ev.Data) {
		length = len(ev.Data)
	}
	payload := ev.Data[:length]
	comm := strings.TrimRight(string(ev.Comm[:]), "\x00")

	fmt.Printf("\n[%s pid=%d tid=%d len=%d]\n", comm, ev.PID, ev.TID, ev.Len)
	if utf8.Valid(payload) {
		fmt.Println(string(payload))
		return
	}
	fmt.Printf("% x\n", payload)
}

func nativeEndian() binary.ByteOrder {
	var value uint16 = 0x0102
	if *(*byte)(unsafe.Pointer(&value)) == 0x02 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}
