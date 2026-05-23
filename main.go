package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
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
	bpfObjectPath = "/data/local/tmp/ssl.bpf.o"
	defaultLib    = "/apex/com.android.conscrypt/lib64/libssl.so"
	defaultSymbol = "SSL_write"
	maxDataSize   = 256
)

type event struct {
	PID  uint32
	TID  uint32
	Len  uint32
	Dir  uint32
	Comm [16]byte
	Data [maxDataSize]byte
}

func main() {
	log.SetFlags(0)
	libPath := flag.String("lib", defaultLib, "shared library or executable path to uprobe")
	symbolName := flag.String("symbol", defaultSymbol, "symbol name to uprobe")
	offset := flag.Uint64("offset", 0, "absolute file offset to uprobe; overrides symbol lookup when non-zero")
	pid := flag.Int("pid", 0, "optional target process id")
	flag.Parse()

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("warning: remove memlock limit failed: %v", err)
	}

	var objs struct {
		TraceSSLWrite *ebpf.Program `ebpf:"trace_ssl_write"`
		TraceSSLRead  *ebpf.Program `ebpf:"trace_ssl_read_enter"`
		TraceSSLReadR *ebpf.Program `ebpf:"trace_ssl_read_exit"`
		Events        *ebpf.Map     `ebpf:"events"`
		ActiveReads   *ebpf.Map     `ebpf:"active_reads"`
	}
	if err := loadObjects(bpfObjectPath, &objs); err != nil {
		log.Fatalf("load eBPF object: %v", err)
	}
	defer objs.TraceSSLWrite.Close()
	defer objs.TraceSSLRead.Close()
	defer objs.TraceSSLReadR.Close()
	defer objs.Events.Close()
	defer objs.ActiveReads.Close()

	uprobe, err := attachUprobe(*libPath, *symbolName, *offset, *pid, objs.TraceSSLWrite, false)
	if err != nil {
		log.Fatalf("attach uprobe %s:%s: %v", *libPath, *symbolName, err)
	}
	defer uprobe.Close()
	readEntry, err := attachUprobe(*libPath, "SSL_read", 0, *pid, objs.TraceSSLRead, false)
	if err == nil {
		defer readEntry.Close()
		readExit, err := attachUprobe(*libPath, "SSL_read", 0, *pid, objs.TraceSSLReadR, true)
		if err == nil {
			defer readExit.Close()
		} else {
			log.Printf("warning: attach SSL_read return failed: %v", err)
		}
	} else {
		log.Printf("warning: attach SSL_read failed: %v", err)
	}

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

	log.Printf("attached %s:%s offset=0x%x pid=%d, waiting for TLS plaintext...", *libPath, *symbolName, *offset, *pid)
	if err := readEvents(reader); err != nil && !errors.Is(err, perf.ErrClosed) {
		log.Fatalf("read events: %v", err)
	}
}

func loadObjects(path string, objs interface{}) error {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return err
	}
	return spec.LoadAndAssign(objs, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelInstruction,
			LogSize:  1024 * 1024,
		},
	})
}

func attachUprobe(path, symbol string, offset uint64, pid int, prog *ebpf.Program, ret bool) (link.Link, error) {
	exe, err := link.OpenExecutable(path)
	if err != nil {
		return nil, err
	}
	var opts *link.UprobeOptions
	if offset != 0 {
		opts = &link.UprobeOptions{Address: offset, PID: pid}
	} else {
		opts = &link.UprobeOptions{PID: pid}
	}
	if ret {
		return exe.Uretprobe(symbol, prog, opts)
	}
	return exe.Uprobe(symbol, prog, opts)
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

	dir := "WRITE"
	if ev.Dir == 1 {
		dir = "READ"
	}
	fmt.Printf("\n[%s %s pid=%d tid=%d len=%d]\n", dir, comm, ev.PID, ev.TID, ev.Len)
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
