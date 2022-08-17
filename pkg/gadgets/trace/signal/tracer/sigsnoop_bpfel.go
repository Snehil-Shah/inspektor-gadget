// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type sigsnoopEvent struct {
	Pid     uint32
	Tpid    uint32
	MntnsId uint64
	Sig     int32
	Ret     int32
	Comm    [16]int8
}

// loadSigsnoop returns the embedded CollectionSpec for sigsnoop.
func loadSigsnoop() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SigsnoopBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load sigsnoop: %w", err)
	}

	return spec, err
}

// loadSigsnoopObjects loads sigsnoop and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *sigsnoopObjects
//     *sigsnoopPrograms
//     *sigsnoopMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSigsnoopObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSigsnoop()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// sigsnoopSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sigsnoopSpecs struct {
	sigsnoopProgramSpecs
	sigsnoopMapSpecs
}

// sigsnoopSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sigsnoopProgramSpecs struct {
	KillEntry   *ebpf.ProgramSpec `ebpf:"kill_entry"`
	KillExit    *ebpf.ProgramSpec `ebpf:"kill_exit"`
	SigTrace    *ebpf.ProgramSpec `ebpf:"sig_trace"`
	TgkillEntry *ebpf.ProgramSpec `ebpf:"tgkill_entry"`
	TgkillExit  *ebpf.ProgramSpec `ebpf:"tgkill_exit"`
	TkillEntry  *ebpf.ProgramSpec `ebpf:"tkill_entry"`
	TkillExit   *ebpf.ProgramSpec `ebpf:"tkill_exit"`
}

// sigsnoopMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sigsnoopMapSpecs struct {
	Events        *ebpf.MapSpec `ebpf:"events"`
	MountNsFilter *ebpf.MapSpec `ebpf:"mount_ns_filter"`
	Values        *ebpf.MapSpec `ebpf:"values"`
}

// sigsnoopObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSigsnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type sigsnoopObjects struct {
	sigsnoopPrograms
	sigsnoopMaps
}

func (o *sigsnoopObjects) Close() error {
	return _SigsnoopClose(
		&o.sigsnoopPrograms,
		&o.sigsnoopMaps,
	)
}

// sigsnoopMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSigsnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type sigsnoopMaps struct {
	Events        *ebpf.Map `ebpf:"events"`
	MountNsFilter *ebpf.Map `ebpf:"mount_ns_filter"`
	Values        *ebpf.Map `ebpf:"values"`
}

func (m *sigsnoopMaps) Close() error {
	return _SigsnoopClose(
		m.Events,
		m.MountNsFilter,
		m.Values,
	)
}

// sigsnoopPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSigsnoopObjects or ebpf.CollectionSpec.LoadAndAssign.
type sigsnoopPrograms struct {
	KillEntry   *ebpf.Program `ebpf:"kill_entry"`
	KillExit    *ebpf.Program `ebpf:"kill_exit"`
	SigTrace    *ebpf.Program `ebpf:"sig_trace"`
	TgkillEntry *ebpf.Program `ebpf:"tgkill_entry"`
	TgkillExit  *ebpf.Program `ebpf:"tgkill_exit"`
	TkillEntry  *ebpf.Program `ebpf:"tkill_entry"`
	TkillExit   *ebpf.Program `ebpf:"tkill_exit"`
}

func (p *sigsnoopPrograms) Close() error {
	return _SigsnoopClose(
		p.KillEntry,
		p.KillExit,
		p.SigTrace,
		p.TgkillEntry,
		p.TgkillExit,
		p.TkillEntry,
		p.TkillExit,
	)
}

func _SigsnoopClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed sigsnoop_bpfel.o
var _SigsnoopBytes []byte
