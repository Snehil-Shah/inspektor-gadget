// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64
// +build 386 amd64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type capabilitiesArgsT struct {
	Cap    int32
	CapOpt int32
}

type capabilitiesCapEvent struct {
	Mntnsid uint64
	Pid     uint32
	Cap     int32
	Tgid    uint32
	Uid     uint32
	CapOpt  int32
	Ret     int32
	Task    [16]uint8
}

type capabilitiesUniqueKey struct {
	Cap     int32
	_       [4]byte
	MntnsId uint64
}

// loadCapabilities returns the embedded CollectionSpec for capabilities.
func loadCapabilities() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_CapabilitiesBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load capabilities: %w", err)
	}

	return spec, err
}

// loadCapabilitiesObjects loads capabilities and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*capabilitiesObjects
//	*capabilitiesPrograms
//	*capabilitiesMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadCapabilitiesObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadCapabilities()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// capabilitiesSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type capabilitiesSpecs struct {
	capabilitiesProgramSpecs
	capabilitiesMapSpecs
}

// capabilitiesSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type capabilitiesProgramSpecs struct {
	IgTraceCapE *ebpf.ProgramSpec `ebpf:"ig_trace_cap_e"`
	IgTraceCapX *ebpf.ProgramSpec `ebpf:"ig_trace_cap_x"`
}

// capabilitiesMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type capabilitiesMapSpecs struct {
	Events        *ebpf.MapSpec `ebpf:"events"`
	MountNsFilter *ebpf.MapSpec `ebpf:"mount_ns_filter"`
	Seen          *ebpf.MapSpec `ebpf:"seen"`
	Start         *ebpf.MapSpec `ebpf:"start"`
}

// capabilitiesObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadCapabilitiesObjects or ebpf.CollectionSpec.LoadAndAssign.
type capabilitiesObjects struct {
	capabilitiesPrograms
	capabilitiesMaps
}

func (o *capabilitiesObjects) Close() error {
	return _CapabilitiesClose(
		&o.capabilitiesPrograms,
		&o.capabilitiesMaps,
	)
}

// capabilitiesMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadCapabilitiesObjects or ebpf.CollectionSpec.LoadAndAssign.
type capabilitiesMaps struct {
	Events        *ebpf.Map `ebpf:"events"`
	MountNsFilter *ebpf.Map `ebpf:"mount_ns_filter"`
	Seen          *ebpf.Map `ebpf:"seen"`
	Start         *ebpf.Map `ebpf:"start"`
}

func (m *capabilitiesMaps) Close() error {
	return _CapabilitiesClose(
		m.Events,
		m.MountNsFilter,
		m.Seen,
		m.Start,
	)
}

// capabilitiesPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadCapabilitiesObjects or ebpf.CollectionSpec.LoadAndAssign.
type capabilitiesPrograms struct {
	IgTraceCapE *ebpf.Program `ebpf:"ig_trace_cap_e"`
	IgTraceCapX *ebpf.Program `ebpf:"ig_trace_cap_x"`
}

func (p *capabilitiesPrograms) Close() error {
	return _CapabilitiesClose(
		p.IgTraceCapE,
		p.IgTraceCapX,
	)
}

func _CapabilitiesClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed capabilities_bpfel_x86.o
var _CapabilitiesBytes []byte
