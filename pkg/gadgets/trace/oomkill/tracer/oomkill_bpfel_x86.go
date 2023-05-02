// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type oomkillDataT struct {
	Fpid      uint32
	Tpid      uint32
	Pages     uint64
	MountNsId uint64
	Timestamp uint64
	Fcomm     [16]uint8
	Tcomm     [16]uint8
}

// loadOomkill returns the embedded CollectionSpec for oomkill.
func loadOomkill() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_OomkillBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load oomkill: %w", err)
	}

	return spec, err
}

// loadOomkillObjects loads oomkill and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*oomkillObjects
//	*oomkillPrograms
//	*oomkillMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadOomkillObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadOomkill()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// oomkillSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type oomkillSpecs struct {
	oomkillProgramSpecs
	oomkillMapSpecs
}

// oomkillSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type oomkillProgramSpecs struct {
	IgOomKill *ebpf.ProgramSpec `ebpf:"ig_oom_kill"`
}

// oomkillMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type oomkillMapSpecs struct {
	Events               *ebpf.MapSpec `ebpf:"events"`
	GadgetMntnsFilterMap *ebpf.MapSpec `ebpf:"gadget_mntns_filter_map"`
}

// oomkillObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadOomkillObjects or ebpf.CollectionSpec.LoadAndAssign.
type oomkillObjects struct {
	oomkillPrograms
	oomkillMaps
}

func (o *oomkillObjects) Close() error {
	return _OomkillClose(
		&o.oomkillPrograms,
		&o.oomkillMaps,
	)
}

// oomkillMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadOomkillObjects or ebpf.CollectionSpec.LoadAndAssign.
type oomkillMaps struct {
	Events               *ebpf.Map `ebpf:"events"`
	GadgetMntnsFilterMap *ebpf.Map `ebpf:"gadget_mntns_filter_map"`
}

func (m *oomkillMaps) Close() error {
	return _OomkillClose(
		m.Events,
		m.GadgetMntnsFilterMap,
	)
}

// oomkillPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadOomkillObjects or ebpf.CollectionSpec.LoadAndAssign.
type oomkillPrograms struct {
	IgOomKill *ebpf.Program `ebpf:"ig_oom_kill"`
}

func (p *oomkillPrograms) Close() error {
	return _OomkillClose(
		p.IgOomKill,
	)
}

func _OomkillClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed oomkill_bpfel_x86.o
var _OomkillBytes []byte
