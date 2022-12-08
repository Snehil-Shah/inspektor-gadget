// Code generated by bpf2go; DO NOT EDIT.
//go:build arm64
// +build arm64

package tracer

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type filetopFileId struct {
	Inode uint64
	Dev   uint32
	Pid   uint32
	Tid   uint32
	_     [4]byte
}

type filetopFileStat struct {
	Reads      uint64
	ReadBytes  uint64
	Writes     uint64
	WriteBytes uint64
	Pid        uint32
	Tid        uint32
	MntnsId    uint64
	Filename   [4096]uint8
	Comm       [16]uint8
	Type       int8
	_          [7]byte
}

// loadFiletop returns the embedded CollectionSpec for filetop.
func loadFiletop() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_FiletopBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load filetop: %w", err)
	}

	return spec, err
}

// loadFiletopObjects loads filetop and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*filetopObjects
//	*filetopPrograms
//	*filetopMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadFiletopObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadFiletop()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// filetopSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type filetopSpecs struct {
	filetopProgramSpecs
	filetopMapSpecs
}

// filetopSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type filetopProgramSpecs struct {
	IgTopfileRdE *ebpf.ProgramSpec `ebpf:"ig_topfile_rd_e"`
	IgTopfileWrE *ebpf.ProgramSpec `ebpf:"ig_topfile_wr_e"`
}

// filetopMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type filetopMapSpecs struct {
	Entries       *ebpf.MapSpec `ebpf:"entries"`
	MountNsFilter *ebpf.MapSpec `ebpf:"mount_ns_filter"`
}

// filetopObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadFiletopObjects or ebpf.CollectionSpec.LoadAndAssign.
type filetopObjects struct {
	filetopPrograms
	filetopMaps
}

func (o *filetopObjects) Close() error {
	return _FiletopClose(
		&o.filetopPrograms,
		&o.filetopMaps,
	)
}

// filetopMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadFiletopObjects or ebpf.CollectionSpec.LoadAndAssign.
type filetopMaps struct {
	Entries       *ebpf.Map `ebpf:"entries"`
	MountNsFilter *ebpf.Map `ebpf:"mount_ns_filter"`
}

func (m *filetopMaps) Close() error {
	return _FiletopClose(
		m.Entries,
		m.MountNsFilter,
	)
}

// filetopPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadFiletopObjects or ebpf.CollectionSpec.LoadAndAssign.
type filetopPrograms struct {
	IgTopfileRdE *ebpf.Program `ebpf:"ig_topfile_rd_e"`
	IgTopfileWrE *ebpf.Program `ebpf:"ig_topfile_wr_e"`
}

func (p *filetopPrograms) Close() error {
	return _FiletopClose(
		p.IgTopfileRdE,
		p.IgTopfileWrE,
	)
}

func _FiletopClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed filetop_bpfel_arm64.o
var _FiletopBytes []byte
