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

type fsslowerEvent struct {
	DeltaUs uint64
	EndNs   uint64
	Offset  int64
	Size    uint64
	MntnsId uint64
	Pid     uint32
	Op      uint32
	File    [32]uint8
	Task    [16]uint8
}

// loadFsslower returns the embedded CollectionSpec for fsslower.
func loadFsslower() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_FsslowerBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load fsslower: %w", err)
	}

	return spec, err
}

// loadFsslowerObjects loads fsslower and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*fsslowerObjects
//	*fsslowerPrograms
//	*fsslowerMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadFsslowerObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadFsslower()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// fsslowerSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type fsslowerSpecs struct {
	fsslowerProgramSpecs
	fsslowerMapSpecs
}

// fsslowerSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type fsslowerProgramSpecs struct {
	IgFsslOpenE *ebpf.ProgramSpec `ebpf:"ig_fssl_open_e"`
	IgFsslOpenX *ebpf.ProgramSpec `ebpf:"ig_fssl_open_x"`
	IgFsslReadE *ebpf.ProgramSpec `ebpf:"ig_fssl_read_e"`
	IgFsslReadX *ebpf.ProgramSpec `ebpf:"ig_fssl_read_x"`
	IgFsslSyncE *ebpf.ProgramSpec `ebpf:"ig_fssl_sync_e"`
	IgFsslSyncX *ebpf.ProgramSpec `ebpf:"ig_fssl_sync_x"`
	IgFsslWrE   *ebpf.ProgramSpec `ebpf:"ig_fssl_wr_e"`
	IgFsslWrX   *ebpf.ProgramSpec `ebpf:"ig_fssl_wr_x"`
}

// fsslowerMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type fsslowerMapSpecs struct {
	Events        *ebpf.MapSpec `ebpf:"events"`
	MountNsFilter *ebpf.MapSpec `ebpf:"mount_ns_filter"`
	Starts        *ebpf.MapSpec `ebpf:"starts"`
}

// fsslowerObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadFsslowerObjects or ebpf.CollectionSpec.LoadAndAssign.
type fsslowerObjects struct {
	fsslowerPrograms
	fsslowerMaps
}

func (o *fsslowerObjects) Close() error {
	return _FsslowerClose(
		&o.fsslowerPrograms,
		&o.fsslowerMaps,
	)
}

// fsslowerMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadFsslowerObjects or ebpf.CollectionSpec.LoadAndAssign.
type fsslowerMaps struct {
	Events        *ebpf.Map `ebpf:"events"`
	MountNsFilter *ebpf.Map `ebpf:"mount_ns_filter"`
	Starts        *ebpf.Map `ebpf:"starts"`
}

func (m *fsslowerMaps) Close() error {
	return _FsslowerClose(
		m.Events,
		m.MountNsFilter,
		m.Starts,
	)
}

// fsslowerPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadFsslowerObjects or ebpf.CollectionSpec.LoadAndAssign.
type fsslowerPrograms struct {
	IgFsslOpenE *ebpf.Program `ebpf:"ig_fssl_open_e"`
	IgFsslOpenX *ebpf.Program `ebpf:"ig_fssl_open_x"`
	IgFsslReadE *ebpf.Program `ebpf:"ig_fssl_read_e"`
	IgFsslReadX *ebpf.Program `ebpf:"ig_fssl_read_x"`
	IgFsslSyncE *ebpf.Program `ebpf:"ig_fssl_sync_e"`
	IgFsslSyncX *ebpf.Program `ebpf:"ig_fssl_sync_x"`
	IgFsslWrE   *ebpf.Program `ebpf:"ig_fssl_wr_e"`
	IgFsslWrX   *ebpf.Program `ebpf:"ig_fssl_wr_x"`
}

func (p *fsslowerPrograms) Close() error {
	return _FsslowerClose(
		p.IgFsslOpenE,
		p.IgFsslOpenX,
		p.IgFsslReadE,
		p.IgFsslReadX,
		p.IgFsslSyncE,
		p.IgFsslSyncX,
		p.IgFsslWrE,
		p.IgFsslWrX,
	)
}

func _FsslowerClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed fsslower_bpfel_x86.o
var _FsslowerBytes []byte
