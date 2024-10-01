// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"strconv"
	"strings"

	"deadlock/digraph"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

var g *digraph.DiGraph

//export gadgetInit
func gadgetInit() int {
	g = digraph.NewDiGraph()
	ds, err := api.GetDataSource("deadlock")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}
	mutex1F, err := ds.GetField("mutex1")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	mutex2F, err := ds.GetField("mutex2")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	tidF, err := ds.GetField("tid")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	pidF, err := ds.GetField("pid")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	mutex1StackF, err := ds.GetField("mutex1_stack_id")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	mutex2StackF, err := ds.GetField("mutex2_stack_id")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	commF, err := ds.GetField("comm")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}
	ds.Subscribe(func(source api.DataSource, data api.Data) {
		mutex1, err := mutex1F.Uint64(data)
		if err != nil {
			api.Warnf("failed to get field: %s", err)
			return
		}
		mutex2, err := mutex2F.Uint64(data)
		if err != nil {
			api.Warnf("failed to get field: %s", err)
			return
		}
		tid, err := tidF.Uint32(data)
		if err != nil {
			api.Warnf("failed to get field: %s", err)
			return
		}
		pid, err := pidF.Uint32(data)
		if err != nil {
			api.Warnf("failed to get field: %s", err)
			return
		}
		mutex1Stack, err := mutex1StackF.Uint64(data)
		if err != nil {
			api.Warnf("failed to get field: %s", err)
			return
		}
		mutex2Stack, err := mutex2StackF.Uint64(data)
		if err != nil {
			api.Warnf("failed to get field: %s", err)
			return
		}
		comm, err := commF.String(data)
		if err != nil {
			api.Warnf("failed to get field: %s", err)
			return
		}
		g.AddEdge(mutex1, mutex2, map[string]interface{}{
			"tid":             tid,
			"pid":             pid,
			"mutex1_stack_id": mutex1Stack,
			"mutex2_stack_id": mutex2Stack,
			"comm":            comm,
		})
	}, 0)
	return 0
}

//export gadgetStop
func gadgetStop() int {
	cycles := digraph.FindCycles(g)
	if len(cycles) > 0 {
		api.Info("Potential deadlocks detected")
		for cycleIdx, cycle := range cycles {
			api.Infof("Cycle %d:", cycleIdx+1)
			for i, edge := range cycle {
				mutex1 := "0x" + strings.ToUpper(strconv.FormatUint(edge[0], 16))
				mutex2 := "0x" + strings.ToUpper(strconv.FormatUint(edge[1], 16))
				api.Infof("Edge %d: %s -> %s", i+1, mutex1, mutex2)
			}
		}
		return 0
	}
	api.Info("No deadlock detected")
	return 0
}

// The main function is not used, but it's still required by the compiler
func main() {}
