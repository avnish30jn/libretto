/*
Copyright (c) 2014-2015 VMware, Inc. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package vm

import (
	"context"
	"flag"

	"github.com/vmware/govmomi/govc/cli"
	"github.com/vmware/govmomi/govc/flags"
<<<<<<< HEAD
	"github.com/vmware/govmomi/object"
)

type markasvm struct {
	*flags.ClientFlag
	*flags.SearchFlag
	*flags.HostSystemFlag
	*flags.ResourcePoolFlag
	HostSystem   *object.HostSystem
	ResourcePool *object.ResourcePool
=======
)

type markasvm struct {
	*flags.SearchFlag
	*flags.ResourcePoolFlag
	*flags.HostSystemFlag
>>>>>>> Update deps for Sep 12 2017
}

func init() {
	cli.Register("vm.markasvm", &markasvm{})
}

func (cmd *markasvm) Register(ctx context.Context, f *flag.FlagSet) {
<<<<<<< HEAD
	cmd.ClientFlag, ctx = flags.NewClientFlag(ctx)
	cmd.ClientFlag.Register(ctx, f)
	cmd.SearchFlag, ctx = flags.NewSearchFlag(ctx, flags.SearchVirtualMachines)
	cmd.SearchFlag.Register(ctx, f)
=======
	cmd.SearchFlag, ctx = flags.NewSearchFlag(ctx, flags.SearchVirtualMachines)
	cmd.SearchFlag.Register(ctx, f)
	cmd.ResourcePoolFlag, ctx = flags.NewResourcePoolFlag(ctx)
	cmd.ResourcePoolFlag.Register(ctx, f)
>>>>>>> Update deps for Sep 12 2017
	cmd.HostSystemFlag, ctx = flags.NewHostSystemFlag(ctx)
	cmd.HostSystemFlag.Register(ctx, f)
}

func (cmd *markasvm) Process(ctx context.Context) error {
<<<<<<< HEAD
	if err := cmd.ClientFlag.Process(ctx); err != nil {
		return err
	}
	if err := cmd.SearchFlag.Process(ctx); err != nil {
=======
	if err := cmd.SearchFlag.Process(ctx); err != nil {
		return err
	}
	if err := cmd.ResourcePoolFlag.Process(ctx); err != nil {
>>>>>>> Update deps for Sep 12 2017
		return err
	}
	if err := cmd.HostSystemFlag.Process(ctx); err != nil {
		return err
	}
	return nil
}

<<<<<<< HEAD
=======
func (cmd *markasvm) Usage() string {
	return "VM..."
}

func (cmd *markasvm) Description() string {
	return `Mark VM template as a virtual machine.

Examples:
  govc vm.markasvm $name -host host1
  govc vm.markasvm $name -pool cluster1/Resources`
}

>>>>>>> Update deps for Sep 12 2017
func (cmd *markasvm) Run(ctx context.Context, f *flag.FlagSet) error {
	vms, err := cmd.VirtualMachines(f.Args())
	if err != nil {
		return err
	}
<<<<<<< HEAD
	cmd.HostSystem, err = cmd.HostSystemFlag.HostSystem()
	if err != nil {
		return err
	}
	cmd.ResourcePool, err = cmd.HostSystem.ResourcePool(ctx)
	if err != nil {
		return err
	}
	for _, vm := range vms {
		err := vm.MarkAsVirtualMachine(ctx, *cmd.ResourcePool, cmd.HostSystem)
=======

	pool, err := cmd.ResourcePoolIfSpecified()
	if err != nil {
		return err
	}

	host, err := cmd.HostSystemFlag.HostSystemIfSpecified()
	if err != nil {
		return err
	}

	if pool == nil {
		if host == nil {
			return flag.ErrHelp
		}

		pool, err = host.ResourcePool(ctx)
		if err != nil {
			return err
		}
	}

	for _, vm := range vms {
		err := vm.MarkAsVirtualMachine(ctx, *pool, host)
>>>>>>> Update deps for Sep 12 2017
		if err != nil {
			return err
		}
	}
<<<<<<< HEAD
=======

>>>>>>> Update deps for Sep 12 2017
	return nil
}
