/*
<<<<<<< HEAD
Copyright (c) 2016 VMware, Inc. All Rights Reserved.
=======
Copyright (c) 2016-2017 VMware, Inc. All Rights Reserved.
>>>>>>> Update deps for Sep 12 2017

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

package option

import (
	"context"
	"flag"
<<<<<<< HEAD
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/vmware/govmomi/govc/cli"
	"github.com/vmware/govmomi/govc/flags"
	"github.com/vmware/govmomi/vim25/types"
)

type ls struct {
	*flags.ClientFlag
	*flags.OutputFlag
=======

	"github.com/vmware/govmomi/govc/cli"
	"github.com/vmware/govmomi/govc/flags"
	"github.com/vmware/govmomi/govc/option"
)

type ls struct {
	*option.List
>>>>>>> Update deps for Sep 12 2017
	*flags.HostSystemFlag
}

func init() {
	cli.Register("host.option.ls", &ls{})
}

func (cmd *ls) Register(ctx context.Context, f *flag.FlagSet) {
<<<<<<< HEAD
	cmd.ClientFlag, ctx = flags.NewClientFlag(ctx)
	cmd.ClientFlag.Register(ctx, f)

	cmd.OutputFlag, ctx = flags.NewOutputFlag(ctx)
	cmd.OutputFlag.Register(ctx, f)
=======
	cmd.List = &option.List{}
	cmd.List.ClientFlag, ctx = flags.NewClientFlag(ctx)
	cmd.List.ClientFlag.Register(ctx, f)

	cmd.List.OutputFlag, ctx = flags.NewOutputFlag(ctx)
	cmd.List.OutputFlag.Register(ctx, f)
>>>>>>> Update deps for Sep 12 2017

	cmd.HostSystemFlag, ctx = flags.NewHostSystemFlag(ctx)
	cmd.HostSystemFlag.Register(ctx, f)
}

func (cmd *ls) Process(ctx context.Context) error {
<<<<<<< HEAD
	if err := cmd.ClientFlag.Process(ctx); err != nil {
		return err
	}
	if err := cmd.OutputFlag.Process(ctx); err != nil {
=======
	if err := cmd.List.Process(ctx); err != nil {
>>>>>>> Update deps for Sep 12 2017
		return err
	}
	if err := cmd.HostSystemFlag.Process(ctx); err != nil {
		return err
	}
	return nil
}

<<<<<<< HEAD
func (cmd *ls) Usage() string {
	return "NAME"
}

func (cmd *ls) Description() string {
	return `List option with the given NAME.

If NAME ends with a dot, all options for that subtree are listed.`
}

func (cmd *ls) Run(ctx context.Context, f *flag.FlagSet) error {
	if f.NArg() != 1 {
		return flag.ErrHelp
	}

=======
func (cmd *ls) Description() string {
	return option.ListDescription + `

Examples:
  govc host.option.ls
  govc host.option.ls Config.HostAgent.
  govc host.option.ls Config.HostAgent.plugins.solo.enableMob`
}

func (cmd *ls) Run(ctx context.Context, f *flag.FlagSet) error {
>>>>>>> Update deps for Sep 12 2017
	host, err := cmd.HostSystem()
	if err != nil {
		return err
	}

	m, err := host.ConfigManager().OptionManager(ctx)
	if err != nil {
		return err
	}

<<<<<<< HEAD
	opts, err := m.Query(ctx, f.Arg(0))
	if err != nil {
		return err
	}

	return cmd.WriteResult(optionResult(opts))
}

type optionResult []types.BaseOptionValue

func (r optionResult) Write(w io.Writer) error {
	tw := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
	for _, opt := range r {
		o := opt.GetOptionValue()
		fmt.Fprintf(tw, "%s:\t%v\n", o.Key, o.Value)
	}
	return tw.Flush()
=======
	return cmd.Query(ctx, f, m)
>>>>>>> Update deps for Sep 12 2017
}
