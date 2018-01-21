// Copyright 2015 Apcera Inc. All rights reserved.

// +build windows, amd64

package vmrun

import (
	"os"
	"path/filepath"
)

// VMRunPath is default path to vmrun to fallback when it is not on path.
var VMRunPath string

// VMwareProducts define VMware products those contain vmrun.exe in Windows.
var VMwareProducts = [3]string{"VMware Workstation", "VMware Player", "VMware VIX"}

func init() {
	for _, products := range VMwareProducts {
		path := filepath.Join(os.Getenv("ProgramFiles(x86)"), "VMware", products, "vmrun.exe")
		if _, err := os.Stat(path); err == nil {
			VMRunPath = path
			break
		}
	}
}
