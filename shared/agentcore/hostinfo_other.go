//go:build !linux

package agentcore

import "runtime"

func readKernel() (string, string) {
	switch runtime.GOOS {
	case "darwin":
		return "Darwin", ""
	case "windows":
		return "Windows", ""
	default:
		return runtime.GOOS, ""
	}
}

func readRootDisk() (uint64, uint64)  { return 0, 0 }
func readPrimaryIP() (string, string) { return "", "" }
