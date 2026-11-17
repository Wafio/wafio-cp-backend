//go:build linux

package agentcore

import (
	"net"
	"syscall"
)

func readKernel() (string, string) {
	var u syscall.Utsname
	if err := syscall.Uname(&u); err != nil {
		return "Linux", ""
	}
	return int8ToString(u.Sysname[:]), int8ToString(u.Release[:])
}

func int8ToString(in []int8) string {
	b := make([]byte, 0, len(in))
	for _, c := range in {
		if c == 0 {
			break
		}
		b = append(b, byte(c)) //nolint:gosec // G115: reinterprets the C char as a raw byte
	}
	return string(b)
}

func readRootDisk() (uint64, uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err != nil {
		return 0, 0
	}
	total := uint64(st.Blocks) * NonNegUint64(st.Bsize)
	free := uint64(st.Bavail) * NonNegUint64(st.Bsize)
	return total, free
}

func readPrimaryIP() (string, string) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", ""
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			var ip net.IP
			switch v := a.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if ip4 := ip.To4(); ip4 != nil {
				return ip4.String(), ifc.Name
			}
		}
	}
	return "", ""
}
