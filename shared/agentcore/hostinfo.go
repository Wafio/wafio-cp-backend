package agentcore

import (
	"bufio"
	"math"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────────
// Host information reported by the agent.
//
// Every eBPF/WAF agent attaches a small HostInfo block to its push payload so
// the control plane can show operators what's actually running where —
// hostname, OS, kernel, CPU count, total memory, uptime, and the agent
// version. Collected once at startup (values that don't change) plus a
// refresh on each push (uptime, memory, load).
// ──────────────────────────────────────────────────────────────────────────────

type HostInfo struct {
	Hostname     string  `json:"hostname"`
	OS           string  `json:"os"`             // "linux", "darwin"
	OSVersion    string  `json:"os_version"`     // e.g. "Ubuntu 24.04 LTS"
	KernelName   string  `json:"kernel_name"`    // "Linux"
	KernelRel    string  `json:"kernel_release"` // "6.8.0-41-generic"
	Arch         string  `json:"arch"`           // "amd64", "arm64"
	CPUCount     int     `json:"cpu_count"`
	CPUModel     string  `json:"cpu_model,omitempty"`
	CPUMHz       float64 `json:"cpu_mhz,omitempty"`
	MemoryTotal  uint64  `json:"memory_total_bytes"`
	MemoryUsed   uint64  `json:"memory_used_bytes,omitempty"`
	MemoryFree   uint64  `json:"memory_free_bytes,omitempty"`
	LoadAvg1     float64 `json:"load_avg_1,omitempty"`
	LoadAvg5     float64 `json:"load_avg_5,omitempty"`
	LoadAvg15    float64 `json:"load_avg_15,omitempty"`
	UptimeSec    int64   `json:"uptime_seconds"`
	BootTime     int64   `json:"boot_time"`
	AgentVersion string  `json:"agent_version"`
	AgentKind    string  `json:"agent_kind"`
	Distro       string  `json:"distro,omitempty"`
	DistroLike   string  `json:"distro_like,omitempty"`
	VirtType     string  `json:"virt_type,omitempty"`
	PublicIP     string  `json:"public_ip,omitempty"`

	// Extended fields (best-effort, Linux-focused)
	Timezone         string `json:"timezone,omitempty"`
	DiskTotalBytes   uint64 `json:"disk_total_bytes,omitempty"`
	DiskFreeBytes    uint64 `json:"disk_free_bytes,omitempty"`
	PrimaryIP        string `json:"primary_ip,omitempty"`
	PrimaryInterface string `json:"primary_interface,omitempty"`
	SELinuxMode      string `json:"selinux_mode,omitempty"`
	AppArmorEnabled  string `json:"apparmor,omitempty"`
	BPFLSMEnabled    string `json:"bpf_lsm,omitempty"`
	ContainerRuntime string `json:"container_runtime,omitempty"`

	// Process and installation metadata
	BinaryPath  string `json:"binary_path,omitempty"`
	InstallDir  string `json:"install_dir,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	ServiceUser string `json:"service_user,omitempty"`

	// SSHPorts: TCP ports sshd listens on (host agent only). The control
	// plane's firewall lockout guard requires an ingress ALLOW for one of
	// them; absent means "unknown" and the guard assumes 22.
	SSHPorts []uint16 `json:"ssh_ports,omitempty"`

	// FirewallFeatures: optional host firewall capabilities (host agent
	// only). "geo_allow": the XDP object and a GeoIP country dataset can
	// enforce geo allow mode; the control plane refuses to switch a host
	// to allow mode without it.
	FirewallFeatures []string `json:"firewall_features,omitempty"`
}

var (
	hostInfoOnce   sync.Once
	hostInfoStatic HostInfo
)

// CollectHostInfo returns a fresh snapshot for an agent of the given kind and
// version. Immutable fields are cached after the first call; mutable ones
// (uptime, memory used, load) are re-read. The host agent adds SSHPorts and
// FirewallFeatures itself.
func CollectHostInfo(kind, version string) HostInfo {
	hostInfoOnce.Do(func() {
		hostInfoStatic = collectStaticHostInfo(version)
	})
	info := hostInfoStatic
	info.AgentKind = kind
	info.UptimeSec = time.Now().Unix() - info.BootTime
	info.MemoryUsed, info.LoadAvg1, info.LoadAvg5, info.LoadAvg15 = readDynamicStats()
	info.MemoryFree = readMemAvailable()
	info.DiskTotalBytes, info.DiskFreeBytes = readRootDisk()
	info.PrimaryIP, info.PrimaryInterface = readPrimaryIP()
	return info
}

func collectStaticHostInfo(version string) HostInfo {
	h, _ := os.Hostname()
	info := HostInfo{
		Hostname:     h,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		CPUCount:     runtime.NumCPU(),
		AgentVersion: version,
	}
	info.KernelName, info.KernelRel = readKernel()
	info.OSVersion = readOSVersion()
	info.CPUModel = readCPUModel()
	info.CPUMHz = readCPUMHz()
	info.MemoryTotal = readMemTotal()
	info.BootTime = readBootTime()
	info.Distro, info.DistroLike = readDistro()
	info.VirtType = detectVirt()
	info.Timezone = readTimezone()
	info.SELinuxMode = readSELinux()
	info.AppArmorEnabled = readAppArmor()
	info.BPFLSMEnabled = readBPFLSM()
	info.ContainerRuntime = detectContainerRuntime()

	if exe, err := os.Executable(); err == nil {
		if realExe, err := filepath.EvalSymlinks(exe); err == nil {
			info.BinaryPath = realExe
		} else {
			info.BinaryPath = exe
		}
		info.InstallDir = filepath.Dir(info.BinaryPath)
	}
	if u, err := user.Current(); err == nil {
		info.ServiceUser = u.Username
	}
	info.ServiceName = detectServiceName()

	return info
}

func detectServiceName() string {
	// 1. Check systemd cgroup on Linux (e.g. "0::/system.slice/wafio-waf-agent.service")
	if data, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, ".service") {
				idx := strings.LastIndex(line, "/")
				if idx >= 0 {
					unit := line[idx+1:]
					if strings.HasSuffix(unit, ".service") {
						return unit
					}
				}
			}
		}
	}
	// 2. Check systemd invocation or unit environment variable
	if unit := os.Getenv("SYSTEMD_UNIT"); unit != "" {
		return unit
	}
	return ""
}

func readOSVersion() string {
	if runtime.GOOS != "linux" {
		return runtime.GOOS + " " + runtime.GOARCH
	}
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }() // read-only file
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}

func readDistro() (string, string) {
	if runtime.GOOS != "linux" {
		return "", ""
	}
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "", ""
	}
	defer func() { _ = f.Close() }() // read-only file
	var id, idLike string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		}
		if strings.HasPrefix(line, "ID_LIKE=") {
			idLike = strings.Trim(strings.TrimPrefix(line, "ID_LIKE="), `"`)
		}
	}
	return id, idLike
}

func readCPUModel() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }() // read-only file
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "model name") {
			i := strings.Index(line, ":")
			if i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

func readMemTotal() uint64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }() // read-only file
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemTotal:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return parseUint(fields[1]) * 1024
			}
		}
	}
	return 0
}

func readDynamicStats() (memUsed uint64, l1, l5, l15 float64) {
	if runtime.GOOS != "linux" {
		return 0, 0, 0, 0
	}
	if f, err := os.Open("/proc/meminfo"); err == nil {
		defer func() { _ = f.Close() }() // read-only file
		var total, available uint64
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := sc.Text()
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			v := parseUint(fields[1])
			switch {
			case strings.HasPrefix(line, "MemTotal:"):
				total = v * 1024
			case strings.HasPrefix(line, "MemAvailable:"):
				available = v * 1024
			}
			if total > 0 && available > 0 {
				break
			}
		}
		if total > available {
			memUsed = total - available
		}
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		parts := strings.Fields(string(b))
		if len(parts) >= 3 {
			l1 = parseFloat(parts[0])
			l5 = parseFloat(parts[1])
			l15 = parseFloat(parts[2])
		}
	}
	return
}

func parseUint(s string) uint64 {
	var v uint64
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		v = v*10 + uint64(c-'0')
	}
	return v
}

func parseFloat(s string) float64 {
	var f float64
	var frac float64 = 1
	seenDot := false
	neg := false
	for i, c := range s {
		if i == 0 && c == '-' {
			neg = true
			continue
		}
		if c == '.' {
			seenDot = true
			continue
		}
		if c < '0' || c > '9' {
			break
		}
		if seenDot {
			frac *= 10
			f += float64(c-'0') / frac
		} else {
			f = f*10 + float64(c-'0')
		}
	}
	if neg {
		f = -f
	}
	return f
}

func readBootTime() int64 {
	if runtime.GOOS != "linux" {
		return time.Now().Unix()
	}
	f, err := os.Open("/proc/stat")
	if err != nil {
		return time.Now().Unix()
	}
	defer func() { _ = f.Close() }() // read-only file
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "btime") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return int64(min(parseUint(fields[1]), math.MaxInt64)) //nolint:gosec // G115: clamped to MaxInt64
			}
		}
	}
	return time.Now().Unix()
}

func detectVirt() string {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	if b, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(b)
		switch {
		case strings.Contains(s, "docker"):
			return "docker"
		case strings.Contains(s, "kubepods"):
			return "kubernetes"
		case strings.Contains(s, "lxc"):
			return "lxc"
		}
	}
	if b, err := os.ReadFile("/sys/class/dmi/id/sys_vendor"); err == nil {
		s := strings.TrimSpace(strings.ToLower(string(b)))
		switch {
		case strings.Contains(s, "qemu"), strings.Contains(s, "kvm"):
			return "kvm"
		case strings.Contains(s, "vmware"):
			return "vmware"
		case strings.Contains(s, "xen"):
			return "xen"
		case strings.Contains(s, "microsoft"):
			return "hyperv"
		case strings.Contains(s, "amazon ec2"):
			return "ec2"
		case strings.Contains(s, "google"):
			return "gcp"
		}
	}
	if out, err := exec.Command("systemd-detect-virt").Output(); err == nil {
		v := strings.TrimSpace(string(out))
		if v != "" && v != "none" {
			return v
		}
		if v == "none" {
			return "bare-metal"
		}
	}
	if _, err := os.Stat("/sys/class/dmi/id/sys_vendor"); err == nil {
		return "bare-metal"
	}
	return ""
}

// ── Extended readers ──────────────────────────────────────────────────────────

func readTimezone() string {
	if b, err := os.ReadFile("/etc/timezone"); err == nil {
		s := strings.TrimSpace(string(b))
		if s != "" {
			return s
		}
	}
	if link, err := os.Readlink("/etc/localtime"); err == nil {
		if idx := strings.Index(link, "zoneinfo/"); idx >= 0 {
			return link[idx+len("zoneinfo/"):]
		}
	}
	if tz, _ := time.Now().Zone(); tz != "" {
		return tz
	}
	return ""
}

func readCPUMHz() float64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }() // read-only file
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "cpu MHz") {
			if i := strings.Index(line, ":"); i >= 0 {
				return parseFloat(strings.TrimSpace(line[i+1:]))
			}
		}
	}
	return 0
}

func readMemAvailable() uint64 {
	if runtime.GOOS != "linux" {
		return 0
	}
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }() // read-only file
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "MemAvailable:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return parseUint(fields[1]) * 1024
			}
		}
	}
	return 0
}

func readSELinux() string {
	if b, err := os.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		switch strings.TrimSpace(string(b)) {
		case "1":
			return "enforcing"
		case "0":
			return "permissive"
		}
	}
	if _, err := os.Stat("/sys/fs/selinux"); err == nil {
		return "disabled"
	}
	return "not-installed"
}

func readAppArmor() string {
	if _, err := os.Stat("/sys/kernel/security/apparmor"); err == nil {
		if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err == nil {
			switch strings.TrimSpace(string(b)) {
			case "Y", "y":
				return "enabled"
			case "N", "n":
				return "disabled"
			}
		}
		return "enabled"
	}
	return "not-installed"
}

func readBPFLSM() string {
	if b, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		s := string(b)
		if strings.Contains(s, "bpf") {
			return "enabled"
		}
		return "disabled"
	}
	return "unknown"
}

func detectContainerRuntime() string {
	paths := []struct {
		path string
		name string
	}{
		{"/var/run/docker.sock", "docker"},
		{"/run/containerd/containerd.sock", "containerd"},
		{"/run/crio/crio.sock", "cri-o"},
		{"/run/podman/podman.sock", "podman"},
	}
	for _, p := range paths {
		if _, err := os.Stat(p.path); err == nil {
			return p.name
		}
	}
	return "none"
}
