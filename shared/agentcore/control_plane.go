package agentcore

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// MaxControlPlaneEndpoints mirrors MAX_CP_ENDPOINTS in wafio_common.h.
const MaxControlPlaneEndpoints = 16

// SplitControlPlaneAddr parses the --grpc-server value ("host:port",
// "[v6]:port", optionally with a gRPC "dns:///" scheme).
func SplitControlPlaneAddr(serverAddr string) (string, uint16, error) {
	addr := strings.TrimSpace(serverAddr)
	if i := strings.LastIndex(addr, "://"); i >= 0 {
		addr = addr[i+3:]
		addr = strings.TrimPrefix(addr, "/")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 || host == "" {
		return "", 0, fmt.Errorf("control-plane address %q has no usable host:port", serverAddr)
	}
	return host, uint16(port), nil
}

type LookupNetIPFunc func(ctx context.Context, network, host string) ([]netip.Addr, error)

// ResolveControlPlaneEndpoints turns the configured address into at most
// MaxControlPlaneEndpoints unique TCP endpoints.
func ResolveControlPlaneEndpoints(ctx context.Context, serverAddr string, lookup LookupNetIPFunc) ([]netip.AddrPort, error) {
	host, port, err := SplitControlPlaneAddr(serverAddr)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		addrs, err = lookup(lctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	seen := make(map[netip.Addr]bool)
	var out []netip.AddrPort
	for _, a := range addrs {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || a.IsUnspecified() || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, netip.AddrPortFrom(a, port))
		if len(out) == MaxControlPlaneEndpoints {
			break
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("control-plane address %q resolved to no usable address", host)
	}
	return out, nil
}
