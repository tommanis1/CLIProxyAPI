//go:build linux || darwin || freebsd

package api

import (
	"context"
	"net"
	"syscall"
)

// listenTCP binds with SO_REUSEPORT, so a new core can bind the same port while the old one drains (hot swap).
func listenTCP(addr string) (net.Listener, error) {
	lc := net.ListenConfig{Control: func(_, _ string, conn syscall.RawConn) error {
		var errSet error
		if errControl := conn.Control(func(fd uintptr) {
			errSet = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1)
		}); errControl != nil {
			return errControl
		}
		return errSet
	}}
	return lc.Listen(context.Background(), "tcp", addr)
}
