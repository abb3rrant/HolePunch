//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"
)

func (c *Client) createTun() error {
	c.tunnelIface = "holepunch0"

	fd, err := syscall.Open("/dev/net/tun", syscall.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open /dev/net/tun: %v (run with sudo)", err)
	}

	var ifr [40]byte
	copy(ifr[:16], c.tunnelIface)
	// IFF_TUN | IFF_NO_PI
	ifr[16] = 0x01
	ifr[17] = 0x10

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x400454ca, uintptr(unsafe.Pointer(&ifr[0])))
	if errno != 0 {
		syscall.Close(fd)
		return fmt.Errorf("ioctl TUNSETIFF: %v", errno)
	}

	c.tunFile = os.NewFile(uintptr(fd), "/dev/net/tun")

	cmd := exec.Command("ip", "addr", "add", "240.0.0.1/24", "dev", c.tunnelIface)
	if out, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "exists") {
			c.tunFile.Close()
			return fmt.Errorf("ip addr: %v: %s", err, out)
		}
	}

	exec.Command("ip", "link", "set", "dev", c.tunnelIface, "mtu", "1400").Run()

	cmd = exec.Command("ip", "link", "set", "dev", c.tunnelIface, "up")
	if out, err := cmd.CombinedOutput(); err != nil {
		c.tunFile.Close()
		return fmt.Errorf("ip link up: %v: %s", err, out)
	}

	return nil
}

func (c *Client) destroyTun() {
	if c.tunFile != nil {
		c.tunFile.Close()
		c.tunFile = nil
	}
	exec.Command("ip", "link", "set", "dev", c.tunnelIface, "down").Run()
	exec.Command("ip", "link", "del", "dev", c.tunnelIface).Run()
}

func (c *Client) addOSRoute(cidr string) error {
	cmd := exec.Command("ip", "route", "add", cidr, "dev", c.tunnelIface)
	if out, err := cmd.CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "exist") {
			return fmt.Errorf("%v: %s", err, out)
		}
	}
	return nil
}

func (c *Client) delOSRoute(cidr string) {
	exec.Command("ip", "route", "del", cidr).Run()
}
