//go:build darwin

package main

import (
	"fmt"
	"os/exec"
)

func (c *Client) createTun() error {
	c.tunnelIface = "lo0"
	cmd := exec.Command("ifconfig", "lo0", "alias", "240.0.0.1", "netmask", "255.255.255.0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	fmt.Println("Note: macOS uses loopback alias - use SOCKS proxy for best results")
	return nil
}

func (c *Client) destroyTun() {
	exec.Command("ifconfig", "lo0", "-alias", "240.0.0.1").Run()
}

func (c *Client) addOSRoute(cidr string) error {
	cmd := exec.Command("route", "-n", "add", "-net", cidr, "240.0.0.1")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	return nil
}

func (c *Client) delOSRoute(cidr string) {
	exec.Command("route", "-n", "delete", "-net", cidr).Run()
}
