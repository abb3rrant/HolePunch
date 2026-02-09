//go:build !linux && !darwin

package main

import "fmt"

func (c *Client) createTun() error {
	return fmt.Errorf("TUN mode not supported on this platform. Use SOCKS5 instead:\n  > socks start\n  $ proxychains nmap -sT <target>")
}

func (c *Client) destroyTun() {
	// No-op on unsupported platforms
}

func (c *Client) addOSRoute(cidr string) error {
	return fmt.Errorf("routing not supported on this platform")
}

func (c *Client) delOSRoute(cidr string) {
	// No-op on unsupported platforms
}
