package home

import (
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os/exec"
	"runtime"
	"strings"

	"github.com/AdguardTeam/golibs/file"
	"github.com/AdguardTeam/golibs/log"
)

// Check if network interface has a static IP configured
// Supports: Raspbian.
func hasStaticIP(ifaceName string) (bool, error) {
	if runtime.GOOS == "windows" {
		return false, errors.New("Can't detect static IP: not supported on Windows")
	}

	body, err := ioutil.ReadFile("/etc/dhcpcd.conf")
	if err != nil {
		return false, err
	}
	lines := strings.Split(string(body), "\n")
	nameLine := fmt.Sprintf("interface %s", ifaceName)
	withinInterfaceCtx := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if withinInterfaceCtx && len(line) == 0 {
			// an empty line resets our state
			withinInterfaceCtx = false
		}

		if len(line) == 0 || line[0] == '#' {
			continue
		}
		line = strings.TrimSpace(line)

		if !withinInterfaceCtx {
			if line == nameLine {
				// we found our interface
				withinInterfaceCtx = true
			}

		} else {
			if strings.HasPrefix(line, "interface ") {
				// we found another interface - reset our state
				withinInterfaceCtx = false
				continue
			}
			if strings.HasPrefix(line, "static ip_address=") {
				return true, nil
			}
		}
	}

	return false, nil
}

// Get IP address with netmask
func getFullIP(ifaceName string) string {
	cmd := exec.Command("ip", "-oneline", "-family", "inet", "address", "show", ifaceName)
	log.Tracef("executing %s %v", cmd.Path, cmd.Args)
	d, err := cmd.Output()
	if err != nil || cmd.ProcessState.ExitCode() != 0 {
		return ""
	}

	fields := strings.Fields(string(d))
	if len(fields) < 4 {
		return ""
	}
	_, _, err = net.ParseCIDR(fields[3])
	if err != nil {
		return ""
	}

	return fields[3]
}

// Get interface name by its IP address.
func getInterfaceByIP(ip string) string {
	ifaces, err := getValidNetInterfacesForWeb()
	if err != nil {
		return ""
	}

	for _, iface := range ifaces {
		for _, addr := range iface.Addresses {
			if ip == addr {
				return iface.Name
			}
		}
	}

	return ""
}

// Get gateway IP address
func getGatewayIP(ifaceName string) string {
	cmd := exec.Command("ip", "route", "show", "dev", ifaceName)
	log.Tracef("executing %s %v", cmd.Path, cmd.Args)
	d, err := cmd.Output()
	if err != nil || cmd.ProcessState.ExitCode() != 0 {
		return ""
	}

	fields := strings.Fields(string(d))
	if len(fields) < 3 || fields[0] != "default" {
		return ""
	}

	ip := net.ParseIP(fields[2])
	if ip == nil {
		return ""
	}

	return fields[2]
}

// Set a static IP for network interface
// Supports: Raspbian.
func setStaticIP(ifaceName string) error {
	ip := getFullIP(ifaceName)
	if len(ip) == 0 {
		return errors.New("Can't get IP address")
	}

	body, err := ioutil.ReadFile("/etc/dhcpcd.conf")
	if err != nil {
		return err
	}

	ip4, _, err := net.ParseCIDR(ip)
	if err != nil {
		return err
	}

	add := fmt.Sprintf("\ninterface %s\nstatic ip_address=%s\n",
		ifaceName, ip)
	body = append(body, []byte(add)...)

	gatewayIP := getGatewayIP(ifaceName)
	if len(gatewayIP) != 0 {
		add = fmt.Sprintf("static routers=%s\n",
			gatewayIP)
		body = append(body, []byte(add)...)
	}

	add = fmt.Sprintf("static domain_name_servers=%s\n\n",
		ip4)
	body = append(body, []byte(add)...)

	err = file.SafeWrite("/etc/dhcpcd.conf", body)
	if err != nil {
		return err
	}

	return nil
}
