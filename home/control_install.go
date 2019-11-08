package home

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"

	"github.com/AdguardTeam/golibs/log"
)

type firstRunData struct {
	WebPort    int                    `json:"web_port"`
	DNSPort    int                    `json:"dns_port"`
	Interfaces map[string]interface{} `json:"interfaces"`
}

// Get initial installation settings
func handleInstallGetAddresses(w http.ResponseWriter, r *http.Request) {
	data := firstRunData{}
	data.WebPort = 80
	data.DNSPort = 53

	ifaces, err := getValidNetInterfacesForWeb()
	if err != nil {
		httpError(w, http.StatusInternalServerError, "Couldn't get interfaces: %s", err)
		return
	}

	data.Interfaces = make(map[string]interface{})
	for _, iface := range ifaces {
		data.Interfaces[iface.Name] = iface
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(data)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "Unable to marshal default addresses to json: %s", err)
		return
	}
}

type checkConfigReqEnt struct {
	Port    int    `json:"port"`
	IP      string `json:"ip"`
	Autofix bool   `json:"autofix"`
}
type checkConfigReq struct {
	Web checkConfigReqEnt `json:"web"`
	DNS checkConfigReqEnt `json:"dns"`
}

type checkConfigRespEnt struct {
	Status     string `json:"status"`
	CanAutofix bool   `json:"can_autofix"`
}
type staticIPJSON struct {
	Static string `json:"static"`
	IP     string `json:"ip"`
	Error  string `json:"error"`
}
type checkConfigResp struct {
	Web      checkConfigRespEnt `json:"web"`
	DNS      checkConfigRespEnt `json:"dns"`
	StaticIP staticIPJSON       `json:"static_ip"`
}

// Check if network interface has a static IP configured
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

// Check if ports are available, respond with results
func handleInstallCheckConfig(w http.ResponseWriter, r *http.Request) {
	reqData := checkConfigReq{}
	respData := checkConfigResp{}
	err := json.NewDecoder(r.Body).Decode(&reqData)
	if err != nil {
		httpError(w, http.StatusBadRequest, "Failed to parse 'check_config' JSON data: %s", err)
		return
	}

	if reqData.Web.Port != 0 && reqData.Web.Port != config.BindPort {
		err = checkPortAvailable(reqData.Web.IP, reqData.Web.Port)
		if err != nil {
			respData.Web.Status = fmt.Sprintf("%v", err)
		}
	}

	if reqData.DNS.Port != 0 {
		err = checkPacketPortAvailable(reqData.DNS.IP, reqData.DNS.Port)

		if errorIsAddrInUse(err) {
			canAutofix := checkDNSStubListener()
			if canAutofix && reqData.DNS.Autofix {

				err = disableDNSStubListener()
				if err != nil {
					log.Error("Couldn't disable DNSStubListener: %s", err)
				}

				err = checkPacketPortAvailable(reqData.DNS.IP, reqData.DNS.Port)
				canAutofix = false
			}

			respData.DNS.CanAutofix = canAutofix
		}

		if err == nil {
			err = checkPortAvailable(reqData.DNS.IP, reqData.DNS.Port)
		}

		if err != nil {
			respData.DNS.Status = fmt.Sprintf("%v", err)

		} else {
			// check if we have a static IP
			interfaceName := getInterfaceByIP(reqData.DNS.IP)
			isStaticIP, err := hasStaticIP(interfaceName)
			staticIPStatus := "yes"
			if err != nil {
				staticIPStatus = "error"
				respData.StaticIP.Error = err.Error()
			} else if !isStaticIP {
				staticIPStatus = "no"
				respData.StaticIP.IP = getFullIP(interfaceName)
			}
			respData.StaticIP.Static = staticIPStatus
		}
	}

	w.Header().Set("Content-Type", "application/json")
	err = json.NewEncoder(w).Encode(respData)
	if err != nil {
		httpError(w, http.StatusInternalServerError, "Unable to marshal JSON: %s", err)
		return
	}
}

// Check if DNSStubListener is active
func checkDNSStubListener() bool {
	cmd := exec.Command("systemctl", "is-enabled", "systemd-resolved")
	log.Tracef("executing %s %v", cmd.Path, cmd.Args)
	_, err := cmd.Output()
	if err != nil || cmd.ProcessState.ExitCode() != 0 {
		log.Error("command %s has failed: %v code:%d",
			cmd.Path, err, cmd.ProcessState.ExitCode())
		return false
	}

	cmd = exec.Command("grep", "-E", "#?DNSStubListener=yes", "/etc/systemd/resolved.conf")
	log.Tracef("executing %s %v", cmd.Path, cmd.Args)
	_, err = cmd.Output()
	if err != nil || cmd.ProcessState.ExitCode() != 0 {
		log.Error("command %s has failed: %v code:%d",
			cmd.Path, err, cmd.ProcessState.ExitCode())
		return false
	}

	return true
}

// Deactivate DNSStubListener
func disableDNSStubListener() error {
	cmd := exec.Command("sed", "-r", "-i.orig", "s/#?DNSStubListener=yes/DNSStubListener=no/g", "/etc/systemd/resolved.conf")
	log.Tracef("executing %s %v", cmd.Path, cmd.Args)
	_, err := cmd.Output()
	if err != nil {
		return err
	}
	if cmd.ProcessState.ExitCode() != 0 {
		return fmt.Errorf("process %s exited with an error: %d",
			cmd.Path, cmd.ProcessState.ExitCode())
	}

	cmd = exec.Command("systemctl", "reload-or-restart", "systemd-resolved")
	log.Tracef("executing %s %v", cmd.Path, cmd.Args)
	_, err = cmd.Output()
	if err != nil {
		return err
	}
	if cmd.ProcessState.ExitCode() != 0 {
		return fmt.Errorf("process %s exited with an error: %d",
			cmd.Path, cmd.ProcessState.ExitCode())
	}

	return nil
}

type applyConfigReqEnt struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}
type applyConfigReq struct {
	Web      applyConfigReqEnt `json:"web"`
	DNS      applyConfigReqEnt `json:"dns"`
	Username string            `json:"username"`
	Password string            `json:"password"`
}

// Copy installation parameters between two configuration objects
func copyInstallSettings(dst *configuration, src *configuration) {
	dst.BindHost = src.BindHost
	dst.BindPort = src.BindPort
	dst.DNS.BindHost = src.DNS.BindHost
	dst.DNS.Port = src.DNS.Port
}

// Apply new configuration, start DNS server, restart Web server
func handleInstallConfigure(w http.ResponseWriter, r *http.Request) {
	newSettings := applyConfigReq{}
	err := json.NewDecoder(r.Body).Decode(&newSettings)
	if err != nil {
		httpError(w, http.StatusBadRequest, "Failed to parse 'configure' JSON: %s", err)
		return
	}

	if newSettings.Web.Port == 0 || newSettings.DNS.Port == 0 {
		httpError(w, http.StatusBadRequest, "port value can't be 0")
		return
	}

	restartHTTP := true
	if config.BindHost == newSettings.Web.IP && config.BindPort == newSettings.Web.Port {
		// no need to rebind
		restartHTTP = false
	}

	// validate that hosts and ports are bindable
	if restartHTTP {
		err = checkPortAvailable(newSettings.Web.IP, newSettings.Web.Port)
		if err != nil {
			httpError(w, http.StatusBadRequest, "Impossible to listen on IP:port %s due to %s",
				net.JoinHostPort(newSettings.Web.IP, strconv.Itoa(newSettings.Web.Port)), err)
			return
		}
	}

	err = checkPacketPortAvailable(newSettings.DNS.IP, newSettings.DNS.Port)
	if err != nil {
		httpError(w, http.StatusBadRequest, "%s", err)
		return
	}

	err = checkPortAvailable(newSettings.DNS.IP, newSettings.DNS.Port)
	if err != nil {
		httpError(w, http.StatusBadRequest, "%s", err)
		return
	}

	var curConfig configuration
	copyInstallSettings(&curConfig, &config)

	config.firstRun = false
	config.BindHost = newSettings.Web.IP
	config.BindPort = newSettings.Web.Port
	config.DNS.BindHost = newSettings.DNS.IP
	config.DNS.Port = newSettings.DNS.Port

	initDNSServer()

	err = startDNSServer()
	if err != nil {
		config.firstRun = true
		copyInstallSettings(&config, &curConfig)
		httpError(w, http.StatusInternalServerError, "Couldn't start DNS server: %s", err)
		return
	}

	u := User{}
	u.Name = newSettings.Username
	config.auth.UserAdd(&u, newSettings.Password)

	err = config.write()
	if err != nil {
		config.firstRun = true
		copyInstallSettings(&config, &curConfig)
		httpError(w, http.StatusInternalServerError, "Couldn't write config: %s", err)
		return
	}

	// this needs to be done in a goroutine because Shutdown() is a blocking call, and it will block
	// until all requests are finished, and _we_ are inside a request right now, so it will block indefinitely
	if restartHTTP {
		go func() {
			_ = config.httpServer.Shutdown(context.TODO())
		}()
	}

	returnOK(w)
}

func registerInstallHandlers() {
	http.HandleFunc("/control/install/get_addresses", preInstall(ensureGET(handleInstallGetAddresses)))
	http.HandleFunc("/control/install/check_config", preInstall(ensurePOST(handleInstallCheckConfig)))
	http.HandleFunc("/control/install/configure", preInstall(ensurePOST(handleInstallConfigure)))
}
