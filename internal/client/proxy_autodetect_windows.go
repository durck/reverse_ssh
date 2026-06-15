//go:build windows

package client

import (
	"fmt"

	"golang.org/x/sys/windows/registry"
)

const winINETInternetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

// DetectSystemProxy reads the WinINET proxy configuration from the current
// user's registry hive (HKCU\...\Internet Settings) and returns a proxy URL
// usable by Connect/GetProxyDetails.
//
// Only the manual ProxyServer value is honoured. ProxyEnable=0 is treated as
// "no proxy". AutoConfigURL (PAC) and AutoDetect (WPAD) are intentionally not
// consulted in this implementation.
//
// An empty return value with nil error means "no proxy configured".
func DetectSystemProxy() (string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, winINETInternetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return "", fmt.Errorf("open HKCU\\%s: %w", winINETInternetSettingsKey, err)
	}
	defer k.Close()

	enable, _, err := k.GetIntegerValue("ProxyEnable")
	if err != nil && err != registry.ErrNotExist {
		return "", fmt.Errorf("read ProxyEnable: %w", err)
	}
	if enable != 1 {
		return "", nil
	}

	server, _, err := k.GetStringValue("ProxyServer")
	if err == registry.ErrNotExist {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read ProxyServer: %w", err)
	}

	return parseWinINETProxyString(server), nil
}
