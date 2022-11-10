package main

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/digitalocean/go-qemu/qmp"
)

func main() {
	monitor, err := qmp.NewSocketMonitor("tcp", "10.0.2.2:4444", 2*time.Second)
	if err != nil {
		fmt.Println(err)
	}
	monitor.Connect()
	defer monitor.Disconnect()

	cmd := []byte(`{"execute":"query-sev-attestation-report","arguments":{"mnonce":"ZBaOEOsVmenc5q34VJb9jw=="}}`)
	raw, _ := monitor.Run(cmd)
	fmt.Println(base64.StdEncoding.EncodeToString(raw))
}
