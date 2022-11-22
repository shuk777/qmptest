package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/digitalocean/go-qemu/qmp"
)

type AttestReport struct {
	// Returns     string `json:"id"`
	Return struct {
		Data string `json:"data"`
	} `json:"return"`
}

type capabilities struct {
	Return struct {
		PDH       string `json:"pdh"`
		CertChain string `json:"cert-chain"`
		CpuId     string `json:"cpu0-id"`
		Cbit      int    `json:"cbitpos"`
		Reduced   int    `json:"reduced-phys-bits"`
	} `json:"return"`
}

func main() {
	monitor, err := qmp.NewSocketMonitor("tcp", "10.0.2.2:4444", 2*time.Second)
	if err != nil {
		fmt.Println(err)
	}
	monitor.Connect()
	defer monitor.Disconnect()

	cmd := []byte(`{"execute":"query-sev-attestation-report","arguments":{"mnonce":"ZBaOEOsVmenc5q34VJb9jw=="}}`)
	raw, _ := monitor.Run(cmd)

	var attestReport AttestReport
	json.Unmarshal(raw, &attestReport)
	d, _ := base64.StdEncoding.DecodeString(attestReport.Return.Data)
	fmt.Println(d)
}
