package main

import (
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

	// cmd := []byte(`{"execute":"query-sev-attestation-report","arguments":{"mnonce":"ZBaOEOsVmenc5q34VJb9jw=="}}`)
	cmd := []byte(`{"execute":"query-sev-capabilities"}`)
	raw, _ := monitor.Run(cmd)
	var c capabilities
	json.Unmarshal(raw, &c)
	fmt.Println(c.Return.CertChain)
	//		mnonce, _ := base64.StdEncoding.DecodeString("ZBaOEOsVmenc5q34VJb9jw==")
	//		data, _ := base64.StdEncoding.DecodeString("eyJyZXR1cm4iOiB7ImRhdGEiOiAiWkJhT0VPc1ZtZW5jNXEzNFZKYjlqK2tjVFl0WGZHbDVPcWFVODFWN1VmVzVSbmhXUmJ5Wi9WOHI0Z3lEVGE5UkFRQUFBQUlRQUFBQ0FBQUFBQUFBQUpCNmh5ck9tZUpjZWZtTzJMV2ZEcy8yeGs5eUM4bklyMHU2cEZ3YlNOcFpzeTExYUg5Tk05OWY4MGI1NHRxSWdnQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUM4aUVzOUdQZ0pkcU8weTNIWnN6OGdUYkFLQ2hHWFRmR1RpaTl0ZjgvYmVKTTE5TXovdUE3SVZVcmlkYTMySFVBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE9PSJ9fQ==")
	//		var attestReport AttestReport
	//		json.Unmarshal(data, &attestReport)
	//		fmt.Println(mnonce)
	//		d, _ := base64.StdEncoding.DecodeString(attestReport.Return.Data)
	//		fmt.Println(d[0:0x10])
	//	}
}
