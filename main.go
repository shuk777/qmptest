package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	"github.com/digitalocean/go-qemu/qmp"
	"github.com/pkg/errors"
)

const (
	certLengthSEV      = 0x824 //certificate length of CEK/PEK
	certLengthAMD      = 1600  //certificate length of ark/ask
	algoSHA256         = 1
	algoECDSASHA256    = 2
	algoRSASHA384      = 0x101
	keyComponentLength = 0x048
	ark                = "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" //AMD Root Key
	ask                = "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" //ask for Rome
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

	cmd := []byte(`{"execute":"query-sev-capabilities"}`)
	raw, _ := monitor.Run(cmd)
	var c capabilities
	json.Unmarshal(raw, &c)
	certChain, _ := base64.StdEncoding.DecodeString(c.Return.CertChain)
	cmd = []byte(`{"execute":"query-sev-attestation-report","arguments":{"mnonce":"ZBaOEOsVmenc5q34VJb9jw=="}}`)
	nonce, _ := base64.StdEncoding.DecodeString("ZBaOEOsVmenc5q34VJb9jw==")
	data, _ := base64.StdEncoding.DecodeString("eyJyZXR1cm4iOiB7ImRhdGEiOiAiWkJhT0VPc1ZtZW5jNXEzNFZKYjlqK2tjVFl0WGZHbDVPcWFVODFWN1VmVzVSbmhXUmJ5Wi9WOHI0Z3lEVGE5UkFRQUFBQUlRQUFBQ0FBQUFBQUFBQUpCNmh5ck9tZUpjZWZtTzJMV2ZEcy8yeGs5eUM4bklyMHU2cEZ3YlNOcFpzeTExYUg5Tk05OWY4MGI1NHRxSWdnQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUM4aUVzOUdQZ0pkcU8weTNIWnN6OGdUYkFLQ2hHWFRmR1RpaTl0ZjgvYmVKTTE5TXovdUE3SVZVcmlkYTMySFVBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE9PSJ9fQ==")
	var attestReport AttestReport
	json.Unmarshal(data, &attestReport)
	d, _ := base64.StdEncoding.DecodeString(attestReport.Return.Data)
	chain, _ := readChain(certChain)
	if err = attestSEV(chain[0], d, nonce); err != nil {
		fmt.Println(err)
	}
	fmt.Println("ok")
	//		fmt.Println(d[0:0x10])
	//	}
}

func readChain(chainBytes []byte) ([][]byte, error) {
	if len(chainBytes) != certLengthSEV*3 {
		return nil, errors.New("invalid cert chain length")
	}
	chain := make([][]byte, 5)
	//cert chain必须严格按照该顺序
	chain[0] = chainBytes[0:certLengthSEV]                   //PEK
	chain[1] = chainBytes[certLengthSEV : certLengthSEV*2]   //OCA
	chain[2] = chainBytes[certLengthSEV*2 : certLengthSEV*3] //CEK
	var err error
	chain[3], err = base64.StdEncoding.DecodeString(ask) //ask
	if err != nil {
		return nil, errors.Wrap(err, "decode ask")
	}
	chain[4], err = base64.StdEncoding.DecodeString(ark) //ark
	if err != nil {
		return nil, errors.Wrap(err, "decode ark")
	}
	return chain, nil
}

func attestSEV(pekCert, report, nonce []byte) error {

	//验证Attestation Report中的mnonce
	if !bytes.Equal(report[0:0x10], nonce) {
		return errors.New("invalid mnonce")
	}

	//验证report中的launch digest与server端config文件中的SEVDigest是否相同

	if int(binary.LittleEndian.Uint16(report[0x38:0x3C])) != algoECDSASHA256 || !bytes.Equal(report[0x34:0x38], pekCert[0x008:0x00C]) {
		return errors.New("invalid signature usage or algorithm")
	}

	//使用PEK公钥验证Attestation Report上的签名
	signedData := report[0:0x34]
	hash := sha256.New()
	hash.Write(signedData)
	hashData := hash.Sum(nil)
	pekPub := unmarshalECPubKey(pekCert[0x010:0x414])
	r, s := unmarshalECSig(report[0x40:0xD0])
	if !ecdsa.Verify(&pekPub, hashData, r, s) {
		return errors.New("invalid signature on attestation report")
	}

	return nil
}

func unmarshalECSig(sig []byte) (r, s *big.Int) {
	//将签名部分转换为ecdsa的格式
	rBytes := sig[0:0x048]
	reversedR := reverse(rBytes)
	sBytes := sig[0x048:0x090]
	reversedS := reverse(sBytes)
	var ri, si big.Int
	return ri.SetBytes(reversedR), si.SetBytes(reversedS)
}

func reverse(origin []byte) []byte {
	n := len(origin)
	s := make([]byte, n)
	for i, j := 0, n-1; i < n; i, j = i+1, j-1 {
		s[j] = origin[i]
	}
	return s
}

func unmarshalECPubKey(key []byte) ecdsa.PublicKey {
	pubX := key[0x004:0x04c]
	pubY := key[0x04c:0x094]
	public := ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X:     unmarshalBytes(pubX),
		Y:     unmarshalBytes(pubY),
	}
	return public
}

func unmarshalBytes(b []byte) *big.Int {
	rb := reverse(b)
	var i big.Int
	return i.SetBytes(rb)
}
