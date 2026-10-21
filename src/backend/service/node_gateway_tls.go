package service

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/c1ayooo/4zreark/config"
)

// NodeGatewayTLS 是节点专用 HTTPS 监听所需的证书信息。
// CAPEM 会被一键部署上传到 worker，让 worker 校验自签网关证书。
type NodeGatewayTLS struct {
	CertFile string
	KeyFile  string
	CAPEM    []byte
}

// EnsureNodeGatewayTLS 准备节点网关证书：优先用配置的 cert/key；
// 否则在 tls_dir 下生成一张自签证书（只生成一次）。
func EnsureNodeGatewayTLS(cfg *config.NodeConfig) (*NodeGatewayTLS, error) {
	if cfg == nil {
		return nil, fmt.Errorf("节点配置为空")
	}
	if (cfg.TLSCert == "") != (cfg.TLSKey == "") {
		return nil, fmt.Errorf("node.tls_cert 和 node.tls_key 必须同时配置")
	}
	if cfg.TLSCert != "" {
		certPEM, err := os.ReadFile(cfg.TLSCert)
		if err != nil {
			return nil, fmt.Errorf("读取节点网关证书失败: %w", err)
		}
		caPEM := certPEM
		if cfg.TLSCA != "" {
			caPEM, err = os.ReadFile(cfg.TLSCA)
			if err != nil {
				return nil, fmt.Errorf("读取节点网关 CA 失败: %w", err)
			}
		}
		return &NodeGatewayTLS{CertFile: cfg.TLSCert, KeyFile: cfg.TLSKey, CAPEM: caPEM}, nil
	}

	dir := cfg.TLSDir
	if dir == "" {
		dir = "data/node-tls"
	}
	certFile := filepath.Join(dir, "node-gateway.crt")
	keyFile := filepath.Join(dir, "node-gateway.key")
	if _, err := os.Stat(certFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			certPEM, rerr := os.ReadFile(certFile)
			if rerr != nil {
				return nil, rerr
			}
			return &NodeGatewayTLS{CertFile: certFile, KeyFile: keyFile, CAPEM: certPEM}, nil
		}
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("创建节点 TLS 目录失败: %w", err)
	}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("生成节点网关私钥失败: %w", err)
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()
	dnsNames := []string{"localhost"}
	ipAddrs := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if hostname != "" {
		dnsNames = append(dnsNames, hostname)
	}
	if cfg.GatewayHost != "" {
		if ip := net.ParseIP(cfg.GatewayHost); ip != nil {
			ipAddrs = append(ipAddrs, ip)
		} else {
			dnsNames = append(dnsNames, cfg.GatewayHost)
		}
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				ipAddrs = append(ipAddrs, ipNet.IP)
			}
		}
	}

	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "4zreark-node-gateway"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              dnsNames,
		IPAddresses:           ipAddrs,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("签发节点网关证书失败: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		return nil, err
	}
	return &NodeGatewayTLS{CertFile: certFile, KeyFile: keyFile, CAPEM: certPEM}, nil
}
