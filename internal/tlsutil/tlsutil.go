package tlsutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var (
	certCacheMu sync.Mutex
	cachedCert  *tls.Certificate
)

// GenerateSelfSignedCert generates an RSA 2048-bit self-signed X.509 certificate and private key.
// If certFile and keyFile are non-empty, the PEM encoded certificate and key are saved to disk.
func GenerateSelfSignedCert(certFile, keyFile string, extraHosts ...string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate RSA private key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now().Add(-1 * time.Hour)
	notAfter := notBefore.Add(10 * 365 * 24 * time.Hour) // 10 years validity

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Honeygo Honeypot Cluster"},
			CommonName:   "Honeygo Security Appliance",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Add default SANs: localhost and loopback IPs
	dnsNames := []string{"localhost"}
	ipAddresses := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}

	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		dnsNames = append(dnsNames, hostname)
	}

	// Add local interface IP addresses to SANs so connecting via LAN IP is valid
	if ifaces, err := net.Interfaces(); err == nil {
		for _, iface := range ifaces {
			if addrs, err := iface.Addrs(); err == nil {
				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}
					if ip != nil && !ip.IsLoopback() {
						ipAddresses = append(ipAddresses, ip)
					}
				}
			}
		}
	}

	// Add any extra hosts passed in
	for _, h := range extraHosts {
		if ip := net.ParseIP(h); ip != nil {
			ipAddresses = append(ipAddresses, ip)
		} else if h != "" {
			dnsNames = append(dnsNames, h)
		}
	}

	template.DNSNames = dnsNames
	template.IPAddresses = ipAddresses

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	if certFile != "" && keyFile != "" {
		if err := os.MkdirAll(filepath.Dir(certFile), 0700); err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to create cert directory: %w", err)
		}
		if err := os.MkdirAll(filepath.Dir(keyFile), 0700); err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to create key directory: %w", err)
		}
		if err := os.WriteFile(certFile, certPEM, 0644); err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to write cert file %s: %w", certFile, err)
		}
		if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
			return tls.Certificate{}, fmt.Errorf("failed to write key file %s: %w", keyFile, err)
		}
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load generated X509 key pair: %w", err)
	}

	return tlsCert, nil
}

// LoadCertsFromDir searches a directory (default "./certs") for server certificate and private key files.
// If not found, it returns an error stating that the cert and key were not found in ./certs/.
func LoadCertsFromDir(dir string) (tls.Certificate, error) {
	if dir == "" {
		dir = "certs"
	}

	certCandidates := []string{
		filepath.Join(dir, "server.crt"),
		filepath.Join(dir, "cert.crt"),
		filepath.Join(dir, "cert.pem"),
		filepath.Join(dir, "server.pem"),
	}

	keyCandidates := []string{
		filepath.Join(dir, "server.key"),
		filepath.Join(dir, "cert.key"),
		filepath.Join(dir, "key.pem"),
		filepath.Join(dir, "server.key.pem"),
	}

	var foundCert, foundKey string
	for _, c := range certCandidates {
		if _, err := os.Stat(c); err == nil {
			foundCert = c
			break
		}
	}
	for _, k := range keyCandidates {
		if _, err := os.Stat(k); err == nil {
			foundKey = k
			break
		}
	}

	if foundCert == "" || foundKey == "" {
		return tls.Certificate{}, fmt.Errorf("SSL certificate and key not found in ./%s/ directory (expected ./%s/server.crt and ./%s/server.key)", dir, dir, dir)
	}

	cert, err := tls.LoadX509KeyPair(foundCert, foundKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load SSL certificate/key pair from %s and %s: %w", foundCert, foundKey, err)
	}

	return cert, nil
}

// GetOrCreateTLSCertificate retrieves an existing TLS certificate or generates a self-signed one.
func GetOrCreateTLSCertificate(certFile, keyFile string, defaultDir string, extraHosts ...string) (tls.Certificate, error) {
	certCacheMu.Lock()
	defer certCacheMu.Unlock()

	// If no custom paths provided, use defaults
	if certFile == "" || keyFile == "" {
		if defaultDir == "" {
			defaultDir = "certs"
		}
		certFile = filepath.Join(defaultDir, "server.crt")
		keyFile = filepath.Join(defaultDir, "server.key")
	}

	// Check if both files already exist on disk
	if _, errCert := os.Stat(certFile); errCert == nil {
		if _, errKey := os.Stat(keyFile); errKey == nil {
			cert, err := tls.LoadX509KeyPair(certFile, keyFile)
			if err == nil {
				return cert, nil
			}
		}
	}

	// Generate and save a new self-signed certificate
	cert, err := GenerateSelfSignedCert(certFile, keyFile, extraHosts...)
	if err != nil {
		return tls.Certificate{}, err
	}

	cachedCert = &cert
	return cert, nil
}

// NewServerTLSConfig creates a modern, hardened *tls.Config for server listeners.
func NewServerTLSConfig(cert tls.Certificate) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

// NewClientTLSConfig creates a *tls.Config for outbound client connections.
// If skipVerify is true, it accepts self-signed or unverified certificates (InsecureSkipVerify).
func NewClientTLSConfig(skipVerify bool) *tls.Config {
	return &tls.Config{
		InsecureSkipVerify: skipVerify,
		MinVersion:         tls.VersionTLS12,
	}
}
