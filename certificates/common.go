package certificates

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path"
	"path/filepath"
)

const (
	ForceFlagUsage  = "Force overwrite of existing files without prompting"
	NameFlagUsage   = "The name of the CA certificate and key file"
	OutDirFlagUsage = "The output directory"
	DayFlagUsage    = "the validity period of the certificate in days"
	CaKeyFlagUsage  = "the path to the CA key file"
	CaCertFlagUsage = "the path to the CA certificate file"
)
const defaultKeySize = 2048

func generateSerialNumber(bits uint) (*big.Int, error) {
	maxValue := new(big.Int).Lsh(big.NewInt(1), bits)
	randValue, err := rand.Int(rand.Reader, maxValue)
	if err != nil {
		return nil, err
	}
	return randValue, nil
}

func generateKeyIDFromRSAPublicKey(N *big.Int, e int) []byte {
	//according to RFC 3280, the Subject key ID must be derived from the public key
	x := new(big.Int).Lsh(N, 32)
	x.Add(x, big.NewInt(int64(e)))
	h := sha256.New()
	h.Write(x.Bytes())
	return h.Sum(nil)
}

func writeFileWithDir(filePath string, data []byte, perm os.FileMode) error {
	dir := path.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filePath, data, perm)
}

func writeCertAndKey(outputDir string, fileName string, certPem, privateKeyPem *bytes.Buffer, force bool) error {
	certFile := filepath.Join(outputDir, fileName+".crt")
	keyFile := filepath.Join(outputDir, fileName+".key")

	if force {
		if _, err := os.Stat(certFile); err == nil {
			if err = os.Chmod(certFile, 0644); err != nil {
				return fmt.Errorf("error making %s writable: %s", certFile, err.Error())
			}
		}
		if _, err := os.Stat(keyFile); err == nil {
			if err = os.Chmod(keyFile, 0600); err != nil {
				return fmt.Errorf("error making %s writable: %s", keyFile, err.Error())
			}
		}
	}

	err := writeFileWithDir(certFile, certPem.Bytes(), 0444)
	if err != nil {
		return fmt.Errorf("error writing certificate to %s: %s", certFile, err.Error())
	}

	err = writeFileWithDir(keyFile, privateKeyPem.Bytes(), 0400)
	if err != nil {
		return fmt.Errorf("error writing private key to %s: %s", keyFile, err.Error())
	}

	return nil
}

func readCertificateFromFile(path string) (*x509.Certificate, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %s", err.Error())
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("error decoding PEM data from file: %s", path)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing certificate from ASN.1 DER data in file: %s", path)
	}
	return cert, nil
}

func readRSAKeyFromFile(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %s", err.Error())
	}

	block, _ := pem.Decode(keyBytes)
	if block == nil {
		return nil, fmt.Errorf("error decoding PEM data from file: %s", path)
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("error parsing RSA key from ASN.1 DER data in file: %s", path)
	}
	return key, nil
}

func checkCertificatesLocationWithForce(dir, certificateName string, force bool) error {
	// Throw an error if the path for the CA and key certificates already
	// exists and the 'force' flag is not set.

	checkFile := func(ext string) bool {
		_, err := os.Stat(filepath.Join(dir, certificateName+ext))
		return !os.IsNotExist(err)
	}

	if !force && (checkFile(".key") || checkFile(".crt")) {
		return fmt.Errorf("existing files would be overwritten. Use -force to proceed")
	}

	return nil
}
