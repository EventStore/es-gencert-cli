package certificates

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"path"
	"text/tabwriter"
)

const defaultKeySize = 2048

const forceOption = "Force overwrite of existing files without prompting"

const (
	ErrFileExists = "Error: Existing files would be overwritten. Use -force to proceed"
)

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

func writeHelpOption(w *tabwriter.Writer, title string, description string) {
	fmt.Fprintf(w, "\t-%s\t%s\n", title, description)
}

func writeCACertAndKey(outputDir string, fileName string, certPem, privateKeyPem *bytes.Buffer, force bool) error {
	certFile := path.Join(outputDir, fileName+".crt")
	keyFile := path.Join(outputDir, fileName+".key")

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
		return fmt.Errorf("error writing CA certificate to %s: %s", certFile, err.Error())
	}

	err = writeFileWithDir(keyFile, privateKeyPem.Bytes(), 0400)
	if err != nil {
		return fmt.Errorf("error writing CA's private key to %s: %s", keyFile, err.Error())
	}

	return nil
}

func fileExists(path string, force bool) bool {
	if _, err := os.Stat(path); !os.IsNotExist(err) && !force {
		return true
	}
	return false
}
