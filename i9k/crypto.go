package i9k

import (
	context "context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	fmt "fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/superp00t/etc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func GetCertFileFingerprint(at string) (string, error) {
	b, err := ioutil.ReadFile(at)
	if err != nil {
		return "", err
	}

	pblock, _ := pem.Decode(b)

	cert, err := x509.ParseCertificate(pblock.Bytes)
	if err != nil {
		return "", nil
	}

	return GetCertFingerprint(cert)
}

func GetCertFingerprint(cert *x509.Certificate) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return "", err
	}

	hash := sha256.Sum256(der)
	hx := strings.ToUpper(hex.EncodeToString(hash[:]))

	return hx, nil
}

func GetPeerFingerprint(ctx context.Context) (string, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		return "", fmt.Errorf("could not extract peer information")
	}

	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", fmt.Errorf("peer does not have tls info")
	}

	certCount := len(tlsInfo.State.PeerCertificates)

	if certCount != 1 {
		return "", fmt.Errorf("invalid certificate count (%d)", certCount)
	}

	cert := tlsInfo.State.PeerCertificates[0]

	return GetCertFingerprint(cert)
}

func genPair(public, private string) error {
	vf := 365 * 24 * time.Hour
	validFor := &vf
	var err error
	var notBefore time.Time
	notBefore = time.Now()

	notAfter := notBefore.Add(*validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %s", err)
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	keyToFile(private, rootKey)

	rootTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Gophercraft"},
			CommonName:   "GC",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return err
	}
	certToFile(public, derBytes)
	return nil
}

// keyToFile writes a PEM serialization of |key| to a new file called
// |filename|.
func keyToFile(filename string, key *ecdsa.PrivateKey) {
	file, err := os.Create(filename)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	b, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
		os.Exit(2)
	}
	if err := pem.Encode(file, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		panic(err)
	}
}

func certToFile(filename string, derBytes []byte) {
	certOut, err := os.Create(filename)
	if err != nil {
		log.Fatalf("failed to open cert.pem for writing: %s", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		log.Fatalf("failed to write data to cert.pem: %s", err)
	}
	if err := certOut.Close(); err != nil {
		log.Fatalf("error closing cert.pem: %s", err)
	}
}

func GenerateTLSKeyPair(at string) error {
	dir := etc.ParseSystemPath(at)
	return genPair(
		dir.Concat("cert.pem").Render(),
		dir.Concat("key.pem").Render())
}
