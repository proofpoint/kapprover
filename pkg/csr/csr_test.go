package csr_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/proofpoint/kapprover/pkg/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"testing"

	_ "github.com/proofpoint/kapprover/pkg/inspectors/minrsakeysize"
	"regexp"
)

var (
	client *kubernetes.Clientset
)

func TestExtract(t *testing.T) {
	// Generate a private key.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Generate the private key")

	// Generate the certificate request.
	certificateRequestTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.invalid",
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	expectedCertificateRequest, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequestTemplate, key)
	require.NoError(t, err, "Generate the CSR")

	certificateRequestBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: expectedCertificateRequest})

	certificateRequest, message := csr.Extract(certificateRequestBytes)
	assert.Equal(t, expectedCertificateRequest, certificateRequest.Raw, "CSR bytes")
	assert.Equal(t, "example.invalid", certificateRequest.Subject.CommonName)
	assert.Empty(t, message, "CSR extract message")
}

func TestExtractNoPem(t *testing.T) {
	certificateRequest, message := csr.Extract([]byte("nothing here"))
	assert.Nil(t, certificateRequest, "CSR bytes")
	assert.Equal(t, "Request did not have a parseable PEM object", message, "CSR extract message")
}

func TestExtractTwoObjects(t *testing.T) {
	// Generate a private key.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Generate the private key")

	// Generate the certificate request.
	certificateRequestTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.invalid",
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	expectedCertificateRequest, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequestTemplate, key)
	require.NoError(t, err, "Generate the CSR")

	certificateRequestBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: expectedCertificateRequest})

	certificateRequest, message := csr.Extract(append(certificateRequestBytes, certificateRequestBytes...))
	assert.Nil(t, certificateRequest, "CSR bytes")
	assert.Equal(t, "Request had more than one PEM object", message, "CSR extract message")
}

func TestExtractNotCSR(t *testing.T) {
	// Generate a private key.
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Generate the private key")

	certificateRequestBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	certificateRequest, message := csr.Extract(certificateRequestBytes)
	assert.Nil(t, certificateRequest, "CSR bytes")
	assert.Regexp(t, regexp.MustCompile("Request had invalid certificate request: .*"), message, "CSR extract message")
}
