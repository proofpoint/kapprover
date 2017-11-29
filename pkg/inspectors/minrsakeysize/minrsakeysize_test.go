package minrsakeysize_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/proofpoint/kapprover/pkg/inspectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
	"testing"

	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	_ "github.com/proofpoint/kapprover/pkg/inspectors/minrsakeysize"
)

var (
	client *kubernetes.Clientset
)

func TestInspect(t *testing.T) {
	inspector, exists := inspectors.Get("minrsakeysize")
	require.True(t, exists, "inspectors.Get(\"minrsakeysize\") to exist")

	for keysize, expectedMessage := range map[uint]string{
		2048: "Public key too small: 2048 < 3072",
		3071: "Public key too small: 3071 < 3072",
		3072: "",
		3100: "",
	} {
		assertInspectionResult(t, inspector, keysize, expectedMessage)
	}
}

func TestInspectConfigured(t *testing.T) {
	inspector, exists := inspectors.Get("minrsakeysize")
	require.True(t, exists, "inspectors.Get(\"minrsakeysize\") to exist")

	inspector, err := inspector.Configure("2048")
	assert.NoError(t, err, "Configure")

	for keysize, expectedMessage := range map[uint]string{
		2047: "Public key too small: 2047 < 2048",
		2048: "",
	} {
		assertInspectionResult(t, inspector, keysize, expectedMessage)
	}
}

func TestInspectNotRsa(t *testing.T) {
	inspector, exists := inspectors.Get("minrsakeysize")
	require.True(t, exists, "inspectors.Get(\"minrsakeysize\") to exist")

	var dsaPrivateKey dsa.PrivateKey
	err := dsa.GenerateParameters(&dsaPrivateKey.Parameters, rand.Reader, dsa.L1024N160)
	require.NoError(t, err, "dsa.GenerateParameters()")

	err = dsa.GenerateKey(&dsaPrivateKey, rand.Reader)
	require.NoError(t, err, "dsa.GenerateKey()")

	ecdsaPrivateKey, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err, "ecdsa.GenerateKey()")

	for alg, testcase := range map[string]struct {
		signatureAlgorithm x509.SignatureAlgorithm
		key                interface{}
	}{
		// dsa.PrivateKey doesn't implement crypto.Signer		"DSA":   {x509.DSAWithSHA256, dsaPrivateKey},
		"ECDSA": {x509.ECDSAWithSHA256, ecdsaPrivateKey},
	} {
		// Generate the certificate request.
		certificateRequestTemplate := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "example.invalid",
			},
			SignatureAlgorithm: testcase.signatureAlgorithm,
		}

		certificateRequest, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequestTemplate, testcase.key)
		require.NoError(t, err, "Generate the CSR")

		certificateRequestBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certificateRequest})

		request := certificates.CertificateSigningRequest{
			Spec: certificates.CertificateSigningRequestSpec{
				Username: "someRandomUser",
				Request:  certificateRequestBytes,
			},
		}
		message, err := inspector.Inspect(client, &request)
		assert.Equal(t, "", message, "Keytype %s", alg)
		assert.NoError(t, err, "Keytype %s", alg)
	}
}

func assertInspectionResult(t *testing.T, inspector inspectors.Inspector, keysize uint, expectedMessage string) {
	// Generate a private key.
	key, err := rsa.GenerateKey(rand.Reader, int(keysize))
	require.NoError(t, err, "Generate the private key")

	// Generate the certificate request.
	certificateRequestTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "example.invalid",
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	certificateRequest, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequestTemplate, key)
	require.NoError(t, err, "Generate the CSR")

	certificateRequestBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certificateRequest})

	request := certificates.CertificateSigningRequest{
		Spec: certificates.CertificateSigningRequestSpec{
			Username: "someRandomUser",
			Request:  certificateRequestBytes,
		},
	}
	message, err := inspector.Inspect(client, &request)
	assert.Equal(t, expectedMessage, message, "Keysize %s", keysize)
	assert.NoError(t, err, "Keysize %s", keysize)
}
