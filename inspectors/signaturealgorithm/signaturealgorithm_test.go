package signaturealgorithm_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/proofpoint/kapprover/inspectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
	"testing"

	_ "github.com/proofpoint/kapprover/inspectors/signaturealgorithm"
)

var (
	client *kubernetes.Clientset
)

func TestInspect(t *testing.T) {
	inspector, exists := inspectors.Get("signaturealgorithm")
	require.True(t, exists, "inspectors.Get(\"signaturealgorithm\") to exist")

	for _, testcase := range []struct {
		signatureAlgorithm x509.SignatureAlgorithm
		publicKeyAlgorithm x509.PublicKeyAlgorithm
		expectAllow        bool
	}{
		// Cannot sign CSR with this {x509.MD2WithRSA, x509.RSA, false},
		{x509.MD5WithRSA, x509.RSA, false},
		{x509.SHA1WithRSA, x509.RSA, false},
		{x509.SHA256WithRSA, x509.RSA, true},
		{x509.SHA384WithRSA, x509.RSA, true},
		{x509.SHA512WithRSA, x509.RSA, true},
		{x509.SHA256WithRSAPSS, x509.RSA, true},
		{x509.SHA384WithRSAPSS, x509.RSA, true},
		{x509.SHA512WithRSAPSS, x509.RSA, true},
		// dsa.PrivateKey doesn't implement crypto.Signer
		// { x509.DSAWithSHA1, x509.DSA, false },
		// { x509.DSAWithSHA256, x509.DSA, false },
		{x509.ECDSAWithSHA1, x509.ECDSA, false},
		{x509.ECDSAWithSHA256, x509.ECDSA, false},
		{x509.ECDSAWithSHA384, x509.ECDSA, false},
		{x509.ECDSAWithSHA512, x509.ECDSA, false},
	} {
		assertInspectionResult(t, inspector, testcase.signatureAlgorithm, testcase.publicKeyAlgorithm, testcase.expectAllow)
	}
}

func TestInspectConfigured(t *testing.T) {
	inspector, exists := inspectors.Get("signaturealgorithm")
	require.True(t, exists, "inspectors.Get(\"signaturealgorithm\") to exist")

	inspector, err := inspector.Configure("MD5WithRSA,SHA1WithRSA,ECDSAWithSHA1,ECDSAWithSHA256,ECDSAWithSHA384,ECDSAWithSHA512")
	assert.NoError(t, err, "Configure")

	for _, testcase := range []struct {
		signatureAlgorithm x509.SignatureAlgorithm
		publicKeyAlgorithm x509.PublicKeyAlgorithm
		expectAllow        bool
	}{
		{x509.MD5WithRSA, x509.RSA, true},
		{x509.SHA1WithRSA, x509.RSA, true},
		{x509.SHA256WithRSA, x509.RSA, false},
		{x509.SHA384WithRSA, x509.RSA, false},
		{x509.SHA512WithRSA, x509.RSA, false},
		{x509.SHA256WithRSAPSS, x509.RSA, false},
		{x509.SHA384WithRSAPSS, x509.RSA, false},
		{x509.SHA512WithRSAPSS, x509.RSA, false},
		// dsa.PrivateKey doesn't implement crypto.Signer
		// { x509.DSAWithSHA1, x509.DSA, false },
		// { x509.DSAWithSHA256, x509.DSA, false },
		{x509.ECDSAWithSHA1, x509.ECDSA, true},
		{x509.ECDSAWithSHA256, x509.ECDSA, true},
		{x509.ECDSAWithSHA384, x509.ECDSA, true},
		{x509.ECDSAWithSHA512, x509.ECDSA, true},
	} {
		assertInspectionResult(t, inspector, testcase.signatureAlgorithm, testcase.publicKeyAlgorithm, testcase.expectAllow)
	}
}

func TestConfigureBadAlgorithm(t *testing.T) {
	for _, algorithm := range []string{
		"MD2WithRSA",
		"DSAWithSHA1",
		"DSAWithSHA256",
		"Unknown",
	} {
		t.Run(algorithm, func(t *testing.T) {
			inspector, exists := inspectors.Get("signaturealgorithm")
			require.True(t, exists, "inspectors.Get(\"signaturealgorithm\") to exist")

			inspector, err := inspector.Configure(algorithm)
			assert.EqualErrorf(t, err, fmt.Sprintf("unsupported SignatureAlgorithm %s", algorithm), algorithm)
		})
	}
}

func assertInspectionResult(t *testing.T, inspector inspectors.Inspector, signatureAlgorithm x509.SignatureAlgorithm, publicKeyAlgorithm x509.PublicKeyAlgorithm, expectAllow bool) {
	t.Run(signatureAlgorithm.String(), func(t *testing.T) {
		var key interface{}
		var err error

		switch publicKeyAlgorithm {
		case x509.RSA:
			// Generate a private key.
			key, err = rsa.GenerateKey(rand.Reader, 1024)
		case x509.ECDSA:
			key, err = ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		default:
			t.Error("Cannot test key algorithm type", publicKeyAlgorithm)
			return
		}
		require.NoError(t, err, "Generate the private key")

		// Generate the certificate request.
		certificateRequestTemplate := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: "example.invalid",
			},
			SignatureAlgorithm: signatureAlgorithm,
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
		expectedMessage := ""
		if !expectAllow {
			expectedMessage = fmt.Sprintf("SignatureAlgorithm is %s", signatureAlgorithm)
		}
		assert.Equal(t, expectedMessage, message, "SignatureAlgorithm %s", signatureAlgorithm)
		assert.NoError(t, err, "SignatureAlgorithm %s", signatureAlgorithm)
	})
}
