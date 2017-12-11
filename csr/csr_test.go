package csr_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/proofpoint/kapprover/csr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	"regexp"
	"testing"

	_ "github.com/proofpoint/kapprover/inspectors/minrsakeysize"
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

func TestGetPodIpAndNamespace(t *testing.T) {
	for _, testcase := range []struct {
		name            string
		clusterDomain   string
		setupRequest    func(request *x509.CertificateRequest)
		expectPodIp     string
		expectNamespace string
		expectMessage   string
	}{
		{
			name:          "CnHasO",
			expectMessage: "Subject has more than one name component",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.ExtraNames = []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 10},
						Value: "SomeOrg",
					},
				}
			},
		},
		{
			name:          "CnHasTwoCN",
			expectMessage: "Subject has more than one name component",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.ExtraNames = []pkix.AttributeTypeAndValue{
					{
						Type:  []int{2, 5, 4, 3},
						Value: []string{"example.com"},
					},
					{
						Type:  []int{2, 5, 4, 3},
						Value: []string{"example.org"},
					},
				}
			},
		},
		{
			name:          "NotInClusterDomain",
			expectMessage: "Subject \"172-1-2-3.somenamespace.pod.example.com\" is not in the pod.cluster.local domain",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-1-2-3.somenamespace.pod.example.com"
			},
		},
		{
			name:          "NotAPodDomain",
			expectMessage: "Subject \"172-1-2-3.somenamespace.svc.cluster.local\" is not in the pod.cluster.local domain",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-1-2-3.somenamespace.svc.cluster.local"
			},
		},
		{
			name:          "ExtraDomainComponents",
			expectMessage: "Subject \"172-1-2-3.somenamespace.extra.pod.cluster.local\" is not a POD-format name",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-1-2-3.somenamespace.extra.pod.cluster.local"
			},
		},
		{
			name:          "MissingNamespace",
			expectMessage: "Subject \"172-1-2-3.pod.cluster.local\" is not a POD-format name",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-1-2-3.pod.cluster.local"
			},
		},
		{
			name:          "IpTooShort",
			expectMessage: "Subject \"172-1-2.somenamespace.pod.cluster.local\" is not a POD-format name",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-1-2.somenamespace.pod.cluster.local"
			},
		},
		{
			name:          "IpTooLong",
			expectMessage: "Subject \"172-1-2-3-4.somenamespace.pod.cluster.local\" is not a POD-format name",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-1-2-3-4.somenamespace.pod.cluster.local"
			},
		},
		{
			name:          "IpNumberTooLarge",
			expectMessage: "Subject \"172-256-2-3.somenamespace.pod.cluster.local\" is not a POD-format name",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-256-2-3.somenamespace.pod.cluster.local"
			},
		},
		{
			name:          "IpNonDigit",
			expectMessage: "Subject \"172-1a-2-3.somenamespace.pod.cluster.local\" is not a POD-format name",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-1a-2-3.somenamespace.pod.cluster.local"
			},
		},
		{
			name:          "IpLeadingZero",
			expectMessage: "Subject \"172-01-2-3.somenamespace.pod.cluster.local\" is not a POD-format name",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-01-2-3.somenamespace.pod.cluster.local"
			},
		},
		{
			name:          "IpMissingByte",
			expectMessage: "Subject \"172--2-3.somenamespace.pod.cluster.local\" is not a POD-format name",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172--2-3.somenamespace.pod.cluster.local"
			},
		},
		{
			name:            "Good",
			expectPodIp:     "172.1.0.3",
			expectNamespace: "somenamespace",
		},
		{
			name:          "ConfiguredNotInClusterDomain",
			clusterDomain: "example.com",
			expectMessage: "Subject \"172-1-0-3.somenamespace.pod.cluster.local\" is not in the pod.example.com domain",
		},
		{
			name:          "ConfiguredGood",
			clusterDomain: "example.com",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-1-0-3.somenamespace.pod.example.com"
			},
			expectMessage:   "",
			expectPodIp:     "172.1.0.3",
			expectNamespace: "somenamespace",
		},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			clusterDomain := testcase.clusterDomain
			if clusterDomain == "" {
				clusterDomain = "cluster.local"
			}
			certificateRequestTemplate := x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "172-1-0-3.somenamespace.pod.cluster.local",
				},
			}
			if testcase.setupRequest != nil {
				testcase.setupRequest(&certificateRequestTemplate)
			}
			certificateRequestTemplate.Subject.Names = make([]pkix.AttributeTypeAndValue, 0)
			certificateRequestTemplate.Subject.Names = append(certificateRequestTemplate.Subject.Names, pkix.AttributeTypeAndValue{Type: []int{2, 5, 4, 3}, Value: certificateRequestTemplate.Subject.CommonName})
			certificateRequestTemplate.Subject.Names = append(certificateRequestTemplate.Subject.Names, certificateRequestTemplate.Subject.ExtraNames...)

			podIp, namespace, msg := csr.GetPodIpAndNamespace(clusterDomain, &certificateRequestTemplate)
			assert.Equal(t, testcase.expectPodIp, podIp, "Namespace")
			assert.Equal(t, testcase.expectNamespace, namespace, "Namespace")
			assert.Equal(t, testcase.expectMessage, msg, "Message")
		})
	}
}
