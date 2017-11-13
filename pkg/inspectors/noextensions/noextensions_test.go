package noextensions_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"github.com/proofpoint/kapprover/pkg/inspectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	certificates "k8s.io/client-go/pkg/apis/certificates/v1beta1"
	"strconv"
	"testing"

	_ "github.com/proofpoint/kapprover/pkg/inspectors/noextensions"
)

var (
	client *kubernetes.Clientset
)

func TestInspect(t *testing.T) {
	inspector, exists := inspectors.Get("noextensions")
	require.True(t, exists, "inspectors.Get(\"noextensions\") to exist")

	basicConstraintsValue, err := asn1.Marshal(struct {
		IsCA       bool `asn1:"optional"`
		MaxPathLen int  `asn1:"optional,default:-1"`
	}{
		true,
		1,
	})
	require.NoError(t, err, "marshall basicConstraintsValue")

	nameConstraintsValue, err := asn1.Marshal(struct {
		Permitted []string `asn1:"optional,tag:0"`
		Excluded  []string `asn1:"optional,tag:1"`
	}{})

	require.NoError(t, err, "marshall basicConstraintsValue")

	var extensions = []pkix.Extension{
		{
			Id:       []int{2, 5, 29, 19},
			Critical: false,
			Value:    basicConstraintsValue,
		},
		{
			Id:       []int{2, 5, 29, 30},
			Critical: false,
			Value:    nameConstraintsValue,
		},
	}

	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Generate the private key")

	for _, testcase := range []struct {
		numExtensions int
		expectMessage string
	}{
		{0, ""},
		{1, "Contains X.509 extension 2.5.29.19"},
		{2, "Contains X.509 extensions 2.5.29.19,2.5.29.30"},
	} {
		t.Run(strconv.Itoa(testcase.numExtensions), func(t *testing.T) {
			// Generate the certificate request.
			certificateRequestTemplate := x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "example.invalid",
				},
				SignatureAlgorithm: x509.SHA256WithRSAPSS,
				ExtraExtensions:    extensions[:testcase.numExtensions],
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
			assert.Equal(t, testcase.expectMessage, message, "Message")
			assert.NoError(t, err)
		})
	}
}
