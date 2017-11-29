package subjectispodforuser_test

import (
	"github.com/proofpoint/kapprover/pkg/inspectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certificates "k8s.io/api/certificates/v1beta1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"testing"

	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	_ "github.com/proofpoint/kapprover/pkg/inspectors/group"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
)

func TestInspect(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Generate the private key")

	for _, testcase := range []struct {
		name            string
		inspectorConfig string
		expectMessage   string
		serviceAccount  string
		setupRequest    func(request *x509.CertificateRequest)
		podNamespace    string
		podIp           string
	}{
		{
			name:          "CnHasO",
			expectMessage: "Subject has more than one name component",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.Organization = []string{"SomeOrg"}
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
		// https://github.com/kubernetes/client-go/issues/326
		//{
		//	name:          "WrongPodIp",
		//	expectMessage: "No POD in namespace \"somenamespace\" with IP \"172.1.0.3\"",
		//	podNamespace:  "somenamespace",
		//	podIp:         "172.1.0.36",
		//},
		{
			name:          "WrongPodNamespace",
			expectMessage: "No POD in namespace \"somenamespace\" with IP \"172.1.0.3\"",
			podNamespace:  "other",
		},
		{
			name:           "WrongUserPrefix",
			expectMessage:  "Requesting user is not \"system:serviceaccount:somenamespace:someserviceaccount\"",
			serviceAccount: "foo:somenamespace:someserviceaccount",
			podNamespace:   "somenamespace",
		},
		{
			name:           "WrongUserNamespace",
			expectMessage:  "Requesting user is not \"system:serviceaccount:somenamespace:someserviceaccount\"",
			serviceAccount: "system:serviceaccount:other:someserviceaccount",
			podNamespace:   "somenamespace",
		},
		{
			name:           "WrongUserAccount",
			expectMessage:  "Requesting user is not \"system:serviceaccount:somenamespace:someserviceaccount\"",
			serviceAccount: "system:serviceaccount:somenamespace:other",
			podNamespace:   "somenamespace",
		},
		{
			name:          "Good",
			expectMessage: "",
			podNamespace:  "somenamespace",
		},
		{
			name:            "ConfiguredNotInClusterDomain",
			inspectorConfig: "example.com",
			expectMessage:   "Subject \"172-1-0-3.somenamespace.pod.cluster.local\" is not in the pod.example.com domain",
		},
		{
			name:            "ConfiguredGood",
			inspectorConfig: "example.com",
			expectMessage:   "",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-1-0-3.somenamespace.pod.example.com"
			},
			podNamespace: "somenamespace",
		},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			inspector, exists := inspectors.Get("subjectispodforuser")
			if !exists {
				t.Fatal("Expected inspectors.Get(\"subjectispodforuser\") to exist, did not")
			}

			if testcase.inspectorConfig != "" {
				var err error
				inspector, err = inspector.Configure(testcase.inspectorConfig)
				assert.NoError(t, err, "Configure")
			}

			podIp := testcase.podIp
			if podIp == "" {
				podIp = "172.1.0.3"
			}
			objects := []runtime.Object{&v1.Pod{
				TypeMeta: metaV1.TypeMeta{
					Kind:       "Pod",
					APIVersion: "v1",
				},
				ObjectMeta: metaV1.ObjectMeta{
					Name:      "tls-app-579f7cd745-t6fdg",
					Namespace: testcase.podNamespace,
					Labels: map[string]string{
						"tag": "",
					},
				},
				Spec: v1.PodSpec{
					ServiceAccountName: "someserviceaccount",
				},
				Status: v1.PodStatus{
					PodIP: podIp,
				},
			}}
			if testcase.podNamespace == "" {
				objects = []runtime.Object{}
			}
			client := fake.NewSimpleClientset(objects...)

			// Generate the certificate request.
			certificateRequestTemplate := x509.CertificateRequest{
				Subject: pkix.Name{
					CommonName: "172-1-0-3.somenamespace.pod.cluster.local",
				},
				SignatureAlgorithm: x509.SHA256WithRSAPSS,
			}
			if testcase.setupRequest != nil {
				testcase.setupRequest(&certificateRequestTemplate)
			}

			certificateRequest, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequestTemplate, key)
			require.NoError(t, err, "Generate the CSR")

			certificateRequestBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certificateRequest})

			request := certificates.CertificateSigningRequest{
				Spec: certificates.CertificateSigningRequestSpec{
					Username: testcase.serviceAccount,
					Request:  certificateRequestBytes,
				},
			}
			if request.Spec.Username == "" {
				request.Spec.Username = "system:serviceaccount:somenamespace:someserviceaccount"
			}

			message, err := inspector.Inspect(client, &request)
			assert.Equal(t, testcase.expectMessage, message, "Message")
			assert.NoError(t, err)
		})
	}
}
