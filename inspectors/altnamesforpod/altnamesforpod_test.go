package altnamesforpod_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"github.com/proofpoint/kapprover/inspectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"net"
	"testing"

	_ "github.com/proofpoint/kapprover/inspectors/group"
)

func TestInspect(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err, "Generate the private key")

	nowTime := metaV1.Now()

	for _, testcase := range []struct {
		name            string
		inspectorConfig string
		expectMessage   string
		serviceAccount  string
		objects         []runtime.Object
		setupRequest    func(request *x509.CertificateRequest)
		podNamespace    string
		podIp           string
		inspectorName   string
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
		//	expectMessage: "No pending or running POD in namespace \"somenamespace\" with IP \"172.1.0.3\"",
		//	podIp:         "172.1.0.36",
		//},
		{
			name:          "WrongPodNamespace",
			expectMessage: "No pending or running POD in namespace \"somenamespace\" with IP \"172.1.0.3\"",
			podNamespace:  "other",
		},
		{
			name: "Good",
			setupRequest: func(request *x509.CertificateRequest) {
				request.DNSNames = []string{
					"172-1-0-3.somenamespace.pod.cluster.local",
					"tls-service.somenamespace.svc.cluster.local",
				}
				request.IPAddresses = makeIps("172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4")
			},
			expectMessage: "",
		},
		{
			name: "ExtraDomain",
			setupRequest: func(request *x509.CertificateRequest) {
				request.DNSNames = []string{
					"172-1-0-3.somenamespace.pod.cluster.local",
					"tls-service.somenamespace.svc.cluster.local",
					"example.org",
				}
				request.IPAddresses = makeIps("172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4")
			},
			expectMessage: "Subject Alt Name contains disallowed name: example.org",
		},
		{
			name: "ExtraIp",
			setupRequest: func(request *x509.CertificateRequest) {
				request.DNSNames = []string{
					"172-1-0-3.somenamespace.pod.cluster.local",
					"tls-service.somenamespace.svc.cluster.local",
				}
				request.IPAddresses = makeIps("172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4", "10.2.3.4")
			},
			expectMessage: "Subject Alt Name contains disallowed name: 10.2.3.4",
		},
		{
			name: "EmailAddress",
			setupRequest: func(request *x509.CertificateRequest) {
				request.DNSNames = []string{
					"172-1-0-3.somenamespace.pod.cluster.local",
					"tls-service.somenamespace.svc.cluster.local",
				}
				request.IPAddresses = makeIps("172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4")
				request.EmailAddresses = []string{"foo@example.invalid"}
			},
			expectMessage: "Subject Alt Name contains disallowed name: Name of type 1",
		},
		{
			name: "ExtraMultiple",
			setupRequest: func(request *x509.CertificateRequest) {
				request.DNSNames = []string{
					"172-1-0-3.somenamespace.pod.cluster.local",
					"tls-service.somenamespace.svc.cluster.local",
					"example.org",
					"example.net",
				}
				request.IPAddresses = makeIps("172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4", "10.2.3.4", "10.2.3.5")
			},
			expectMessage: "Subject Alt Name contains disallowed names: example.org,example.net,10.2.3.4,10.2.3.5",
		},
		{
			name:            "ConfiguredNotInClusterDomain",
			inspectorConfig: "example.com",
			objects:         []runtime.Object{},
			expectMessage:   "Subject \"172-1-0-3.somenamespace.pod.cluster.local\" is not in the pod.example.com domain",
		},
		{
			name:            "ConfiguredGood",
			inspectorConfig: "example.com",
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-1-0-3.somenamespace.pod.example.com"
				request.DNSNames = []string{
					"172-1-0-3.somenamespace.pod.example.com",
					"tls-service.somenamespace.svc.example.com",
				}
				request.IPAddresses = makeIps("172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4")
			},
		},
		{
			name:            "IgnoresNotPendingOrRunningPod",
			inspectorConfig: "example.com",
			objects: []runtime.Object{
				&v1.Pod{
					TypeMeta: metaV1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metaV1.ObjectMeta{
						Name:      "wrong-app-579f7cd745-wrong",
						Namespace: "somenamespace",
						Labels: map[string]string{
							"app": "wrong-app",
						},
					},
					Status: v1.PodStatus{
						Phase: v1.PodFailed,
						PodIP: "172.1.0.3",
					},
				},
				&v1.Pod{
					TypeMeta: metaV1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metaV1.ObjectMeta{
						Name:      "tls-app-579f7cd745-t6fdg",
						Namespace: "somenamespace",
						Labels: map[string]string{
							"app": "some-app",
						},
					},
					Status: v1.PodStatus{
						Phase: v1.PodPending,
						PodIP: "172.1.0.3",
					},
				},
				&v1.Service{
					ObjectMeta: metaV1.ObjectMeta{
						Name:      "tls-service",
						Namespace: "somenamespace",
						Labels: map[string]string{
							"app": "some-service",
						},
					},
					Spec: v1.ServiceSpec{
						Selector:    map[string]string{"app": "some-app"},
						ClusterIP:   "10.0.0.1",
						Type:        v1.ServiceTypeLoadBalancer,
						ExternalIPs: []string{"10.1.2.3", "10.1.2.4"},
					},
				},
			},
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-1-0-3.somenamespace.pod.example.com"
				request.DNSNames = []string{
					"172-1-0-3.somenamespace.pod.example.com",
					"tls-service.somenamespace.svc.example.com",
				}
				request.IPAddresses = makeIps("172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4")
			},
		},
		{
			name:            "IgnoresPodMarkedForDeletion",
			inspectorConfig: "example.com",
			objects: []runtime.Object{
				&v1.Pod{
					TypeMeta: metaV1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metaV1.ObjectMeta{
						Name:              "wrong-app-579f7cd745-wrong",
						Namespace:         "somenamespace",
						DeletionTimestamp: &nowTime,
						Labels: map[string]string{
							"app": "wrong-app",
						},
					},
					Status: v1.PodStatus{
						Phase: v1.PodRunning,
						PodIP: "172.1.0.3",
					},
				},
				&v1.Pod{
					TypeMeta: metaV1.TypeMeta{
						Kind:       "Pod",
						APIVersion: "v1",
					},
					ObjectMeta: metaV1.ObjectMeta{
						Name:      "tls-app-579f7cd745-t6fdg",
						Namespace: "somenamespace",
						Labels: map[string]string{
							"app": "some-app",
						},
					},
					Status: v1.PodStatus{
						Phase: v1.PodRunning,
						PodIP: "172.1.0.3",
					},
				},
				&v1.Service{
					ObjectMeta: metaV1.ObjectMeta{
						Name:      "tls-service",
						Namespace: "somenamespace",
						Labels: map[string]string{
							"app": "some-service",
						},
					},
					Spec: v1.ServiceSpec{
						Selector:    map[string]string{"app": "some-app"},
						ClusterIP:   "10.0.0.1",
						Type:        v1.ServiceTypeLoadBalancer,
						ExternalIPs: []string{"10.1.2.3", "10.1.2.4"},
					},
				},
			},
			setupRequest: func(request *x509.CertificateRequest) {
				request.Subject.CommonName = "172-1-0-3.somenamespace.pod.example.com"
				request.DNSNames = []string{
					"172-1-0-3.somenamespace.pod.example.com",
					"tls-service.somenamespace.svc.example.com",
				}
				request.IPAddresses = makeIps("172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4")
			},
		},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			if testcase.inspectorName == "" {
				testcase.inspectorName = "altnamesforpodallowunqualified"
			}

			inspector, exists := inspectors.Get(testcase.inspectorName)
			if !exists {
				t.Fatal("Expected inspectors.Get(\"altnamesforpod\") to exist, did not")
			}

			if testcase.inspectorConfig != "" {
				var err error
				inspector, err = inspector.Configure(testcase.inspectorConfig)
				assert.NoError(t, err, "Configure")
			}

			if testcase.podNamespace == "" {
				testcase.podNamespace = "somenamespace"
			}

			if testcase.objects == nil {
				testcase.objects = []runtime.Object{
					&v1.Pod{
						TypeMeta: metaV1.TypeMeta{
							Kind:       "Pod",
							APIVersion: "v1",
						},
						ObjectMeta: metaV1.ObjectMeta{
							Name:      "tls-app-579f7cd745-t6fdg",
							Namespace: testcase.podNamespace,
							Labels: map[string]string{
								"app": "some-app",
							},
						},
						Status: v1.PodStatus{
							Phase: v1.PodPending,
							PodIP: "172.1.0.3",
						},
					},
					&v1.Service{
						ObjectMeta: metaV1.ObjectMeta{
							Name:      "tls-service",
							Namespace: "somenamespace",
							Labels: map[string]string{
								"app": "some-service",
							},
						},
						Spec: v1.ServiceSpec{
							Selector:    map[string]string{"app": "some-app"},
							ClusterIP:   "10.0.0.1",
							Type:        v1.ServiceTypeLoadBalancer,
							ExternalIPs: []string{"10.1.2.3", "10.1.2.4"},
						},
					},
				}
			}
			client := fake.NewSimpleClientset(testcase.objects...)

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

func makeIps(ips ...string) []net.IP {
	var iplist []net.IP
	for _, ip := range ips {
		iplist = append(iplist, net.ParseIP(ip))
	}
	return iplist
}
