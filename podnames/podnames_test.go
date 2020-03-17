package podnames_test

import (
	"github.com/proofpoint/kapprover/podnames"
	"github.com/stretchr/testify/assert"
	"k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	"net"
	"testing"
)

func TestGetNamesForPodAndNamespace(t *testing.T) {
	for _, testcase := range []struct {
		name             string
		clusterDomain    string
		setupPod         func(pod *v1.Pod)
		objects          []runtime.Object
		expectDnsnames   []string
		expectIps        []string
		expectErr        string
		allowUnqualified bool
	}{
		{
			name:           "Basic",
			expectDnsnames: []string{"172-1-0-3.somenamespace.pod.cluster.local"},
			expectIps:      []string{"172.1.0.3"},
		},
		{
			name:           "Clusterdomain",
			clusterDomain:  "somedomain.invalid",
			expectDnsnames: []string{"172-1-0-3.somenamespace.pod.somedomain.invalid"},
			expectIps:      []string{"172.1.0.3"},
		},
		{
			name: "headless",
			setupPod: func(pod *v1.Pod) {
				pod.Spec.Hostname = "somehostname"
				pod.Spec.Subdomain = "somesubdomain"
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"somehostname.somesubdomain.somenamespace.svc.cluster.local",
			},
			expectIps: []string{"172.1.0.3"},
		},
		{
			name: "headless with allowUnqualified",
			setupPod: func(pod *v1.Pod) {
				pod.Spec.Hostname = "somehostname"
				pod.Spec.Subdomain = "somesubdomain"
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"somehostname.somesubdomain.somenamespace.svc.cluster.local",
				"somehostname.somesubdomain.somenamespace.svc",
			},
			allowUnqualified: true,
			expectIps:        []string{"172.1.0.3"},
		},
		{
			name: "Hostnameonly",
			setupPod: func(pod *v1.Pod) {
				pod.Spec.Hostname = "somehostname"
			},
			expectDnsnames: []string{"172-1-0-3.somenamespace.pod.cluster.local"},
			expectIps:      []string{"172.1.0.3"},
		},
		{
			name: "Subdomainonly",
			setupPod: func(pod *v1.Pod) {
				pod.Spec.Subdomain = "somesubdomain"
			},
			expectDnsnames: []string{"172-1-0-3.somenamespace.pod.cluster.local"},
			expectIps:      []string{"172.1.0.3"},
		},
		{
			name: "Service",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"tls-service.somenamespace.svc.cluster.local",
			},
			expectIps: []string{"172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4"},
		},
		{
			name: "Service with allowUnqualified",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"tls-service.somenamespace.svc.cluster.local",
				"tls-service.somenamespace.svc",
			},
			allowUnqualified: true,
			expectIps:        []string{"172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4"},
		},
		{
			name: "WrongServiceNamespace",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.ObjectMeta.Namespace = "othernamespace"
				}),
			},
			expectDnsnames: []string{"172-1-0-3.somenamespace.pod.cluster.local"},
			expectIps:      []string{"172.1.0.3"},
		},
		{
			name: "ServiceNoSelector",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.Spec.Selector = nil
				}),
			},
			expectDnsnames: []string{"172-1-0-3.somenamespace.pod.cluster.local"},
			expectIps:      []string{"172.1.0.3"},
		},
		{
			name: "ServiceWrongSelector",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.Spec.Selector = map[string]string{"app": "other-app"}
				}),
			},
			expectDnsnames: []string{"172-1-0-3.somenamespace.pod.cluster.local"},
			expectIps:      []string{"172.1.0.3"},
		},
		{
			name:          "ServiceClusterdomain",
			clusterDomain: "somedomain.invalid",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.somedomain.invalid",
				"tls-service.somenamespace.svc.somedomain.invalid",
			},
			expectIps: []string{"172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4"},
		},
		{
			name:          "ServiceClusterdomain with allowUnqualified",
			clusterDomain: "somedomain.invalid",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.somedomain.invalid",
				"tls-service.somenamespace.svc.somedomain.invalid",
				"tls-service.somenamespace.svc",
			},
			allowUnqualified: true,
			expectIps:        []string{"172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4"},
		},
		{
			name: "ServiceClusterIp",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.Spec.Type = v1.ServiceTypeClusterIP
				}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"tls-service.somenamespace.svc.cluster.local",
			},
			expectIps: []string{"172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4"},
		},
		{
			name: "ServiceClusterIp with allowUnqualified",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.Spec.Type = v1.ServiceTypeClusterIP
				}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"tls-service.somenamespace.svc.cluster.local",
				"tls-service.somenamespace.svc",
			},
			allowUnqualified: true,
			expectIps:        []string{"172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4"},
		},
		{
			name: "ServiceNodePort",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.Spec.Type = v1.ServiceTypeNodePort
				}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"tls-service.somenamespace.svc.cluster.local",
			},
			expectIps: []string{"172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4"},
		},
		{
			name: "ServiceNodePort with allowUnqualified",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.Spec.Type = v1.ServiceTypeNodePort
				}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"tls-service.somenamespace.svc.cluster.local",
				"tls-service.somenamespace.svc",
			},
			allowUnqualified: true,
			expectIps:        []string{"172.1.0.3", "10.0.0.1", "10.1.2.3", "10.1.2.4"},
		},
		{
			name: "ServiceExternalName",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.Spec.Type = v1.ServiceTypeExternalName
				}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"tls-service.somenamespace.svc.cluster.local",
				"someexternalname.somedomain.invalid",
			},
			expectIps: []string{"172.1.0.3", "10.1.2.3", "10.1.2.4"},
		},
		{
			name: "ServiceExternalName with allowUnqualified",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.Spec.Type = v1.ServiceTypeExternalName
				}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"tls-service.somenamespace.svc.cluster.local",
				"tls-service.somenamespace.svc",
				"someexternalname.somedomain.invalid",
			},
			allowUnqualified: true,
			expectIps:        []string{"172.1.0.3", "10.1.2.3", "10.1.2.4"},
		},
		{
			name: "ServiceExternalNameNoName",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.Spec.Type = v1.ServiceTypeExternalName
					service.Spec.ExternalName = ""
				}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"tls-service.somenamespace.svc.cluster.local",
				"someexternalname.somedomain.invalid",
			},
			expectIps: []string{"172.1.0.3", "10.1.2.3", "10.1.2.4"},
		},
		{
			name: "ServiceExternalNameNoName with allowUnqualified",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.Spec.Type = v1.ServiceTypeExternalName
					service.Spec.ExternalName = ""
				}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"tls-service.somenamespace.svc.cluster.local",
				"tls-service.somenamespace.svc",
				"someexternalname.somedomain.invalid",
			},
			allowUnqualified: true,
			expectIps:        []string{"172.1.0.3", "10.1.2.3", "10.1.2.4"},
		},
		{
			name: "ServiceNoExternalIps",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.Spec.ExternalIPs = nil
				}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"tls-service.somenamespace.svc.cluster.local",
			},
			expectIps: []string{"172.1.0.3", "10.0.0.1"},
		},
		{
			name: "ServiceNoExternalIps with allowUnqualified",
			objects: []runtime.Object{
				makeService(func(service *v1.Service) {
					service.Spec.ExternalIPs = nil
				}),
			},
			expectDnsnames: []string{
				"172-1-0-3.somenamespace.pod.cluster.local",
				"tls-service.somenamespace.svc.cluster.local",
				"tls-service.somenamespace.svc",
			},
			expectIps: []string{"172.1.0.3", "10.0.0.1"},
		},
	} {
		t.Run(testcase.name, func(t *testing.T) {
			clusterDomain := testcase.clusterDomain
			if clusterDomain == "" {
				clusterDomain = "cluster.local"
			}
			pod := v1.Pod{
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
				Spec: v1.PodSpec{
					ServiceAccountName: "someserviceaccount",
				},
				Status: v1.PodStatus{
					PodIP: "172.1.0.3",
				},
			}
			if testcase.setupPod != nil {
				testcase.setupPod(&pod)
			}
			client := fake.NewSimpleClientset(testcase.objects...)
			dnsnames, ips, err := podnames.GetNamesForPod(client, pod, clusterDomain, testcase.allowUnqualified)

			assert.Subset(t, testcase.expectDnsnames, dnsnames, "Dnsnames contains all expected values")
			assert.Subset(t, dnsnames, testcase.expectDnsnames, dnsnames, "All values in dnsnames are expected")
			expectIps := make([]net.IP, 0, len(testcase.expectIps))
			for _, expectIp := range testcase.expectIps {
				expectIps = append(expectIps, net.ParseIP(expectIp))
			}
			assert.Subset(t, expectIps, ips, "Ips contains all expected values")
			assert.Subset(t, ips, expectIps, "All values in ips are expected")
			if testcase.expectErr == "" {
				assert.NoError(t, err, "Error")
			} else {
				assert.EqualError(t, err, testcase.expectErr, "Error")
			}
		})
	}
}

func makeService(setupService func(service *v1.Service)) *v1.Service {
	service := v1.Service{
		ObjectMeta: metaV1.ObjectMeta{
			Name:      "tls-service",
			Namespace: "somenamespace",
			Labels: map[string]string{
				"app": "some-service",
			},
		},
		Spec: v1.ServiceSpec{
			Selector:     map[string]string{"app": "some-app"},
			ClusterIP:    "10.0.0.1",
			Type:         v1.ServiceTypeLoadBalancer,
			ExternalName: "someexternalname.somedomain.invalid",
			ExternalIPs:  []string{"10.1.2.3", "10.1.2.4"},
		},
	}
	setupService(&service)
	return &service
}
