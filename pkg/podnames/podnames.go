package podnames

import (
	"fmt"
	"k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"net"
	"strings"
)

// GetNamesForPod returns the DNS names and IPs that a given POD is permitted to have, either in its own right
// or by dint of matching services.
// Does not currently pay attention to static Endpoints.
func GetNamesForPod(client kubernetes.Interface, pod v1.Pod, clusterDomain string) (dnsnames []string, ips []net.IP, err error) {
	dnsnames = []string{fmt.Sprintf("%s.%s.pod.%s", ipToName(pod.Status.PodIP), pod.Namespace, clusterDomain)}
	if pod.Spec.Hostname != "" && pod.Spec.Subdomain != "" {
		dnsnames = append(dnsnames, fmt.Sprintf("%s.%s.%s.svc.%s", pod.Spec.Hostname, pod.Spec.Subdomain, pod.Namespace, clusterDomain))
	}

	ips = []net.IP{net.ParseIP(pod.Status.PodIP)}

	podLabels := labels.Set(pod.Labels)

	serviceList, err := client.CoreV1().Services(pod.Namespace).List(metaV1.ListOptions{})
	if err != nil {
		return nil, nil, err
	}
	for _, service := range serviceList.Items {
		if service.Spec.Selector == nil {
			continue
		}
		selector := labels.Set(service.Spec.Selector).AsSelectorPreValidated()
		if selector.Matches(podLabels) {
			dnsnames = append(dnsnames, fmt.Sprintf("%s.%s.svc.%s", service.Name, service.Namespace, clusterDomain))

			if service.Spec.Type == v1.ServiceTypeExternalName {
				if service.Spec.ExternalName != "" {
					dnsnames = append(dnsnames, service.Spec.ExternalName)
				}
			} else {
				appendIp(&ips, service.Spec.ClusterIP)
			}

			if service.Spec.ExternalIPs != nil {
				for _, externalIp := range service.Spec.ExternalIPs {
					appendIp(&ips, externalIp)
				}
			}
		}
	}

	return
}

func ipToName(ip string) string {
	return strings.Replace(ip, ".", "-", -1)
}

func appendIp(ipList *[]net.IP, ip string) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return
	}
	*ipList = append(*ipList, parsed)
}
