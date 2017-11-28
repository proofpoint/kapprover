package altnamesforpod

import (
	"fmt"
	"github.com/proofpoint/kapprover/pkg/csr"
	"github.com/proofpoint/kapprover/pkg/inspectors"
	"github.com/proofpoint/kapprover/pkg/podnames"
	certificates "k8s.io/api/certificates/v1beta1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"strings"
)

func init() {
	inspectors.Register("altnamesforpod", &altnamesforpod{"cluster.local"})
}

// AltNamesForPod is an Inspector that verifies all the Subject Alt Names in the CSR are appropriate
// for the POD named in the subject
type altnamesforpod struct {
	clusterDomain string
}

func (a *altnamesforpod) Configure(config string) error {
	if config != "" {
		a.clusterDomain = config
	}
	return nil
}

func (a *altnamesforpod) Inspect(client kubernetes.Interface, request *certificates.CertificateSigningRequest) (string, error) {
	certificateRequest, msg := csr.Extract(request.Spec.Request)
	if msg != "" {
		return msg, nil
	}

	podIp, namespace, msg := csr.GetPodIpAndNamespace(a.clusterDomain, certificateRequest)
	if msg != "" {
		return msg, nil
	}

	podList, err := client.CoreV1().Pods(namespace).List(metaV1.ListOptions{FieldSelector: "status.podIp=" + podIp})
	if err != nil {
		return "", err
	}
	if len(podList.Items) == 0 {
		return fmt.Sprintf("No POD in namespace %q with IP %q", namespace, podIp), nil
	}

	permittedDnsnames, permittedIps, err := podnames.GetNamesForPod(client, podList.Items[0], a.clusterDomain)
	if err != nil {
		return "", err
	}

	var badNames []string
	for _, name := range certificateRequest.DNSNames {
		found := false
		for _, permittedDnsname := range permittedDnsnames {
			if name == permittedDnsname {
				found = true
				break
			}
		}
		if !found {
			badNames = append(badNames, name)
		}
	}

	for _, ip := range certificateRequest.IPAddresses {
		found := false
		for _, permittedIp := range permittedIps {
			if ip.Equal(permittedIp) {
				found = true
				break
			}
		}
		if !found {
			badNames = append(badNames, ip.String())
		}
	}

	badNames = append(badNames, certificateRequest.EmailAddresses...)

	if len(badNames) != 0 {
		msg = "Subject Alt Name contains disallowed name"
		if len(badNames) != 1 {
			msg += "s"
		}
		msg += ": "
		msg += strings.Join(badNames, ",")
		return msg, nil
	}

	return "", nil
}
