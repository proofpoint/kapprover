package subjectispodforuser

import (
	"fmt"
	"github.com/proofpoint/kapprover/pkg/csr"
	"github.com/proofpoint/kapprover/pkg/inspectors"
	certificates "k8s.io/api/certificates/v1beta1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"strconv"
	"strings"
)

func init() {
	inspectors.Register("subjectispodforuser", &subjectispodforuser{"cluster.local"})
}

// SubjectIsPodForUser is an Inspector that verifies the CSR contains a subject that contains only
// the DNS name for a POD in a deployment that has the requesting username as the service account
type subjectispodforuser struct {
	clusterDomain string
}

func (s *subjectispodforuser) Configure(config string) error {
	if config != "" {
		s.clusterDomain = config
	}
	return nil
}

func (s *subjectispodforuser) Inspect(client kubernetes.Interface, request *certificates.CertificateSigningRequest) (string, error) {
	certificateRequest, msg := csr.Extract(request.Spec.Request)
	if msg != "" {
		return msg, nil
	}

	if len(certificateRequest.Subject.Names) > 1 {
		return "Subject has more than one name component", nil
	}

	if !strings.HasSuffix(certificateRequest.Subject.CommonName, ".pod."+s.clusterDomain) {
		return fmt.Sprintf("Subject %q is not in the pod.%s domain", certificateRequest.Subject.CommonName, s.clusterDomain), nil
	}

	splitName := strings.Split(strings.TrimSuffix(certificateRequest.Subject.CommonName, ".pod."+s.clusterDomain), ".")
	if len(splitName) != 2 {
		return fmt.Sprintf("Subject %q is not a POD-format name", certificateRequest.Subject.CommonName), nil
	}

	namespace := splitName[1]
	splitIp := strings.Split(splitName[0], "-")
	if len(splitIp) != 4 {
		return fmt.Sprintf("Subject %q is not a POD-format name", certificateRequest.Subject.CommonName), nil
	}
	for _, byteStr := range splitIp {
		val, err := strconv.ParseUint(byteStr, 10, 8)
		if err != nil || (val == 0 && byteStr != "0") || (byteStr[0] == '0' && val != 0) {
			return fmt.Sprintf("Subject %q is not a POD-format name", certificateRequest.Subject.CommonName), nil
		}
	}
	podIp := strings.Join(splitIp, ".")

	podList, err := client.CoreV1().Pods(namespace).List(metaV1.ListOptions{FieldSelector: "status.podIp=" + podIp})
	if err != nil {
		return "", err
	}
	if len(podList.Items) == 0 {
		return fmt.Sprintf("No POD in namespace %q with IP %q", namespace, podIp), nil
	}

	expectedServiceAccount := "system:serviceaccount:" + namespace + ":" + podList.Items[0].Spec.ServiceAccountName
	if request.Spec.Username != expectedServiceAccount {
		return fmt.Sprintf("Requesting user is not %q", expectedServiceAccount), nil
	}

	return "", nil
}
