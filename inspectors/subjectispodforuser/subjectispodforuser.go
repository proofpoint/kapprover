package subjectispodforuser

import (
	"fmt"
	"github.com/proofpoint/kapprover/csr"
	"github.com/proofpoint/kapprover/inspectors"
	certificates "k8s.io/api/certificates/v1beta1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"github.com/sirupsen/logrus"
	"k8s.io/api/core/v1"
)

func init() {
	inspectors.Register("subjectispodforuser", &subjectispodforuser{"cluster.local"})
}

// SubjectIsPodForUser is an Inspector that verifies the CSR contains a subject that contains only
// the DNS name for a POD in a deployment that has the requesting username as the service account
type subjectispodforuser struct {
	clusterDomain string
}

func (s *subjectispodforuser) Configure(config string) (inspectors.Inspector, error) {
	if config != "" {
		return &subjectispodforuser{clusterDomain: config}, nil
	}
	return s, nil
}

func (s *subjectispodforuser) Inspect(client kubernetes.Interface, request *certificates.CertificateSigningRequest) (string, error) {
	certificateRequest, msg := csr.Extract(request.Spec.Request)
	if msg != "" {
		return msg, nil
	}

	podIp, namespace, msg := csr.GetPodIpAndNamespace(s.clusterDomain, certificateRequest)
	if msg != "" {
		return msg, nil
	}

	podList, err := client.CoreV1().Pods(namespace).List(metaV1.ListOptions{FieldSelector: "status.podIP=" + podIp})
	if err != nil {
		return "", err
	}

	filtered := make([]v1.Pod, 0, 1)
	for _, pod := range podList.Items {
		if pod.DeletionTimestamp != nil {
			continue
		}
		if pod.Status.Phase != v1.PodPending && pod.Status.Phase != v1.PodRunning {
			continue
		}
		filtered = append(filtered, pod)
	}

	if len(filtered) == 0 {
		return fmt.Sprintf("No pending or running POD in namespace %q with IP %q", namespace, podIp), nil
	}
	if len(filtered) > 1 {
		logrus.Warnf("Subjectispodforuser found multiple pods for IP %q", podIp)
		for _, pod := range filtered {
			logrus.Infof("Pod %+v", pod)
		}
	}

	expectedServiceAccount := "system:serviceaccount:" + namespace + ":" + filtered[0].Spec.ServiceAccountName
	if request.Spec.Username != expectedServiceAccount {
		return fmt.Sprintf("Requesting user %q is not %q", request.Spec.Username, expectedServiceAccount), nil
	}

	return "", nil
}
