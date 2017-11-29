package username

import (
	"fmt"
	"github.com/proofpoint/kapprover/pkg/inspectors"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
)

func init() {
	inspectors.Register("username", &username{"kubelet-bootstrap"})
}

// Username is an Inspector that verifies the CSR was submitted
// by the configured user.
type username struct {
	requiredUsername string
}

func (u *username) Configure(config string) (inspectors.Inspector, error) {
	if config != "" {
		return &username{requiredUsername: config}, nil
	}
	return u, nil
}

func (u *username) Inspect(client kubernetes.Interface, request *certificates.CertificateSigningRequest) (string, error) {
	if request.Spec.Username != u.requiredUsername {
		return fmt.Sprintf("Requesting user is not %s", u.requiredUsername), nil
	}

	return "", nil
}
