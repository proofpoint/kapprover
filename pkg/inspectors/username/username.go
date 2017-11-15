package username

import (
	"fmt"
	"github.com/proofpoint/kapprover/pkg/inspectors"
	"k8s.io/client-go/kubernetes"
	certificates "k8s.io/client-go/pkg/apis/certificates/v1beta1"
)

func init() {
	inspectors.Register("username", &username{"kubelet-bootstrap"})
}

// Username is an Inspector that verifies the CSR was submitted
// by the configured user.
type username struct {
	requiredUsername string
}

func (u *username) Configure(config string) error {
	if config != "" {
		u.requiredUsername = config
	}
	return nil
}

func (u *username) Inspect(client kubernetes.Interface, request *certificates.CertificateSigningRequest) (string, error) {
	if request.Spec.Username != u.requiredUsername {
		return fmt.Sprintf("Requesting user is not %s", u.requiredUsername), nil
	}

	return "", nil
}
