package noextensions

import (
	"errors"
	"github.com/proofpoint/kapprover/pkg/csr"
	"github.com/proofpoint/kapprover/pkg/inspectors"
	"k8s.io/client-go/kubernetes"
	certificates "k8s.io/client-go/pkg/apis/certificates/v1beta1"
)

func init() {
	inspectors.Register("noextensions", &noextensions{})
}

// Noextensions is an Inspector that verifies that the CSR has no X.509 extensions
type noextensions struct {
}

func (n *noextensions) Configure(config string) error {
	if config != "" {
		return errors.New("configuration not supported")
	}
	return nil
}

func (n *noextensions) Inspect(client kubernetes.Interface, request *certificates.CertificateSigningRequest) (string, error) {
	certificateRequest, msg := csr.Extract(request.Spec.Request)
	if msg != "" {
		return msg, nil
	}

	if len(certificateRequest.Extensions) == 0 {
		return "", nil
	}

	msg = "Contains X.509 extension"
	if len(certificateRequest.Extensions) > 1 {
		msg += "s"
	}
	sep := " "
	for _, extension := range certificateRequest.Extensions {
		msg += sep + extension.Id.String()
		sep = ","
	}

	return msg, nil
}
