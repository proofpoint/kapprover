package noextensions

import (
	"errors"
	"github.com/proofpoint/kapprover/pkg/csr"
	"github.com/proofpoint/kapprover/pkg/inspectors"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
)

func init() {
	inspectors.Register("noextensions", &noextensions{})
}

// Noextensions is an Inspector that verifies that the CSR has no X.509 extensions
type noextensions struct {
}

func (n *noextensions) Configure(config string) (inspectors.Inspector, error) {
	if config != "" {
		return nil, errors.New("configuration not supported")
	}
	return n, nil
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
