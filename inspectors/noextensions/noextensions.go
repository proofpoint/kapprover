package noextensions

import (
	"errors"
	"github.com/proofpoint/kapprover/csr"
	"github.com/proofpoint/kapprover/inspectors"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
)

func init() {
	inspectors.Register("noextensions", &noextensions{})
}

// Noextensions is an Inspector that verifies that the CSR has no X.509 extensions
// other than SubjectAltName
type noextensions struct {
}

var (
	oidExtensionSubjectAltName = []int{2, 5, 29, 17}
)

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

	numBad := 0
	bad := ""
	sep := " "
	for _, extension := range certificateRequest.Extensions {
		if !extension.Id.Equal(oidExtensionSubjectAltName) {
			bad += sep + extension.Id.String()
			sep = ","
			numBad++
		}
	}

	if numBad == 0 {
		return "", nil
	}

	msg = "Contains X.509 extension"
	if numBad > 1 {
		msg += "s"
	}
	msg += bad

	return msg, nil
}
