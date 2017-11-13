package minrsakeysize

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"github.com/proofpoint/kapprover/pkg/csr"
	"github.com/proofpoint/kapprover/pkg/inspectors"
	"k8s.io/client-go/kubernetes"
	certificates "k8s.io/client-go/pkg/apis/certificates/v1beta1"
	"strconv"
)

func init() {
	inspectors.Register("minrsakeysize", &minrsakeysize{3072})
}

// Minkeysize is an Inspector that verifies that the CSR either has a non-RSA public key or has an
// RSA public key of at least a configured minimum size. If you want to restrict public keys, use
// the signaturealgorithm Inspector.
type minrsakeysize struct {
	minSize int
}

func (m *minrsakeysize) Configure(config string) error {
	if config != "" {
		minsize, err := strconv.ParseUint(config, 10, 0)
		if err != nil {
			return err
		}
		m.minSize = int(minsize)
	}
	return nil
}

func (m *minrsakeysize) Inspect(client *kubernetes.Clientset, request *certificates.CertificateSigningRequest) (string, error) {
	certificateRequest, msg := csr.Extract(request.Spec.Request)
	if msg != "" {
		return msg, nil
	}

	if certificateRequest.PublicKeyAlgorithm != x509.RSA {
		return "", nil
	}

	bitsize := certificateRequest.PublicKey.(*rsa.PublicKey).N.BitLen()
	if bitsize < m.minSize {
		return fmt.Sprintf("Public key too small: %d < %d", bitsize, m.minSize), nil
	}

	return "", nil
}
