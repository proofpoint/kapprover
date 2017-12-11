package signaturealgorithm

import (
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/proofpoint/kapprover/csr"
	"github.com/proofpoint/kapprover/inspectors"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
	"strings"
)

func init() {
	inspectors.Register("signaturealgorithm", &signaturealgorithm{map[x509.SignatureAlgorithm]bool{
		x509.SHA256WithRSA:    true,
		x509.SHA384WithRSA:    true,
		x509.SHA512WithRSA:    true,
		x509.SHA256WithRSAPSS: true,
		x509.SHA384WithRSAPSS: true,
		x509.SHA512WithRSAPSS: true,
	}})
}

// SignatureAlgorithm is an Inspector that verifies that the CSR's signature algorithm is in a permitted set.
// As the signature algorithm constrains the key type, it also verifies the public key type is in a permitted set.
type signaturealgorithm struct {
	permittedAlgorithms map[x509.SignatureAlgorithm]bool
}

var supportedAlgorithms = map[string]x509.SignatureAlgorithm{
	// MD2WithRSA not permitted
	"md5withrsa":       x509.MD5WithRSA,
	"sha1withrsa":      x509.SHA1WithRSA,
	"sha256withrsa":    x509.SHA256WithRSA,
	"sha384withrsa":    x509.SHA384WithRSA,
	"sha512withrsa":    x509.SHA512WithRSA,
	"ecdsawithsha1":    x509.ECDSAWithSHA1,
	"ecdsawithsha256":  x509.ECDSAWithSHA256,
	"ecdsawithsha384":  x509.ECDSAWithSHA384,
	"ecdsawithsha512":  x509.ECDSAWithSHA512,
	"sha256withrsapss": x509.SHA256WithRSAPSS,
	"sha384withrsapss": x509.SHA384WithRSAPSS,
	"sha512withrsapss": x509.SHA512WithRSAPSS,
}

func (s *signaturealgorithm) Configure(config string) (inspectors.Inspector, error) {
	if config != "" {
		ret := signaturealgorithm{permittedAlgorithms: map[x509.SignatureAlgorithm]bool{}}
		for _, signatureAlgorithm := range strings.Split(config, ",") {
			algorithm, ok := supportedAlgorithms[strings.ToLower(signatureAlgorithm)]
			if !ok {
				return nil, errors.New(fmt.Sprintf("unsupported SignatureAlgorithm %s", signatureAlgorithm))
			}
			ret.permittedAlgorithms[algorithm] = true
		}
		return &ret, nil
	}
	return s, nil
}

func (s *signaturealgorithm) Inspect(client kubernetes.Interface, request *certificates.CertificateSigningRequest) (string, error) {
	certificateRequest, msg := csr.Extract(request.Spec.Request)
	if msg != "" {
		return msg, nil
	}

	if s.permittedAlgorithms[certificateRequest.SignatureAlgorithm] {
		return "", nil
	}

	return fmt.Sprintf("SignatureAlgorithm is %s", certificateRequest.SignatureAlgorithm), nil
}
