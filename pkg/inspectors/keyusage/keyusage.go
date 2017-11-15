package keyusage

import (
	"errors"
	"fmt"
	"github.com/proofpoint/kapprover/pkg/inspectors"
	"k8s.io/client-go/kubernetes"
	certificates "k8s.io/client-go/pkg/apis/certificates/v1beta1"
	"strings"
)

func init() {
	inspectors.Register("keyusage", &keyusage{map[certificates.KeyUsage]bool{
		certificates.UsageDigitalSignature: true,
		certificates.UsageKeyEncipherment:  true,
		certificates.UsageServerAuth:       true,
		certificates.UsageClientAuth:       true,
	}})
}

// Keyusage is an Inspector that verifies that all of the requested key usages are permitted.
type keyusage struct {
	permittedKeyUsages map[certificates.KeyUsage]bool
}

var supportedKeyUsages = map[string]certificates.KeyUsage{
	"signing":             certificates.UsageSigning,
	"digital signature":   certificates.UsageDigitalSignature,
	"content committment": certificates.UsageContentCommittment,
	"key encipherment":    certificates.UsageKeyEncipherment,
	"key agreement":       certificates.UsageKeyAgreement,
	"data encipherment":   certificates.UsageDataEncipherment,
	"cert sign":           certificates.UsageCertSign,
	"crl sign":            certificates.UsageCRLSign,
	"encipher only":       certificates.UsageEncipherOnly,
	"decipher only":       certificates.UsageDecipherOnly,
	"any":                 certificates.UsageAny,
	"server auth":         certificates.UsageServerAuth,
	"client auth":         certificates.UsageClientAuth,
	"code signing":        certificates.UsageCodeSigning,
	"email protection":    certificates.UsageEmailProtection,
	"s/mime":              certificates.UsageSMIME,
	"ipsec end system":    certificates.UsageIPsecEndSystem,
	"ipsec tunnel":        certificates.UsageIPsecTunnel,
	"ipsec user":          certificates.UsageIPsecUser,
	"timestamping":        certificates.UsageTimestamping,
	"ocsp signing":        certificates.UsageOCSPSigning,
	"microsoft sgc":       certificates.UsageMicrosoftSGC,
	"netscape sgc":        certificates.UsageNetscapSGC,
}

func (k *keyusage) Configure(config string) error {
	if config != "" {
		k.permittedKeyUsages = map[certificates.KeyUsage]bool{}
		for _, keyUsage := range strings.Split(config, ",") {
			usage, ok := supportedKeyUsages[strings.Replace(strings.ToLower(keyUsage), "_", " ", -1)]
			if !ok {
				return errors.New(fmt.Sprintf("unsupported usage %s", keyUsage))
			}
			k.permittedKeyUsages[usage] = true
		}
	}
	return nil
}

func (k *keyusage) Inspect(client *kubernetes.Clientset, request *certificates.CertificateSigningRequest) (string, error) {
	badUsages := ""
	sep := ""
	for _, keyUsage := range request.Spec.Usages {
		if !k.permittedKeyUsages[keyUsage] {
			badUsages += sep + string(keyUsage)
			sep = ","
		}
	}

	if badUsages == "" {
		return "", nil
	}

	msg := "Contains key usage"
	if strings.Index(badUsages, ",") != -1 {
		msg += "s"
	}
	return fmt.Sprintf("%s %s", msg, badUsages), nil
}
