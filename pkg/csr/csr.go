package csr

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func Extract(data []byte) (certificateRequest *x509.CertificateRequest, rejectMessage string) {
	certificateRequestBytes, rest := pem.Decode(data)
	if certificateRequestBytes == nil {
		return nil, "Request did not have a parseable PEM object"
	}

	extraneousPemObject, _ := pem.Decode(rest)
	if extraneousPemObject != nil {
		return nil, "Request had more than one PEM object"
	}

	certificateRequest, err := x509.ParseCertificateRequest(certificateRequestBytes.Bytes)
	if err != nil {
		return nil, fmt.Sprintf("Request had invalid certificate request: %s", err)
	}

	return certificateRequest, ""
}
