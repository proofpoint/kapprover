package csr

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
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

func GetPodIpAndNamespace(clusterDomain string, certificateRequest *x509.CertificateRequest) (podIp, namespace, message string) {
	if len(certificateRequest.Subject.Names) > 1 {
		return "", "", "Subject has more than one name component"
	}

	if !strings.HasSuffix(certificateRequest.Subject.CommonName, ".pod."+clusterDomain) {
		return "", "", fmt.Sprintf("Subject %q is not in the pod.%s domain", certificateRequest.Subject.CommonName, clusterDomain)
	}

	splitName := strings.Split(strings.TrimSuffix(certificateRequest.Subject.CommonName, ".pod."+clusterDomain), ".")
	if len(splitName) != 2 {
		return "", "", fmt.Sprintf("Subject %q is not a POD-format name", certificateRequest.Subject.CommonName)
	}

	splitIp := strings.Split(splitName[0], "-")
	if len(splitIp) != 4 {
		return "", "", fmt.Sprintf("Subject %q is not a POD-format name", certificateRequest.Subject.CommonName)
	}
	for _, byteStr := range splitIp {
		val, err := strconv.ParseUint(byteStr, 10, 8)
		if err != nil || (val == 0 && byteStr != "0") || (byteStr[0] == '0' && val != 0) {
			return "", "", fmt.Sprintf("Subject %q is not a POD-format name", certificateRequest.Subject.CommonName)
		}
	}
	return strings.Join(splitIp, "."), splitName[1], ""
}
