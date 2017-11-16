package keyusage_test

import (
	"github.com/proofpoint/kapprover/pkg/inspectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/client-go/kubernetes"
	"testing"

	"fmt"
	_ "github.com/proofpoint/kapprover/pkg/inspectors/signaturealgorithm"
	"strings"
)

var (
	client *kubernetes.Clientset
)

var keyUsages = []struct {
	keyusage      certificates.KeyUsage
	expectDefault bool
}{
	{certificates.UsageSigning, false},
	{certificates.UsageDigitalSignature, true},
	{certificates.UsageContentCommittment, false},
	{certificates.UsageKeyEncipherment, true},
	{certificates.UsageKeyAgreement, false},
	{certificates.UsageDataEncipherment, false},
	{certificates.UsageCertSign, false},
	{certificates.UsageCRLSign, false},
	{certificates.UsageEncipherOnly, false},
	{certificates.UsageDecipherOnly, false},
	{certificates.UsageAny, false},
	{certificates.UsageServerAuth, true},
	{certificates.UsageClientAuth, true},
	{certificates.UsageCodeSigning, false},
	{certificates.UsageEmailProtection, false},
	{certificates.UsageSMIME, false},
	{certificates.UsageIPsecEndSystem, false},
	{certificates.UsageIPsecTunnel, false},
	{certificates.UsageIPsecUser, false},
	{certificates.UsageTimestamping, false},
	{certificates.UsageOCSPSigning, false},
	{certificates.UsageMicrosoftSGC, false},
	{certificates.UsageNetscapSGC, false},
}

func TestInspect(t *testing.T) {
	inspector, exists := inspectors.Get("keyusage")
	require.True(t, exists, "inspectors.Get(\"keyusage\") to exist")

	for _, testcase := range keyUsages {
		if testcase.expectDefault {
			assertInspectionResult(t, inspector, []certificates.KeyUsage{testcase.keyusage}, "")
		}
	}
	for _, testcase := range keyUsages {
		if !testcase.expectDefault {
			assertInspectionResult(t, inspector, []certificates.KeyUsage{testcase.keyusage}, fmt.Sprintf("Contains key usage %s", testcase.keyusage))
		}
	}
	assertInspectionResult(t, inspector, []certificates.KeyUsage{certificates.UsageAny, certificates.UsageTimestamping}, "Contains key usages any,timestamping")
}

func TestInspectConfigured(t *testing.T) {
	inspector, exists := inspectors.Get("keyusage")
	require.True(t, exists, "inspectors.Get(\"keyusage\") to exist")

	config := ""
	sep := ""
	for _, testcase := range keyUsages {
		if !testcase.expectDefault {
			config += sep + strings.Replace(string(testcase.keyusage), " ", "_", -1)
			sep = ","
		}
	}
	err := inspector.Configure(config)
	assert.NoError(t, err, "Configure")

	for _, testcase := range keyUsages {
		if !testcase.expectDefault {
			assertInspectionResult(t, inspector, []certificates.KeyUsage{testcase.keyusage}, "")
		}
	}
	for _, testcase := range keyUsages {
		if testcase.expectDefault {
			assertInspectionResult(t, inspector, []certificates.KeyUsage{testcase.keyusage}, fmt.Sprintf("Contains key usage %s", testcase.keyusage))
		}
	}
}

func TestConfigureBadKeyusage(t *testing.T) {
	for _, keyUsage := range []string{
		"Unknown",
	} {
		t.Run(keyUsage, func(t *testing.T) {
			inspector, exists := inspectors.Get("keyusage")
			require.True(t, exists, "inspectors.Get(\"keyusage\") to exist")

			err := inspector.Configure(keyUsage)
			assert.EqualErrorf(t, err, fmt.Sprintf("unsupported usage %s", keyUsage), "bad usage")
		})
	}
}

func assertInspectionResult(t *testing.T, inspector inspectors.Inspector, keyUsages []certificates.KeyUsage, expectedMessage string) {
	testname := ""
	sep := ""
	for _, keyUsage := range keyUsages {
		testname += sep + string(keyUsage)
		sep = ","
	}
	t.Run(testname, func(t *testing.T) {
		request := certificates.CertificateSigningRequest{
			Spec: certificates.CertificateSigningRequestSpec{
				Username: "someRandomUser",
				Usages:   keyUsages,
			},
		}
		message, err := inspector.Inspect(client, &request)
		assert.Equal(t, expectedMessage, message)
		assert.NoError(t, err)
	})
}
