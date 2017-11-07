package group_test

import (
	"github.com/proofpoint/kapprover/pkg/inspectors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/client-go/kubernetes"
	certificates "k8s.io/client-go/pkg/apis/certificates/v1beta1"
	"testing"

	_ "github.com/proofpoint/kapprover/pkg/inspectors/group"
)

var (
	client *kubernetes.Clientset
)

func TestInspect(t *testing.T) {
	inspector, exists := inspectors.Get("group")
	if !exists {
		t.Fatal("Expected inspectors.Get(\"group\") to exist, did not")
	}

	for group, expectedMessage := range map[string]string{
		"system:kubelet-bootstrap": "",
		"someOtherGroup":           "Requesting user is not in the system:kubelet-bootstrap group",
	} {
		assertInspectionResult(t, inspector, group, expectedMessage)
	}
}

func TestInspectConfigured(t *testing.T) {
	inspector, exists := inspectors.Get("group")
	require.True(t, exists, "inspectors.Get(\"group\") to exist")

	err := inspector.Configure("system:serviceaccount")
	assert.NoError(t, err, "Configure")

	for group, expectedMessage := range map[string]string{
		"system:serviceaccount":    "",
		"system:kubelet-bootstrap": "Requesting user is not in the system:serviceaccount group",
	} {
		assertInspectionResult(t, inspector, group, expectedMessage)
	}
}

func assertInspectionResult(t *testing.T, inspector inspectors.Inspector, group string, expectedMessage string) {
	request := certificates.CertificateSigningRequest{
		Spec: certificates.CertificateSigningRequestSpec{
			Username: "someRandomUser",
			Groups: []string{
				"someRandomGroup",
				group,
			},
		},
	}
	message, err := inspector.Inspect(client, &request)
	assert.Equal(t, expectedMessage, message, "Group", group)
	assert.NoError(t, err, "Group", group)
}
