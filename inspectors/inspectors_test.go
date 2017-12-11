package inspectors_test

import (
	"github.com/proofpoint/kapprover/inspectors"
	"github.com/stretchr/testify/assert"
	"testing"

	_ "github.com/proofpoint/kapprover/inspectors/group"
	_ "github.com/proofpoint/kapprover/inspectors/signaturealgorithm"
	_ "github.com/proofpoint/kapprover/inspectors/username"
)

func TestInspectors(t *testing.T) {
	var i inspectors.Inspectors
	assert := assert.New(t)

	actual := i.String()
	assert.Empty(actual, "default Inspectors.String()")
	assert.Len(i, 0, "default Inspectors")

	assert.NoError(i.Set("group=system:serviceaccount"))
	assert.Equal("group=system:serviceaccount", i.String(), "Inspectors.String()")
	assert.Len(i, 1, "Inspectors")
	assert.Equal("group", i[0].Name, "Inspectors[0].Name")

	assert.NoError(i.Set("username"))
	assert.Equal("group=system:serviceaccount,username", i.String(), "Inspectors.String()")
	assert.Len(i, 2, "Inspectors")
	assert.Equal("username", i[1].Name, "Inspectors[1].Name")

	i = inspectors.Inspectors{}
	assert.NoError(i.Set("signaturealgorithm=SHA256WithRSA,SHA384WithRSA"))
	assert.Equal("signaturealgorithm=SHA256WithRSA,SHA384WithRSA", i.String(), "Inspectors.String()")
	assert.Len(i, 1, "Inspectors")
	assert.Equal("signaturealgorithm", i[0].Name, "Inspectors[0].Name")

	i = inspectors.Inspectors{}
	assert.Error(i.Set("notonlist"))
}
