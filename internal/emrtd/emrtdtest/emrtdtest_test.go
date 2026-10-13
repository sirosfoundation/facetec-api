package emrtdtest

import (
	"encoding/base64"
	"testing"

	"github.com/gmrtd/gmrtd/document"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func dataGroup(t *testing.T, c *Chip, name string) []byte {
	t.Helper()
	b64, ok := c.Raw[name]
	require.True(t, ok, "%s present", name)
	b, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	return b
}

func TestNew_DefaultsHaveNoDG11(t *testing.T) {
	c := New(Options{})
	assert.Contains(t, c.Raw, "SOD")
	assert.Contains(t, c.Raw, "DG1")
	assert.Contains(t, c.Raw, "DG2")
	assert.NotContains(t, c.Raw, "DG11")

	dg1, err := document.NewDG1(dataGroup(t, c, "DG1"))
	require.NoError(t, err)
	assert.Equal(t, "F", dg1.Mrz.Sex)
	assert.Equal(t, "ERIKSSON", dg1.Mrz.NameOfHolder.Primary)
}

func TestNew_DG11RoundTrips(t *testing.T) {
	c := New(Options{DG11Name: "ERIKSSON<LINDQVIST<<ANNA<MARIA<SOFIA", DG11FullDateOfBirth: "19850307"})

	dg11, err := document.NewDG11(dataGroup(t, c, "DG11"))
	require.NoError(t, err)
	require.NotNil(t, dg11.Details.NameOfHolder)
	assert.Equal(t, "ERIKSSON LINDQVIST", dg11.Details.NameOfHolder.Primary)
	assert.Equal(t, "ANNA MARIA SOFIA", dg11.Details.NameOfHolder.Secondary)
	assert.Equal(t, "19850307", dg11.Details.FullDateOfBirth)
}

func TestNew_DG11WithOnlyOneElement(t *testing.T) {
	c := New(Options{DG11FullDateOfBirth: "19850307"})

	dg11, err := document.NewDG11(dataGroup(t, c, "DG11"))
	require.NoError(t, err)
	assert.Nil(t, dg11.Details.NameOfHolder)
	assert.Equal(t, "19850307", dg11.Details.FullDateOfBirth)
}

func TestNew_DG1SexAndExpiryOverrides(t *testing.T) {
	c := New(Options{DG1Sex: "M", DG1ExpiryYYMMDD: "290101"})

	dg1, err := document.NewDG1(dataGroup(t, c, "DG1"))
	require.NoError(t, err)
	assert.Equal(t, "M", dg1.Mrz.Sex)
	assert.Equal(t, "290101", dg1.Mrz.DateOfExpiry)
}
