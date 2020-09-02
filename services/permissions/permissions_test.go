package permissions

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPermissionConfig(t *testing.T) {
	perms := New()
	assert.NotEmpty(t, perms.GetAll())
}