package permissions

import (
	"github.com/mattermost/mattermost-server/v5/model"
)

type Permissions []*model.Permission

var permissions = Permissions{}

func New() *Permissions {
	permissions = model.ALL_PERMISSIONS

	return &permissions
}

func (p *Permissions) GetAll() Permissions {
	return model.ALL_PERMISSIONS
}

