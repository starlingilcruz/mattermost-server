// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package api4

import (
	"net/http"

	"github.com/mattermost/mattermost-server/v5/audit"
	"github.com/mattermost/mattermost-server/v5/model"
)

func (api *API) InitRole() {
	api.BaseRoutes.Roles.Handle("", api.ApiSessionRequired(createRole)).Methods("POST")
	api.BaseRoutes.Roles.Handle("/{role_id:[A-Za-z0-9]+}", api.ApiSessionRequiredTrustRequester(getRole)).Methods("GET")
	api.BaseRoutes.Roles.Handle("/name/{role_name:[a-z0-9_]+}", api.ApiSessionRequiredTrustRequester(getRoleByName)).Methods("GET")
	api.BaseRoutes.Roles.Handle("/names", api.ApiSessionRequiredTrustRequester(getRolesByNames)).Methods("POST")
	api.BaseRoutes.Roles.Handle("/{role_id:[A-Za-z0-9]+}/patch", api.ApiSessionRequired(patchRole)).Methods("PUT")
	api.BaseRoutes.Roles.Handle("/{role_id:[A-Za-z0-9]+}", api.ApiSessionRequired(deleteRole)).Methods("DELETE")
}

func getRole(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireRoleId()
	if c.Err != nil {
		return
	}

	role, err := c.App.GetRole(c.Params.RoleId)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(role.ToJson()))
}

func getRoleByName(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireRoleName()
	if c.Err != nil {
		return
	}

	role, err := c.App.GetRoleByName(c.Params.RoleName)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(role.ToJson()))
}

func getRolesByNames(c *Context, w http.ResponseWriter, r *http.Request) {
	rolenames := model.ArrayFromJson(r.Body)

	if len(rolenames) == 0 {
		c.SetInvalidParam("rolenames")
		return
	}

	cleanedRoleNames, valid := model.CleanRoleNames(rolenames)
	if !valid {
		c.SetInvalidParam("rolename")
		return
	}

	roles, err := c.App.GetRolesByNames(cleanedRoleNames)
	if err != nil {
		c.Err = err
		return
	}

	w.Write([]byte(model.RoleListToJson(roles)))
}

func patchRole(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireRoleId()
	if c.Err != nil {
		return
	}

	patch := model.RolePatchFromJson(r.Body)
	if patch == nil {
		c.SetInvalidParam("role")
		return
	}

	auditRec := c.MakeAuditRecord("patchRole", audit.Fail)
	defer c.LogAuditRec(auditRec)

	oldRole, err := c.App.GetRole(c.Params.RoleId)
	if err != nil {
		c.Err = err
		return
	}
	auditRec.AddMeta("role", oldRole)

	if !c.App.SessionHasPermissionTo(*c.App.Session(), model.PERMISSION_MANAGE_SYSTEM) {
		c.SetPermissionError(model.PERMISSION_MANAGE_SYSTEM)
		return
	}

	role, err := c.App.PatchRole(oldRole, patch)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	auditRec.AddMeta("patch", role)
	c.LogAudit("")

	w.Write([]byte(role.ToJson()))
}


func createRole(c *Context, w http.ResponseWriter, r *http.Request) {
	role := model.RoleFromJson(r.Body)
	if role == nil {
		c.SetInvalidParam("role")
		return
	}

	if !c.App.SessionHasPermissionTo(*c.App.Session(), model.PERMISSION_MANAGE_SYSTEM) {
		c.SetPermissionError(model.PERMISSION_MANAGE_SYSTEM)
		return
	}

	role, err := c.App.CreateRole(role)
	if err != nil {
		c.Err = err
		return
	}

	auditRec := c.MakeAuditRecord("createRole", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("role", role)
	
	w.Write([]byte(role.ToJson()))
}


func deleteRole(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireRoleId()
	if c.Err != nil {
		return
	}

	auditRec := c.MakeAuditRecord("deleteRole", audit.Fail)
	defer c.LogAuditRec(auditRec)


	if !c.App.SessionHasPermissionTo(*c.App.Session(), model.PERMISSION_MANAGE_SYSTEM) {
		c.SetPermissionError(model.PERMISSION_MANAGE_SYSTEM)
		return
	}

	role, err := c.App.DeleteRole(c.Params.RoleId)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	auditRec.AddMeta("role", role)

	ReturnStatusOK(w)
}
