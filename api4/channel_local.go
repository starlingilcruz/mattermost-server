// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

package api4

import (
	"net/http"

	"github.com/mattermost/mattermost-server/v5/audit"
	"github.com/mattermost/mattermost-server/v5/model"
)

func (api *API) InitChannelLocal() {
	api.BaseRoutes.Channels.Handle("", api.ApiLocal(getAllChannels)).Methods("GET")
	api.BaseRoutes.Channels.Handle("", api.ApiLocal(localCreateChannel)).Methods("POST")
	api.BaseRoutes.Channel.Handle("", api.ApiLocal(getChannel)).Methods("GET")
	api.BaseRoutes.ChannelByName.Handle("", api.ApiLocal(getChannelByName)).Methods("GET")
	api.BaseRoutes.Channel.Handle("", api.ApiLocal(deleteChannel)).Methods("DELETE")
	api.BaseRoutes.Channel.Handle("/patch", api.ApiLocal(localPatchChannel)).Methods("PUT")

	api.BaseRoutes.ChannelMember.Handle("", api.ApiLocal(localRemoveChannelMember)).Methods("DELETE")
	api.BaseRoutes.ChannelMember.Handle("", api.ApiLocal(getChannelMember)).Methods("GET")
	api.BaseRoutes.ChannelMembers.Handle("", api.ApiLocal(localAddChannelMember)).Methods("POST")
	api.BaseRoutes.ChannelMembers.Handle("", api.ApiLocal(getChannelMembers)).Methods("GET")

	api.BaseRoutes.ChannelsForTeam.Handle("", api.ApiLocal(getPublicChannelsForTeam)).Methods("GET")
	api.BaseRoutes.ChannelsForTeam.Handle("/deleted", api.ApiLocal(getDeletedChannelsForTeam)).Methods("GET")
	api.BaseRoutes.ChannelsForTeam.Handle("/private", api.ApiLocal(getPrivateChannelsForTeam)).Methods("GET")

	api.BaseRoutes.ChannelByName.Handle("", api.ApiLocal(getChannelByName)).Methods("GET")
	api.BaseRoutes.ChannelByNameForTeamName.Handle("", api.ApiLocal(getChannelByNameForTeamName)).Methods("GET")
}

func localCreateChannel(c *Context, w http.ResponseWriter, r *http.Request) {
	channel := model.ChannelFromJson(r.Body)
	if channel == nil {
		c.SetInvalidParam("channel")
		return
	}

	auditRec := c.MakeAuditRecord("localCreateChannel", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("channel", channel)

	sc, err := c.App.CreateChannel(channel, false)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	auditRec.AddMeta("channel", sc) // overwrite meta
	c.LogAudit("name=" + channel.Name)

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(sc.ToJson()))
}

func localAddChannelMember(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireChannelId()
	if c.Err != nil {
		return
	}

	props := model.StringInterfaceFromJson(r.Body)
	userId, ok := props["user_id"].(string)
	if !ok || !model.IsValidId(userId) {
		c.SetInvalidParam("user_id")
		return
	}

	user, err := c.App.GetUser(userId)
	if err != nil {
		c.Err = err
		return
	}

	channel, err := c.App.GetChannel(c.Params.ChannelId)
	if err != nil {
		c.Err = err
		return
	}

	auditRec := c.MakeAuditRecord("localAddChannelMember", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("channel", channel)

	if channel.Type == model.CHANNEL_DIRECT || channel.Type == model.CHANNEL_GROUP {
		c.Err = model.NewAppError("addUserToChannel", "api.channel.add_user_to_channel.type.app_error", nil, "", http.StatusBadRequest)
		return
	}

	if channel.IsGroupConstrained() {
		nonMembers, err := c.App.FilterNonGroupChannelMembers([]string{user.Id}, channel)
		if err != nil {
			if v, ok := err.(*model.AppError); ok {
				c.Err = v
			} else {
				c.Err = model.NewAppError("addChannelMember", "api.channel.add_members.error", nil, err.Error(), http.StatusBadRequest)
			}
			return
		}
		if len(nonMembers) > 0 {
			c.Err = model.NewAppError("addChannelMember", "api.channel.add_members.user_denied", map[string]interface{}{"UserIDs": nonMembers}, "", http.StatusBadRequest)
			return
		}
	}

	cm, err := c.App.AddUserToChannel(user, channel)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	auditRec.AddMeta("add_user_id", cm.UserId)
	c.LogAudit("name=" + channel.Name + " user_id=" + cm.UserId)

	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(cm.ToJson()))
}

func localRemoveChannelMember(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireChannelId().RequireUserId()
	if c.Err != nil {
		return
	}

	channel, err := c.App.GetChannel(c.Params.ChannelId)
	if err != nil {
		c.Err = err
		return
	}

	user, err := c.App.GetUser(c.Params.UserId)
	if err != nil {
		c.Err = err
		return
	}

	if !(channel.Type == model.CHANNEL_OPEN || channel.Type == model.CHANNEL_PRIVATE) {
		c.Err = model.NewAppError("removeChannelMember", "api.channel.remove_channel_member.type.app_error", nil, "", http.StatusBadRequest)
		return
	}

	if channel.IsGroupConstrained() && !user.IsBot {
		c.Err = model.NewAppError("removeChannelMember", "api.channel.remove_member.group_constrained.app_error", nil, "", http.StatusBadRequest)
		return
	}

	auditRec := c.MakeAuditRecord("localRemoveChannelMember", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("channel", channel)
	auditRec.AddMeta("remove_user_id", user.Id)

	if err = c.App.RemoveUserFromChannel(c.Params.UserId, "", channel); err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	c.LogAudit("name=" + channel.Name + " user_id=" + c.Params.UserId)

	ReturnStatusOK(w)
}

func localPatchChannel(c *Context, w http.ResponseWriter, r *http.Request) {
	c.RequireChannelId()
	if c.Err != nil {
		return
	}

	patch := model.ChannelPatchFromJson(r.Body)
	if patch == nil {
		c.SetInvalidParam("channel")
		return
	}

	originalOldChannel, err := c.App.GetChannel(c.Params.ChannelId)
	if err != nil {
		c.Err = err
		return
	}
	channel := originalOldChannel.DeepCopy()

	auditRec := c.MakeAuditRecord("localPatchChannel", audit.Fail)
	defer c.LogAuditRec(auditRec)
	auditRec.AddMeta("channel", channel)

	channel.Patch(patch)
	rchannel, err := c.App.UpdateChannel(channel)
	if err != nil {
		c.Err = err
		return
	}

	err = c.App.FillInChannelProps(rchannel)
	if err != nil {
		c.Err = err
		return
	}

	auditRec.Success()
	c.LogAudit("")
	auditRec.AddMeta("patch", rchannel)

	w.Write([]byte(rchannel.ToJson()))
}
