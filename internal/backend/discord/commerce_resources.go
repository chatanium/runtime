package discordbackend

import (
	"context"
	"net/url"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
)

func (b *Backend) resolveSKU(ctx context.Context, p runtime.InstancePrincipal, id string) (*corewire.ResourceScope, error) {
	if !snowflake(id) {
		return nil, invalid("DISCORD_RESOURCE_INVALID")
	}
	var values []struct {
		ID            string `json:"id"`
		ApplicationID string `json:"application_id"`
	}
	if e := b.readJSON(ctx, p, "/applications/"+b.config.ApplicationID+"/skus", &values); e != nil {
		return nil, e
	}
	for _, value := range values {
		if value.ID == id && value.ApplicationID == b.config.ApplicationID {
			return scope(map[string]string{"sku_id": id, "application_id": b.config.ApplicationID}), nil
		}
	}
	return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
}
func (b *Backend) subscriptionResources(ctx context.Context, p runtime.InstancePrincipal, operation string, plan *RESTPlan) ([]*corewire.ResourceScope, error) {
	if operation != "Subscription" && operation != "Subscriptions" {
		return nil, nil
	}
	sku, subscription, user := "", "", ""
	for _, target := range plan.Targets {
		switch target.Kind {
		case "sku_id":
			sku = target.ID
		case "subscription_id":
			subscription = target.ID
		case "user_id":
			user = target.ID
		}
	}
	if !snowflake(sku) || (subscription != "" && !snowflake(subscription)) || (user != "" && !snowflake(user)) {
		return nil, invalid("DISCORD_RESOURCE_INVALID")
	}
	resolved, e := b.resolveSKU(ctx, p, sku)
	if e != nil {
		return nil, e
	}
	ids := resolved.GetSelector().ResourceIds
	if subscription != "" {
		path := "/skus/" + sku + "/subscriptions/" + subscription
		if user != "" {
			path += "?user_id=" + url.QueryEscape(user)
		}
		var actual struct {
			ID     string   `json:"id"`
			UserID string   `json:"user_id"`
			SKUIDs []string `json:"sku_ids"`
		}
		if e = b.readJSON(ctx, p, path, &actual); e != nil {
			return nil, e
		}
		matched := false
		for _, id := range actual.SKUIDs {
			matched = matched || id == sku
		}
		if actual.ID != subscription || !snowflake(actual.UserID) || (user != "" && user != actual.UserID) || !matched {
			return nil, denied("RESOURCE_RELATIONSHIP_DENIED")
		}
		ids["subscription_id"] = subscription
		ids["user_id"] = actual.UserID
	} else if user != "" {
		ids["user_id"] = user
	}
	return []*corewire.ResourceScope{scope(ids)}, nil
}
