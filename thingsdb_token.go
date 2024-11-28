package vault_plugin_secrets_thingsdb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	thingsDBTokenType = "thingsdb_token"
)

// thingsDBToken defines a secret for the ThingsDb access token
type thingsDBToken struct {
	Token   string `json:"token"`
	User    string `json:"user"`
	TokenID string `json:"token_id"`
}

// thingsDBToken defines a secret to store for a given role
// and how it should be revoked or renewed.
func (b *thingsDBBackend) thingsDBToken() *framework.Secret {
	return &framework.Secret{
		Type: thingsDBTokenType,
		Fields: map[string]*framework.FieldSchema{
			"token": {
				Type:        framework.TypeString,
				Description: `The token for accesing ThingsDB`,
			},
			"user": {
				Type:        framework.TypeString,
				Description: `The newly created user associated with the token`,
			},
		},
		Revoke: b.tokenRevoke,
		Renew:  b.tokenRenew,
	}
}

func deleteToken(c *thingsDBClient, user string) error {
	vars := map[string]interface{}{
		"user": user,
	}

	_, err := c.Query("@thingsdb", "del_user({user});", vars)
	return err
}

func (b *thingsDBBackend) tokenRevoke(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("error getting client: %w", err)
	}

	user := ""
	userRaw, ok := req.Secret.InternalData["user"]
	if ok {
		user, ok = userRaw.(string)
		if !ok {
			return nil, fmt.Errorf("invalid value for user in secret internal data")
		}
	}

	if err := deleteToken(client, user); err != nil {
		return nil, fmt.Errorf("error revoking token: %w", err)
	}
	return nil, nil
}

func createToken(c *thingsDBClient, roleName string, target string, mask string) (*thingsDBToken, error) {
	// Generate random username
	timestamp := time.Now().Unix()
	username := fmt.Sprintf("%d_%s", timestamp, roleName)

	vars := map[string]interface{}{
		"user":   username,
		"target": target,
		"mask":   mask,
	}

	// Create the user in ThingsDB
	_, err := c.Query("@thingsdb", "new_user({user});", vars)
	if err != nil {
		return nil, err
	}

	// Grant priviledges to that user
	_, err = c.Query("@thingsdb", "grant({target}, {user}, {mask});", vars)
	if err != nil {
		return nil, err
	}

	// Generate a token
	tokenResp, err := c.Query("@thingsdb", "new_token({user});", vars)
	if err != nil {
		return nil, err
	}

	tokenID := uuid.New().String()

	return &thingsDBToken{
		User:    username,
		Token:   tokenResp.(string),
		TokenID: tokenID,
	}, nil
}

func (b *thingsDBBackend) tokenRenew(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}
