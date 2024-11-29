package vault_plugin_secrets_thingsdb

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCredentials extends the Vault API with a `/creds`
// endpoint for a role.
func pathCredentials(b *thingsDBBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
			},
		},
		HelpSynopsis:    pathCredentialsHelpSynopsis,
		HelpDescription: pathCredentialsHelpDescription,
	}
}

func (b *thingsDBBackend) createToken(ctx context.Context, s logical.Storage, roleEntry *thingsDBRoleEntry) (*thingsDBToken, error) {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return nil, err
	}

	var token *thingsDBToken

	token, err = createToken(client, roleEntry.Target, roleEntry.Mask)
	if err != nil {
		return nil, fmt.Errorf("error creating token: %w", err)
	}

	if token == nil {
		return nil, errors.New("error creating token: no token returned")
	}

	return token, nil
}

func (b *thingsDBBackend) createUserCreds(ctx context.Context, req *logical.Request, role *thingsDBRoleEntry) (*logical.Response, error) {
	token, err := b.createToken(ctx, req.Storage, role)
	if err != nil {
		return nil, err
	}

	resp := b.Secret(thingsDBTokenType).Response(map[string]interface{}{
		"token":    token.Token,
		"token_id": token.TokenID,
		"user":     token.User,
	}, map[string]interface{}{
		"token": token.Token,
		"role":  role.Name,
		"user":  token.User,
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

func (b *thingsDBBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error reading role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	return b.createUserCreds(ctx, req, roleEntry)
}

const pathCredentialsHelpSynopsis = `
Generate a ThingsDB API Token using a specific role
`

const pathCredentialsHelpDescription = `
This path generates a ThingsDB API Token
based on a particular role.
`
