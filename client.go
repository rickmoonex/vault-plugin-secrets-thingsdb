package vault_plugin_secrets_thingsdb

import (
	"errors"
	"strconv"

	ti "github.com/thingsdb/go-thingsdb"
)

// thingsDBClient creates an object storing
// the ThingsDB Conn
type thingsDBClient struct {
	*ti.Conn
}

// newClient creates a new client to access ThingsDB
// and expose it for any secrets or roles to use.
func newClient(config *thingsDBConfig) (*thingsDBClient, error) {
	if config == nil {
		return nil, errors.New("client config is nil")
	}

	if config.Hostname == "" {
		return nil, errors.New("client hostname was not defined")
	}

	if config.Token == "" {
		return nil, errors.New("client token was not defined")
	}

	if config.Port == "" {
		return nil, errors.New("client port not provided")
	}

	parsedPort, err := strconv.ParseUint(config.Port, 10, 16)
	if err != nil {
		return nil, err
	}

	conn := ti.NewConn(config.Hostname, uint16(parsedPort), nil)
	if err := conn.Connect(); err != nil {
		return nil, err
	}
	if err := conn.AuthToken(config.Token); err != nil {
		return nil, err
	}
	return &thingsDBClient{conn}, nil
}
