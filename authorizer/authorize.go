package authorizer

import (
	"context"
	"fmt"

	"github.com/influxdata/influxdb"
	icontext "github.com/influxdata/influxdb/context"
)

// IsAllowed checks to see if an action is authorized by retrieving the authorizer
// off of context and authorizing the action appropriately.
func IsAllowed(ctx context.Context, p influxdb.Permission) error {
	a, err := icontext.GetAuthorizer(ctx)
	if err != nil {
		return err
	}
	return IsAuthorizerAllowedAll(a, []influxdb.Permission{p})
}

// IsAllowedAll checks to see if an action is authorized by ALL permissions.
// Also see IsAllowed.
func IsAllowedAll(ctx context.Context, permissions []influxdb.Permission) error {
	a, err := icontext.GetAuthorizer(ctx)
	if err != nil {
		return err
	}
	return IsAuthorizerAllowedAll(a, permissions)
}

// IsAuthorizerAllowed checks to see if an action is authorized by retrieving the authorizer
// off of context and authorizing the action appropriately.
func IsAuthorizerAllowed(a influxdb.Authorizer, p influxdb.Permission) error {
	return IsAuthorizerAllowedAll(a, []influxdb.Permission{p})
}

// IsAuthorizerAllowedAll checks to see if an action is authorized by ALL permissions.
// Also see IsAuthorizerAllowed.
func IsAuthorizerAllowedAll(a influxdb.Authorizer, permissions []influxdb.Permission) error {
	for _, p := range permissions {
		if !a.Allowed(p) {
			return &influxdb.Error{
				Code: influxdb.EUnauthorized,
				Msg:  fmt.Sprintf("%s is unauthorized", p),
			}
		}
	}
	return nil
}
