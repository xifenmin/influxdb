package authorizer

import (
	"context"
	"fmt"

	"github.com/influxdata/influxdb"
	icontext "github.com/influxdata/influxdb/context"
)

// authorizedWithOrgID adds the provided org as an owner of the document if
// the authorizer is allowed to access the org in being added.
func CreateDocumentAuthorizerOption(ctx context.Context, orgID influxdb.ID, orgName string) influxdb.DocumentOptions {
	if orgID.Valid() {
		return authorizedWithOrgID(ctx, orgID, influxdb.WriteAction)
	}
	return authorizedWithOrg(ctx, orgName, influxdb.WriteAction)
}

func GetDocumentsAuthorizerOption(ctx context.Context, orgID influxdb.ID, orgName string) influxdb.DocumentFindOptions {
	if orgID.Valid() {
		return authorizedWhereOrgID(ctx, orgID)
	}
	return authorizedWhereOrg(ctx, orgName)
}

func GetDocumentAuthorizerOption(ctx context.Context, docID influxdb.ID) influxdb.DocumentFindOptions {
	return authorizedRead(ctx, docID)
}

func UpdateDocumentAuthorizerOption(ctx context.Context, docID influxdb.ID) influxdb.DocumentOptions {
	return toDocumentOptions(authorizedWrite(ctx, docID))
}

func DeleteDocumentAuthorizerOption(ctx context.Context, docID influxdb.ID) influxdb.DocumentFindOptions {
	return authorizedWrite(ctx, docID)
}

func newDocumentPermission(a influxdb.Action, orgID, id influxdb.ID) (*influxdb.Permission, error) {
	return influxdb.NewPermissionAtID(id, a, influxdb.DocumentsResourceType, orgID)
}

func newDocumentOrgPermission(a influxdb.Action, orgID influxdb.ID) (*influxdb.Permission, error) {
	return influxdb.NewPermission(a, influxdb.DocumentsResourceType, orgID)
}

func authorizedMatchPermission(ctx context.Context, p influxdb.Permission) influxdb.DocumentFindOptions {
	return func(idx influxdb.DocumentIndex, _ influxdb.DocumentDecorator) ([]influxdb.ID, error) {
		if err := IsAllowed(ctx, p); err != nil {
			return nil, err
		}
		return []influxdb.ID{*p.Resource.ID}, nil
	}
}

func authorizedWhereIDs(ctx context.Context, orgID, docID influxdb.ID, action influxdb.Action) influxdb.DocumentFindOptions {
	return func(idx influxdb.DocumentIndex, dec influxdb.DocumentDecorator) ([]influxdb.ID, error) {
		p, err := newDocumentPermission(action, orgID, docID)
		if err != nil {
			return nil, err
		}
		return authorizedMatchPermission(ctx, *p)(idx, dec)
	}
}

func orgIDForDocument(ctx context.Context, idx influxdb.DocumentIndex, d influxdb.ID) (influxdb.ID, error) {
	oids, err := idx.GetDocumentsAccessors(d)
	if err != nil {
		return 0, err
	}
	if len(oids) == 0 {
		// This document has no accessor.
		// From the perspective of the user, it does not exist.
		return 0, &influxdb.Error{
			Code: influxdb.ENotFound,
			Msg:  influxdb.ErrDocumentNotFound,
		}
	}
	a, err := icontext.GetAuthorizer(ctx)
	if err != nil {
		return 0, err
	}
	for _, oid := range oids {
		if err := idx.IsOrgAccessor(a.GetUserID(), oid); err == nil {
			return oid, nil
		}
	}
	// There are accessors, but this user is not part of those ones.
	return 0, &influxdb.Error{
		Code: influxdb.EUnauthorized,
		Msg:  fmt.Sprintf("%s is unauthorized", a.GetUserID()),
	}
}

func authorizedWhereID(ctx context.Context, docID influxdb.ID, action influxdb.Action) influxdb.DocumentFindOptions {
	return func(idx influxdb.DocumentIndex, dec influxdb.DocumentDecorator) ([]influxdb.ID, error) {
		oid, err := orgIDForDocument(ctx, idx, docID)
		if err != nil {
			return nil, err
		}
		p, err := newDocumentPermission(action, oid, docID)
		if err != nil {
			return nil, err
		}
		return authorizedMatchPermission(ctx, *p)(idx, dec)
	}
}

func authorizedRead(ctx context.Context, docID influxdb.ID) influxdb.DocumentFindOptions {
	return func(idx influxdb.DocumentIndex, dec influxdb.DocumentDecorator) ([]influxdb.ID, error) {
		return authorizedWhereID(ctx, docID, influxdb.ReadAction)(idx, dec)
	}
}

func authorizedWrite(ctx context.Context, docID influxdb.ID) influxdb.DocumentFindOptions {
	return func(idx influxdb.DocumentIndex, dec influxdb.DocumentDecorator) ([]influxdb.ID, error) {
		return authorizedWhereID(ctx, docID, influxdb.WriteAction)(idx, dec)
	}
}

func authorizedWithOrgID(ctx context.Context, orgID influxdb.ID, action influxdb.Action) func(influxdb.ID, influxdb.DocumentIndex) error {
	return func(id influxdb.ID, idx influxdb.DocumentIndex) error {
		p, err := newDocumentOrgPermission(action, orgID)
		if err != nil {
			return err
		}
		if err := IsAllowed(ctx, *p); err != nil {
			return err
		}
		// This is required for retrieving later.
		return idx.AddDocumentOwner(id, "org", orgID)
	}
}

func authorizedWithOrg(ctx context.Context, org string, action influxdb.Action) func(influxdb.ID, influxdb.DocumentIndex) error {
	return func(id influxdb.ID, idx influxdb.DocumentIndex) error {
		oid, err := idx.FindOrganizationByName(org)
		if err != nil {
			return err
		}
		return authorizedWithOrgID(ctx, oid, action)(id, idx)
	}
}

func authorizedWhereOrgID(ctx context.Context, orgID influxdb.ID) influxdb.DocumentFindOptions {
	return func(idx influxdb.DocumentIndex, dec influxdb.DocumentDecorator) ([]influxdb.ID, error) {
		if err := idx.FindOrganizationByID(orgID); err != nil {
			return nil, err
		}
		ids, err := idx.GetAccessorsDocuments("org", orgID)
		if err != nil {
			return nil, err
		}
		// This filters without allocating
		// https://github.com/golang/go/wiki/SliceTricks#filtering-without-allocating
		dids := ids[:0]
		for _, id := range ids {
			if _, err := authorizedWhereIDs(ctx, orgID, id, influxdb.ReadAction)(idx, dec); err != nil {
				continue
			}
			dids = append(dids, id)
		}
		return dids, nil
	}
}

func authorizedWhereOrg(ctx context.Context, org string) influxdb.DocumentFindOptions {
	return func(idx influxdb.DocumentIndex, dec influxdb.DocumentDecorator) ([]influxdb.ID, error) {
		oid, err := idx.FindOrganizationByName(org)
		if err != nil {
			return nil, err
		}
		return authorizedWhereOrgID(ctx, oid)(idx, dec)
	}
}

func toDocumentOptions(findOpt influxdb.DocumentFindOptions) influxdb.DocumentOptions {
	return func(id influxdb.ID, index influxdb.DocumentIndex) error {
		_, err := findOpt(index, nil)
		return err
	}
}
