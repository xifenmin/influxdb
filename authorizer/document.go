package authorizer

import (
	"context"
	"fmt"

	"github.com/influxdata/influxdb"
	icontext "github.com/influxdata/influxdb/context"
)

// TODO(affo): this file contains the functions to create the options to pass to the corresponding method of influxdb.DocumentStore.
//  This pattern is different from the ons in the other services, where the authorization layer is a service that wrap
//  the vanilla one and adds permission checks.
//  For more, see refactor_document_service.md.

// CreateDocumentAuthorizerOption provides the option to pass to DocumentStore.CreateDocument for proper authorization.
func CreateDocumentAuthorizerOption(ctx context.Context, orgID influxdb.ID, orgName string) influxdb.DocumentOptions {
	if orgID.Valid() {
		return authorizedWithOrgID(ctx, orgID, influxdb.WriteAction)
	}
	return authorizedWithOrg(ctx, orgName, influxdb.WriteAction)
}

// GetDocumentsAuthorizerOption provides the option to pass to DocumentStore.FindDocuments.
// It makes the store return only the documents that the user in the context is allowed to read in the specified org.
func GetDocumentsAuthorizerOption(ctx context.Context, orgID influxdb.ID, orgName string) influxdb.DocumentFindOptions {
	if orgID.Valid() {
		return authorizedWhereOrgID(ctx, orgID)
	}
	return authorizedWhereOrg(ctx, orgName)
}

// GetDocumentAuthorizerOption provides the option to pass to DocumentStore.FindDocuments.
// It makes the store return the document specified if authorized.
func GetDocumentAuthorizerOption(ctx context.Context, docID influxdb.ID) influxdb.DocumentFindOptions {
	return authorizedRead(ctx, docID)
}

// UpdateDocumentAuthorizerOption provides the option to pass to DocumentStore.UpdateDocument for proper authorization.
func UpdateDocumentAuthorizerOption(ctx context.Context, docID influxdb.ID) influxdb.DocumentOptions {
	return toDocumentOptions(authorizedWrite(ctx, docID))
}

// DeleteDocumentAuthorizerOption provides the option to pass to DocumentStore.DeleteDocuments for proper authorization.
// It makes the store delete the specified document.
func DeleteDocumentAuthorizerOption(ctx context.Context, docID influxdb.ID) influxdb.DocumentFindOptions {
	return authorizedWrite(ctx, docID)
}

//// Private functions to build the options above.

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

// TODO(affo): the DocumentService has a weird way of retrieving the users mapped to a document.
//  It only saves one URM of type OrgMappingType on document creation (see DocumentIndex.AddDocumentOwner),
//  and later if looks for those orgs that have access to the document and checks if the current user
//  (in the context) is accessor of the org (with the right read/write permissions depending on the action).
//  Other services store one URM of UserMappingType for each user in an org to the new resource. Those URMs,
//  indeed, are used to build up the permissions in a session and can be used to authorize the user.
//  For more, see refactor_document_service.md.
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
