package influxdb

import (
	"context"
)

// ErrDocumentNotFound is the error msg for a missing document.
const ErrDocumentNotFound = "document not found"

// DocumentService is used to create/find instances of document stores.
type DocumentService interface {
	CreateDocumentStore(ctx context.Context, name string) (DocumentStore, error)
	FindDocumentStore(ctx context.Context, name string) (DocumentStore, error)
}

// Document is a generic structure for stating data.
type Document struct {
	ID      ID           `json:"id"`
	Meta    DocumentMeta `json:"meta"`
	Content interface{}  `json:"content,omitempty"` // TODO(desa): maybe this needs to be json.Marshaller & json.Unmarshaler
	Labels  []*Label     `json:"labels,omitempty"`  // read only
}

// DocumentMeta is information that is universal across documents. Ideally
// data in the meta should be indexed and queryable.
type DocumentMeta struct {
	Name        string `json:"name"`
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
	Version     string `json:"version,omitempty"`
	CRUDLog
}

// DocumentStore is used to perform CRUD operations on documents. It follows an options
// pattern that allows users to perform actions related to documents in a transactional way.
type DocumentStore interface {
	CreateDocument(ctx context.Context, d *Document, opts ...DocumentOptions) error
	UpdateDocument(ctx context.Context, d *Document, opts ...DocumentOptions) error

	FindDocuments(ctx context.Context, opts ...DocumentFindOptions) ([]*Document, error)
	DeleteDocuments(ctx context.Context, opts ...DocumentFindOptions) error
}

// DocumentIndex is a structure that is used in DocumentOptions to perform operations
// related to labels and ownership.
type DocumentIndex interface {
	// TODO(desa): support users as document owners eventually
	AddDocumentOwner(docID ID, ownerType string, ownerID ID) error
	RemoveDocumentOwner(docID ID, ownerType string, ownerID ID) error

	GetAccessorsDocuments(ownerType string, ownerID ID) ([]ID, error)
	GetDocumentsAccessors(docID ID) ([]ID, error)

	UsersOrgs(userID ID) ([]ID, error)
	// IsOrgAccessor checks to see if the userID provided is allowed to access
	// the orgID privided. If the lookup is done in a writable operation
	// then this method should ensure that the user is an org owner. If the
	// operation is readable, then it should only require that the user is an org
	// member.
	IsOrgAccessor(userID, orgID ID) error

	FindOrganizationByName(n string) (ID, error)
	FindOrganizationByID(id ID) error
	FindLabelByID(id ID) error

	AddDocumentLabel(docID, labelID ID) error
	RemoveDocumentLabel(docID, labelID ID) error

	// TODO(desa): support finding document by label
}

// DocumentDecorator passes information to the DocumentStore about the presentation
// of the data being retrieved. It can be used to include the content or the labels
// associated with a document.
type DocumentDecorator interface {
	IncludeContent() error
	IncludeLabels() error
	// TODO(desa): add support for including owners.
}

// IncludeContent signals to the DocumentStore that the content of the document
// should be included.
func IncludeContent(_ DocumentIndex, dd DocumentDecorator) ([]ID, error) {
	return nil, dd.IncludeContent()
}

// IncludeLabels signals to the DocumentStore that the documents labels
// should be included.
func IncludeLabels(_ DocumentIndex, dd DocumentDecorator) ([]ID, error) {
	return nil, dd.IncludeLabels()
}

// DocumentOptions are specified during create/update. They can be used to add labels/owners
// to documents. During Create, options are executed after the creation of the document has
// taken place. During Update, they happen before.
type DocumentOptions func(ID, DocumentIndex) error

// DocumentFindOptions are speficied during find/delete. They are used to lookup
// documents using labels/owners.
// TODO(desa): consider changing this to have a single struct that has both
// the decorator and the index on it.
type DocumentFindOptions func(DocumentIndex, DocumentDecorator) ([]ID, error)

// WithOrg adds the provided org as an owner of the document.
func WithOrg(org string) func(ID, DocumentIndex) error {
	return func(id ID, idx DocumentIndex) error {
		oid, err := idx.FindOrganizationByName(org)
		if err != nil {
			return err
		}

		return idx.AddDocumentOwner(id, "org", oid)
	}
}

// WithLabel adds a label to the documents where it is applied.
func WithLabel(lid ID) func(ID, DocumentIndex) error {
	return func(id ID, idx DocumentIndex) error {
		// TODO(desa): turns out that labels are application global, at somepoint we'll
		// want to scope these by org. We should add auth at that point.
		err := idx.FindLabelByID(lid)
		if err != nil {
			return err
		}

		return idx.AddDocumentLabel(id, lid)
	}
}

// WithoutLabel removes a label to the documents where it is applied.
func WithoutLabel(lid ID) func(ID, DocumentIndex) error {
	return func(id ID, idx DocumentIndex) error {
		// TODO(desa): turns out that labels are application global, at somepoint we'll
		// want to scope these by org. We should add auth at that point.
		err := idx.FindLabelByID(lid)
		if err != nil {
			return err
		}

		return idx.RemoveDocumentLabel(id, lid)
	}
}

// WhereOrg retrieves a list of the ids of the documents that belong to the provided org.
func WhereOrg(org string) func(DocumentIndex, DocumentDecorator) ([]ID, error) {
	return func(idx DocumentIndex, dec DocumentDecorator) ([]ID, error) {
		oid, err := idx.FindOrganizationByName(org)
		if err != nil {
			return nil, err
		}
		return WhereOrgID(oid)(idx, dec)
	}
}

// WhereOrgID retrieves a list of the ids of the documents that belong to the provided orgID.
func WhereOrgID(orgID ID) func(DocumentIndex, DocumentDecorator) ([]ID, error) {
	return func(idx DocumentIndex, _ DocumentDecorator) ([]ID, error) {
		return idx.GetAccessorsDocuments("org", orgID)
	}
}

// WhereID passes through the id provided.
func WhereID(docID ID) func(DocumentIndex, DocumentDecorator) ([]ID, error) {
	return func(idx DocumentIndex, _ DocumentDecorator) ([]ID, error) {
		return []ID{docID}, nil
	}
}
