package testing

import (
	"bytes"
	"context"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/influxdata/influxdb"
	"github.com/influxdata/influxdb/authorizer"
	icontext "github.com/influxdata/influxdb/context"
	"github.com/influxdata/influxdb/kv"
	"github.com/influxdata/influxdb/mock"
	"go.uber.org/zap"
)

// NewDocumentIntegrationTest will test the documents related funcs.
func NewDocumentIntegrationTest(store kv.Store) func(t *testing.T) {
	return func(t *testing.T) {
		ctx := context.Background()
		svc := kv.NewService(zap.NewNop(), store)
		mockTimeGen := new(mock.TimeGenerator)
		if err := svc.Initialize(ctx); err != nil {
			t.Fatalf("failed to initialize service: %v", err)
		}

		svc.TimeGenerator = mockTimeGen

		s, err := svc.CreateDocumentStore(ctx, "testing")
		if err != nil {
			t.Fatalf("failed to create document store: %v", err)
		}

		ss, err := svc.FindDocumentStore(ctx, "testing")
		if err != nil {
			t.Fatalf("failed to find document store: %v", err)
		}

		l1 := &influxdb.Label{Name: "l1", OrgID: MustIDBase16("41a9f7288d4e2d64")}
		l2 := &influxdb.Label{Name: "l2", OrgID: MustIDBase16("41a9f7288d4e2d64")}
		MustCreateLabels(ctx, svc, l1, l2)
		lBad := &influxdb.Label{ID: MustIDBase16(oneID), Name: "bad"}

		o1 := &influxdb.Organization{Name: "foo"}
		o2 := &influxdb.Organization{Name: "bar"}
		MustCreateOrgs(ctx, svc, o1, o2)

		u1 := &influxdb.User{Name: "yanky"}
		u2 := &influxdb.User{Name: "doodle"}
		MustCreateUsers(ctx, svc, u1, u2)

		MustMakeUsersOrgOwner(ctx, svc, o1.ID, u1.ID)

		MustMakeUsersOrgOwner(ctx, svc, o2.ID, u2.ID)
		MustMakeUsersOrgMember(ctx, svc, o1.ID, u2.ID)

		// TODO(desa): test tokens and authorizations as well.
		now := time.Now()
		s1 := &influxdb.Session{
			CreatedAt: now,
			ExpiresAt: now.Add(1 * time.Hour),
			UserID:    u1.ID,
			Permissions: []influxdb.Permission{
				// create doc for o1
				{
					Action: influxdb.WriteAction,
					Resource: influxdb.Resource{
						OrgID: &o1.ID,
						Type:  influxdb.DocumentsResourceType,
					},
				},
			},
		}
		s2 := &influxdb.Session{
			CreatedAt: now,
			ExpiresAt: now.Add(1 * time.Hour),
			UserID:    u2.ID,
			Permissions: []influxdb.Permission{
				// create doc for o2
				{
					Action: influxdb.WriteAction,
					Resource: influxdb.Resource{
						OrgID: &o2.ID,
						Type:  influxdb.DocumentsResourceType,
					},
				},
			},
		}

		var d1 *influxdb.Document
		var d2 *influxdb.Document
		var d3 *influxdb.Document

		t.Run("u1 can create document for o1", func(t *testing.T) {
			d1 = &influxdb.Document{
				Meta: influxdb.DocumentMeta{
					Name:        "i1",
					Type:        "type1",
					Description: "desc1",
				},
				Content: map[string]interface{}{
					"v1": "v1",
				},
			}
			ctx := context.Background()
			ctx = icontext.SetAuthorizer(ctx, s1)

			mockTimeGen.FakeValue = time.Date(2009, 1, 2, 3, 0, 0, 0, time.UTC)
			if err := s.CreateDocument(ctx, d1, authorizer.CreateDocumentAuthorizerOption(ctx, 0, o1.Name), influxdb.WithLabel(l1.ID)); err != nil {
				t.Errorf("failed to create document: %v", err)
			}
		})

		// u1 owns d1
		s1.Permissions = append(s1.Permissions,
			influxdb.Permission{
				Action: influxdb.ReadAction,
				Resource: influxdb.Resource{
					ID:   &d1.ID,
					Type: influxdb.DocumentsResourceType,
				},
			},
			influxdb.Permission{
				Action: influxdb.WriteAction,
				Resource: influxdb.Resource{
					ID:   &d1.ID,
					Type: influxdb.DocumentsResourceType,
				},
			},
		)
		// u2 is part of o1
		s2.Permissions = append(s2.Permissions,
			influxdb.Permission{
				Action: influxdb.ReadAction,
				Resource: influxdb.Resource{
					ID:   &d1.ID,
					Type: influxdb.DocumentsResourceType,
				},
			},
		)

		t.Run("u2 cannot create document for o1", func(t *testing.T) {
			d2 = &influxdb.Document{
				Meta: influxdb.DocumentMeta{
					Name: "i2",
				},
				Content: map[string]interface{}{
					"i2": "i2",
				},
			}
			ctx := context.Background()
			ctx = icontext.SetAuthorizer(ctx, s2)

			mockTimeGen.FakeValue = time.Date(2009, 1, 2, 3, 0, 1, 0, time.UTC)
			if err := s.CreateDocument(ctx, d2, authorizer.CreateDocumentAuthorizerOption(ctx, 0, o1.Name), influxdb.WithLabel(l2.ID)); err == nil {
				t.Fatalf("should not have be authorized to create document")
			}

			mockTimeGen.FakeValue = time.Date(2009, 1, 2, 3, 0, 1, 0, time.UTC)
			if err := s.CreateDocument(ctx, d2, authorizer.CreateDocumentAuthorizerOption(ctx, 0, o2.Name)); err != nil {
				t.Errorf("should have been authorized to create document: %v", err)
			}
		})

		// u2 owns d2
		s2.Permissions = append(s2.Permissions,
			influxdb.Permission{
				Action: influxdb.ReadAction,
				Resource: influxdb.Resource{
					ID:   &d2.ID,
					Type: influxdb.DocumentsResourceType,
				},
			},
			influxdb.Permission{
				Action: influxdb.WriteAction,
				Resource: influxdb.Resource{
					ID:   &d2.ID,
					Type: influxdb.DocumentsResourceType,
				},
			},
		)

		t.Run("u1 cannot create document for o2", func(t *testing.T) {
			d3 = &influxdb.Document{
				Meta: influxdb.DocumentMeta{
					Name: "i2",
				},
				Content: map[string]interface{}{
					"k2": "v2",
				},
			}
			ctx := context.Background()
			ctx = icontext.SetAuthorizer(ctx, s1)

			mockTimeGen.FakeValue = time.Date(2009, 1, 2, 3, 0, 2, 0, time.UTC)
			if err := s.CreateDocument(ctx, d3, authorizer.CreateDocumentAuthorizerOption(ctx, 0, o2.Name)); err == nil {
				t.Errorf("should not have be authorized to create document")
			}
		})

		/* Affo: This is not allowed now.
		t.Run("can create unowned document", func(t *testing.T) {
			// TODO(desa): should this be allowed?
			mockTimeGen.FakeValue = time.Date(2009, 1, 2, 3, 0, 2, 0, time.UTC)
			if err := s.CreateDocument(ctx, d3); err != nil {
				t.Fatalf("should have been able to create document: %v", err)
			}
		})
		 */

		t.Run("can't create document with unexisted label", func(t *testing.T) {
			d4 := &influxdb.Document{
				Meta: influxdb.DocumentMeta{
					Name: "i4",
				},
				Content: map[string]interface{}{
					"k4": "v4",
				},
			}
			ctx := context.Background()
			ctx = icontext.SetAuthorizer(ctx, s1)
			err = s.CreateDocument(ctx, d4, authorizer.CreateDocumentAuthorizerOption(ctx, 0, o1.Name), influxdb.WithLabel(lBad.ID))
			ErrorsEqual(t, err, &influxdb.Error{
				Code: influxdb.ENotFound,
				Msg:  "label not found",
			})
		})

		d1.Meta.CreatedAt = time.Date(2009, 1, 2, 3, 0, 0, 0, time.UTC)
		dl1 := new(influxdb.Document)
		*dl1 = *d1
		dl1.Labels = append([]*influxdb.Label{}, l1)

		d2.Meta.CreatedAt = time.Date(2009, 1, 2, 3, 0, 1, 0, time.UTC)
		dl2 := new(influxdb.Document)
		*dl2 = *d2
		dl2.Labels = append([]*influxdb.Label{}, d2.Labels...)

		d3.Meta.CreatedAt = time.Date(2009, 1, 2, 3, 0, 2, 0, time.UTC)

		t.Run("bare call to find returns all documents", func(t *testing.T) {
			ds, err := ss.FindDocuments(ctx)
			if err != nil {
				t.Fatalf("failed to retrieve documents: %v", err)
			}
			// Affo: there is no d3 now.
			// if exp, got := []*influxdb.Document{d1, d2, d3}, ds; !docsMetaEqual(exp, got) {
			if exp, got := []*influxdb.Document{d1, d2}, ds; !docsMetaEqual(exp, got) {
				t.Errorf("documents are different -got/+want\ndiff %s", docsMetaDiff(exp, got))
			}
		})

		t.Run("u1 can see o1s documents by label", func(t *testing.T) {
			ctx := context.Background()
			ctx = icontext.SetAuthorizer(ctx, s1)
			ds, err := ss.FindDocuments(ctx, authorizer.GetDocumentsAuthorizerOption(ctx, 0, o1.Name), influxdb.IncludeContent, influxdb.IncludeLabels)

			if err != nil {
				t.Fatalf("failed to retrieve documents: %v", err)
			}

			if exp, got := []*influxdb.Document{dl1}, ds; !docsEqual(got, exp) {
				t.Errorf("documents are different -got/+want\ndiff %s", docsDiff(got, exp))
			}
		})

		t.Run("check not found err", func(t *testing.T) {
			_, err := ss.FindDocuments(ctx, influxdb.WhereID(MustIDBase16(fourID)), influxdb.IncludeContent)
			ErrorsEqual(t, err, &influxdb.Error{
				Code: influxdb.ENotFound,
				Msg:  influxdb.ErrDocumentNotFound,
			})
		})

		t.Run("u2 can see o1 and o2s documents", func(t *testing.T) {
			ctx := context.Background()
			ctx = icontext.SetAuthorizer(ctx, s2)
			ds1, err := ss.FindDocuments(ctx, authorizer.GetDocumentsAuthorizerOption(ctx, 0, o1.Name), influxdb.IncludeContent, influxdb.IncludeLabels)
			if err != nil {
				t.Fatalf("failed to retrieve documents for org1: %v", err)
			}
			ds2, err := ss.FindDocuments(ctx, authorizer.GetDocumentsAuthorizerOption(ctx, 0, o2.Name), influxdb.IncludeContent, influxdb.IncludeLabels)
			if err != nil {
				t.Fatalf("failed to retrieve documents for org2: %v", err)
			}

			if exp, got := []*influxdb.Document{dl1, dl2}, append(ds1, ds2...); !docsEqual(exp, got) {
				t.Errorf("documents are different -got/+want\ndiff %s", docsDiff(exp, got))
			}
		})

		t.Run("u2 cannot update document d1", func(t *testing.T) {
			d := &influxdb.Document{
				ID: d1.ID,
				Meta: influxdb.DocumentMeta{
					Name: "updatei1",
				},
				Content: map[string]interface{}{
					"updatev1": "updatev1",
				},
			}
			ctx := context.Background()
			ctx = icontext.SetAuthorizer(ctx, s2)
			if err := s.UpdateDocument(ctx, d, authorizer.UpdateDocumentAuthorizerOption(ctx, d.ID)); err == nil {
				t.Errorf("should not have been authorized to update document")
				return
			}
		})

		t.Run("u2 can update document d2", func(t *testing.T) {
			d := &influxdb.Document{
				ID: d2.ID,
				Meta: influxdb.DocumentMeta{
					Name: "updatei2",
				},
				Content: map[string]interface{}{
					"updatev2": "updatev2",
				},
			}
			ctx := context.Background()
			ctx = icontext.SetAuthorizer(ctx, s2)
			if err := s.UpdateDocument(ctx, d, authorizer.UpdateDocumentAuthorizerOption(ctx, d.ID)); err != nil {
				t.Errorf("unexpected error updating document: %v", err)
			}
		})

		t.Run("u1 can update document d1", func(t *testing.T) {
			ctx := context.Background()
			ctx = icontext.SetAuthorizer(ctx, s1)
			if err := s.DeleteDocuments(ctx, authorizer.DeleteDocumentAuthorizerOption(ctx, d1.ID)); err != nil {
				t.Errorf("unexpected error deleteing document: %v", err)
			}
		})

	}
}

func docsEqual(i1, i2 interface{}) bool {
	return cmp.Equal(i1, i2, documentCmpOptions...)
}

func docsMetaEqual(i1, i2 interface{}) bool {
	return cmp.Equal(i1, i2, documentMetaCmpOptions...)
}

func docsDiff(i1, i2 interface{}) string {
	return cmp.Diff(i1, i2, documentCmpOptions...)
}

func docsMetaDiff(i1, i2 interface{}) string {
	return cmp.Diff(i1, i2, documentMetaCmpOptions...)
}

var documentMetaCmpOptions = append(documentCmpOptions, cmpopts.IgnoreFields(influxdb.Document{}, "Content", "Labels"))

var documentCmpOptions = cmp.Options{
	cmp.Comparer(func(x, y []byte) bool {
		return bytes.Equal(x, y)
	}),
	cmp.Transformer("Sort", func(in []*influxdb.Document) []*influxdb.Document {
		out := append([]*influxdb.Document(nil), in...) // Copy input to avoid mutating it
		sort.Slice(out, func(i, j int) bool {
			return out[i].ID.String() > out[j].ID.String()
		})
		return out
	}),
}
