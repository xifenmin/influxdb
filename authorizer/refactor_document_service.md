# Refactor Document Service

This is a document that contains how the `DocumentService` should be refactored and why.

__TL;DR__

The `DocumentService` is different from other resource services, because it bounds authorization with its business logic.  
Not only, it also bounds URM creation logic up to the HTTP layer.

This results with a less readable implementation and debugging.  
Authorization ends up being pretty custom and not standardized with other services.  
This increases the chance of bugs and subtle undesired behavior.

The `DocumentService` should end up being similar to other services.  
That would require, at least, re-shaping its interface.

## Before

The `DocumentHandler` embeds a `influxdb.DocumentService` and delegates execution to them. 
Given a namespace, it can retrieve a `influxdb.DocumentStore` from which operating on documents.
The service contains simple methods that are highly flexible thanks to the options passed.  
The options can operate on a `DocumentIndex` that allows to query and manipulate data in the store.

The problem is that one is forced to include business logic in those options.  
Current options, for example, include authorization and URM addition bits.  
Those should stay in a separate authorizer service and in the kv store implementation (as it is for other services).  
That would make the implementation cleaner and less error prone.

## Now

Moved the authorization options to `authorizer` package and exposed only the ones to be passed to the `DocumentStore` basing on the action that some is doing.  
See, for instance, the `http/document_handler.go`, and tests.

Refactored the options to use the provided methods to check permissions (package `authorizer`), to make their behavior more similar to the one exhibited in other services.

The `DocumentStore` has a weird way of retrieving the users mapped to a document.  
It only saves one URM of type `OrgMappingType` on document creation.
Upon get, it looks for those orgs that have access to the document and checks if the current user is accessor of the org (with the right read/write permissions depending on the action).  
See `DocumentIndex.AddDocumentOwner` for the creation step, and `authorizer.authorizedWhereID` for the retrieval step.

Other services, instead, store one URM of typee `UserMappingType` for each user in an org to the new resource.
Those URMs, indeed, are used to build up the permissions in a session and to authorize the user.

## Next

The `DocumentStore` should make it possible to clearly separate authorization, data, and business logic.

A first step towards that could be to change the logic for URMs and make a `Document` contain its `OrgID`.

However, that would require a database migration.