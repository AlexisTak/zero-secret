module github.com/AlexisTak/biscuits-shield/apps/admin-api

go 1.25

require github.com/AlexisTak/biscuits-shield/pkg/gen v0.0.0

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/oapi-codegen/runtime v1.7.0 // indirect
	google.golang.org/grpc v1.83.1 // indirect
)

// pkg/gen n'est jamais publié (module interne au monorepo) — résolu localement, même patron
// qu'apps/access-broker (L2.3) et apps/credential-issuer (L2.4).
replace github.com/AlexisTak/biscuits-shield/pkg/gen => ../../pkg/gen
