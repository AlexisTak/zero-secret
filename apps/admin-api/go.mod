module github.com/Biscuits-ia/biscuits-shield/apps/admin-api

go 1.23

require github.com/Biscuits-ia/biscuits-shield/pkg/gen v0.0.0

require google.golang.org/grpc v1.83.1 // indirect

// pkg/gen n'est jamais publié (module interne au monorepo) — résolu localement, même patron
// qu'apps/access-broker (L2.3) et apps/credential-issuer (L2.4).
replace github.com/Biscuits-ia/biscuits-shield/pkg/gen => ../../pkg/gen
