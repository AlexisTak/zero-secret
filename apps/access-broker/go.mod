module github.com/Biscuits-ia/biscuits-shield/apps/access-broker

go 1.23

require (
	github.com/Biscuits-ia/biscuits-shield/pkg/gen v0.0.0
	github.com/google/uuid v1.6.0
	github.com/oapi-codegen/runtime v1.7.0
	google.golang.org/grpc v1.83.1
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/apapsch/go-jsonmerge/v2 v2.0.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

// pkg/gen n'est jamais publié (module interne au monorepo) — résolu localement, pas via un
// registre. Même patron nécessaire pour tout futur composant apps/ qui importera pkg/gen.
replace github.com/Biscuits-ia/biscuits-shield/pkg/gen => ../../pkg/gen
