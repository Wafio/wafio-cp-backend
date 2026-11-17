// GraphQL semantic engine: introspection visibility + batch-operation
// abuse detection. GraphQL operations already flow through the generic
// semantic parts (the "query" JSON field is a scanned leaf); this engine adds
// the two GraphQL-specific abuse signals that generic scanning misses.
package engine

// DefaultGraphQLMaxBatch is the fallback per-request GraphQL operation cap
// when the caller does not configure one (GraphQLMaxBatch == 0).
const DefaultGraphQLMaxBatch = 10
