package engine

// NoSQL injection semantic engine.
//
// Detects MongoDB operator injection, Redis command injection, and similar
// NoSQL attack patterns. MongoDB is the primary target (most common NoSQL).
//
// Attack patterns detected:
//   - MongoDB operator injection: $gt, $ne, $where, $regex, $or, $and, $nin, $in
//   - $where JavaScript injection: {"$where": "1==1"} or ?a[$where]=1==1
//   - [$ne] / [$gt] parameter pollution (array notation from Express/PHP frameworks)
//   - Aggregation pipeline injection: $group, $lookup, $out, $merge
//   - mapReduce JavaScript: db.collection.mapReduce(function(){})
//   - Redis command injection via RESP/inline protocol
//
// Evidence is weighted; score ≥ softThreshold triggers alert.

// ── constants ─────────────────────────────────────────────────────────────────

// ── detection patterns ────────────────────────────────────────────────────────

// ── types ─────────────────────────────────────────────────────────────────────

type NoSQLSemanticInput struct {
	Raw      string
	Method   string
	Route    string
	Location string
}

type NoSQLSemanticEvidence struct {
	Signal     string
	Confidence float64
	Weight     float64
}

type NoSQLSemanticReport struct {
	Alert    bool
	Primary  string
	Score    float64
	Evidence []NoSQLSemanticEvidence
}

// NoSQLBaseScore is the score a block-tier NoSQL injection verdict carries when
// semantic_policies.nosql.base_score is absent. Equals the SQLi category default the engine was
// coupled to before it had its own base score, so existing projects keep their effective score.
const NoSQLBaseScore = 180

type NoSQLSemanticPolicy struct {
	BlockThreshold float64
	SoftThreshold  float64
	// BaseScore is the decision-scale score of a block-tier verdict
	// (semantic_policies.nosql.base_score). nil = NoSQLBaseScore; 0 = engine disabled.
	BaseScore *int
}

// ── analyzer ─────────────────────────────────────────────────────────────────
