# Analytics and confidence

## Bounded algorithms

Neighborhoods use breadth-first search over incident claims, with a visited-node map to handle cycles.
Depth 0 returns the seed; depth 1 returns immediate neighbors; maximum depth is 6. Output is bounded to
1,000 nodes and 5,000 edges, with at most 20,000 scanned incident claims. Entity and relationship filters
apply during expansion, so filtered-out intermediate nodes are not traversed. The seed is retained
regardless of its type filter. Results report depth, scanned_edges and truncated. A truncated result
is not a complete neighborhood. Rejected/superseded claims are omitted by default; disputed claims stay
visible. API/CLI neighborhoods can explicitly include inactive claims.

Shortest path uses BFS with a parent map, yielding one minimum-hop path in the examined graph. Claims
are undirected by default; `--directed` follows source to target only. Depth/node/scan limits still
apply. No found path means no path within those limits; it does not establish global disconnection.
Edges and evidence are available for every path claim. Parallel claims can provide different evidence
for the same hop; a shortest path is not an attribution chain.

Shared-neighbor results intersect bounded one-hop neighborhoods (2..10 selected entities) and report
truncation. Shared indicators count distinct reports per canonical IOC, not repeated evidence.
Related techniques list ATT&CK nodes within a bounded neighborhood, with a warning that proximity is
not itself a behavioral mapping. Component summaries use undirected BFS on the selected node/edge
slice; degree counts incident claims, so multiple source claims can increase degree without adding
independent real-world actors. Components/degrees report truncation if node/edge scan limits are hit.
Exports combine bounded seed neighborhoods into a capped investigation graph; all included edge
evidence and score rationale are attached. They reflect current state, not a frozen historical case.

## Confidence

`ScoreConfig` bounds all configurable inputs; `configs/scoring.json` documents defaults. Source-supplied
confidence/rationale remain separate from computed heuristic confidence. Quality is source-supplied,
not objectively validated. When no quality is supplied, computed confidence stays unknown.

Default formula for a claim with quality:

1. Mean supplied quality multiplied by origin weight: direct=.65, source-reported=.40,
   deterministic=.55, analyst-confirmed=.65, hypothesis=.15.
2. Up to .24 bonus for multiple explicitly identified distinct upstream claim groups (.12 per
   additional group). Unidentified independence and duplicate upstream claims add no bonus.
3. Subtract .15 if latest known observation is older than 365 days, .10 for recorded limitations,
   .15 for expired validity, and .20 for a disputed parallel claim.
4. Entity-level active CONTRADICTS information receives a conservative .20 penalty, with a rationale
   requiring analyst review; it does not prove the particular relationship false.
5. Clamp to 0..1. Rejected/superseded selected claims have no current score.

Unknown observation times do not become recent. Rationale explicitly records missing quality, time,
independence, contradictions and limitations. Hypotheses retain that origin regardless of score.
Indicator risk and investigation priority remain null: this release has no justified rubric for either.
Scores are not calibrated probabilities, and quality of a source is not truth of every statement.

Deduplicated evidence IDs prevent identical imports from increasing confidence. Explicit upstream IDs
avoid bonus for known copied reports; concealed copying remains a limitation. Scoring groups parallel
claims on endpoints and type, regardless of interval; analyst review is required where claims describe
different historical periods. This is a conservative local heuristic, not temporal causal analysis.
No automatic ownership, authorship, campaign, actor, or ATT&CK inference comes from shared neighbors,
infrastructure, degree, paths or components. Community detection/centrality and cluster attribution
are deliberately outside the initial release.
