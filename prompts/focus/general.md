1. **Security data leak** — credentials/keys/PII committed to the repo (these are also flagged by a separate scanner; if you also notice one, mention it).
2. **Security bugs** — SQL/command injection, SSRF, missing authn/authz, unsafe deserialisation, path traversal, hardcoded crypto, insecure randomness, broken TLS verification.
3. **Correctness bugs** — off-by-one, wrong condition, nil/None deref, await/async mistakes, race conditions, wrong error handling, swallowed exceptions, type coercion bugs.
4. **Data-loss / blast-radius risks** — destructive migrations without backfill, missing transactions, unbounded fan-out, unguarded retries.
5. **Performance footguns** — N+1 queries, accidental O(n²) loops inside hot paths, missing indexes on new lookups.
6. **Small-but-real issues** — a missing edge case (empty list, `None`, zero, negative, duplicate), an easy-to-misuse new parameter or API, unclear/silently-swallowed error handling, a minor logic gap. Low severity is fine and expected here — flag it when it's a concrete, nameable problem; skip it when it's just a style preference with no real downside.
