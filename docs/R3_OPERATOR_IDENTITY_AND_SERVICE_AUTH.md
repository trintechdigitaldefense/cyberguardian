# R3 operator identity and service authorization design

Status: **design baseline — implementation and acceptance tests still required**  
Branch: `r2-1.6.0-security`  
Scope: dashboard-to-gateway operator attribution and service-to-service least privilege.

## Security objectives

1. The gateway must derive operator identity only from a cryptographically verified assertion minted by the authenticated dashboard backend. Client-supplied `X-Actor`, role, tenant, or approval headers are never authoritative.
2. Every assertion is bound to one HTTP method, normalized API path, tenant, short issue time, unique nonce, and authenticated operator subject/role. The gateway rejects expired, future-dated, malformed, incorrectly signed, wrong-method/path, and replayed assertions.
3. Audit events must record the verified operator subject and role, tenant, request/correlation ID, action or command ID, approval decision, and timestamp. Agent-originated events remain explicitly attributed to the enrolled agent identity, not the dashboard operator.
4. The dashboard must not possess a fleet-wide administrator credential. Each internal caller receives a distinct credential and explicit endpoint/method scope.
5. Service authentication is fail-closed in production. A service credential for one workload must not authorize another workload's routes.

## Trust boundaries and request flow

- Browser -> Dashboard: persistent session, role check, CSRF check for every state-changing request.
- Dashboard -> API gateway: dashboard-specific service credential plus HMAC-signed operator context. The dashboard backend signs claims from its server-side session; it does not copy actor/role/tenant from browser input.
- NAD processor -> API gateway: NAD-specific service credential limited to submitting detections. No operator assertion is accepted or synthesized for this workload.
- API gateway -> Decision service: decision-service credential limited to the decision API. Decision service is not exposed to the host.
- Agent -> API gateway: existing per-agent credential and enrolled asset/tenant binding; agent scope remains limited to agent endpoints.

## Signed operator context contract

Canonical payload fields:

- `v`: fixed protocol version.
- `sub`: authenticated dashboard username / stable operator subject.
- `role`: server-side role from the dashboard session.
- `tenant_id`: server-side tenant from the dashboard session.
- `iat`: UTC Unix issue time; maximum age 60 seconds and no future clock skew beyond 5 seconds.
- `nonce`: cryptographically random, single-use value; replay state is persistent and shared by gateway workers.
- `method` and `path`: exact upstream HTTP method and normalized path.
- `request_id`: unique correlation ID for the upstream request.
- `action_id`: optional action/approval/command identifier when the route operates on one.

Signature: HMAC-SHA-256 over the canonical UTF-8 JSON representation, using a dedicated random secret of at least 32 bytes. Compare signatures in constant time. Never log the secret or full assertion.

The gateway must verify the signature, schema, freshness, nonce uniqueness, method/path binding, tenant match, and allowed role before exposing verified claims to route handlers/audit code. A verified assertion must not elevate a caller beyond the endpoint's server-side authorization policy.

## Service identity and endpoint scopes

| Caller | Allowed scope | Explicitly denied |
|---|---|---|
| Dashboard | Approved dashboard read endpoints; operator actions only with required role, CSRF and verified context | Agent enrollment/command-result APIs, unrestricted admin APIs, credential management |
| NAD processor | Submit detection events only | Fleet reads, gate approvals, rollback, containment, agent enrollment, decision administration |
| Decision service | Internal decision operations required by gateway | Dashboard, fleet, enrollment, agent command and operator endpoints |
| Agent | Own enrollment/heartbeat/command/result endpoints, bound to its asset and tenant | Other assets, fleet/admin/dashboard endpoints |
| Human administrator | Separate administrative credential and explicitly documented admin endpoints | Implicit access by reusing a workload credential |

Exact route/method allowlists must be derived from the gateway route inventory during implementation. Default-deny is required; unknown routes are denied to workload identities.

## Audit event requirements

For every state-changing dashboard action, persist:

- `actor_subject`, `actor_role`, and `tenant_id` from verified context;
- service caller identity;
- HTTP method, route, request ID, timestamp;
- action ID / command ID / asset ID where applicable;
- approval state and approver identity for human-gated actions;
- outcome and denial reason.

Do not trust body fields or headers for actor, role, tenant, or approval identity. Preserve existing agent identity attribution for agent polling/results. Audit write failure for a security-sensitive state change must fail closed or enter a durable, explicitly monitored audit queue; it must never silently discard the event.

## R3 acceptance gates

- [ ] Valid dashboard assertion is accepted and audit record contains exact subject, role, tenant, request ID and action correlation.
- [ ] Forged, missing, expired, future-dated, replayed, wrong-method, wrong-path and wrong-tenant assertions are rejected.
- [ ] Client-supplied actor/role/tenant/approval headers cannot override signed claims.
- [ ] Cross-tenant object-ID substitution is denied on every dashboard proxy route.
- [ ] Viewer/analyst/operator/admin role matrix is enforced server-side for every route.
- [ ] Dashboard credential cannot invoke NAD-only, agent, credential-management or unrestricted admin endpoints.
- [ ] NAD credential can submit detections but cannot read fleet data or approve/rollback/contain.
- [ ] Decision-service credential cannot call unrelated gateway endpoints; missing/wrong credentials fail closed.
- [ ] Agent credentials remain asset- and tenant-bound and cannot be used as service credentials.
- [ ] Full Compose integration tests cover login, expired/revoked sessions, CSRF, role denial, service-scope denial, tenant isolation, audit persistence and wrong-secret failure.
- [ ] Secrets are independently generated, rotated, excluded from Git, and documented for deployment.

## Implementation order

1. Inventory gateway routes and audit schema; define exact endpoint scopes.
2. Implement dashboard assertion minting from server-side session and gateway verification with durable nonce replay protection.
3. Bind verified claims to audit writes and correlate approvals/commands.
4. Split dashboard, NAD, decision-service and agent credentials into separate scopes; remove shared admin-key use from workload containers.
5. Add negative authorization, replay, cross-tenant and audit-persistence tests.
6. Run full Compose acceptance suite and review deployment/secret migration documentation.

**Release rule:** R3 remains in progress until every acceptance item above is implemented and evidenced by tests. Do not start R4, merge the draft PR, or describe CyberGuardian as client-ready before R3 acceptance is complete.
