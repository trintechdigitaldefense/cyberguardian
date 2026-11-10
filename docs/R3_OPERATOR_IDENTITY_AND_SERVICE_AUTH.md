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


## Implementation progress (2026-11-10)

The first operator-assertion implementation slice is now present on the security branch:

- `control-plane/api/operator_context.py` mints/verifies canonical HMAC-SHA-256 assertions, enforces a 32-byte minimum secret, checks a 60-second age / 5-second future-skew window, binds method/path/tenant, and consumes single-use nonces in a persistent SQLite replay store.
- `dashboard/main.py` mints request-bound assertions from the authenticated server-side session for dashboard proxy calls and the initial dashboard data load. Browser-supplied actor, role, or tenant values are not used as assertion claims.
- `control-plane/api/main.py` verifies assertions at the gateway boundary in production, exposes verified claims in request state and a request-scoped context variable, and enriches gateway audit writes with the verified subject, role, tenant, and request ID. It writes a durable start record before the handler runs; completion-write failures are logged while the start record remains.
- Docker Compose now requires the same dedicated `CG_OPERATOR_ASSERTION_SECRET` in the API and dashboard containers. The API data volume stores replay nonces across gateway restarts.

Tests added in `tests/test_operator_context.py` cover valid claims, signature tampering, expiry/future time, method/path/tenant binding, nonce replay, weak secrets, and dashboard session-derived signing.

**Important limitations — R3 is not accepted:** the gateway's current shared API credential is still used by dashboard and NAD workloads; exact default-deny service scopes have not yet been implemented. Gateway role enforcement for each route, cross-tenant object-ID substitution coverage, full Compose acceptance, CSP/throttle/startup hardening, and audit-schema integration review remain outstanding. The assertion middleware currently protects requests using the configured dashboard API key in production; non-production mode intentionally bypasses enforcement. Do not treat the present slice as client-ready or start R4.


## Service-scope implementation progress (2026-11-10)

A second implementation slice now separates workload credentials and applies default-deny route scopes:

- `CYBERGUARDIAN_API_KEY` remains the administrator credential and is supplied only to the API gateway.
- `CG_DASHBOARD_API_KEY` is supplied to the dashboard and gateway. The gateway allows only the dashboard's documented read routes and the explicit operator-action routes (client mode, gate approve/reject, rollback, benign feedback). The request must carry a verified operator assertion in production.
- `CG_NAD_API_KEY` is supplied to NAD processor and gateway. It is restricted to `POST /v1/detections`; it cannot read fleet data or access approval, rollback, agent, or administrative routes.
- Agent credentials continue to use their existing per-asset and per-tenant allowlist.
- The API startup check requires all five administrator/workload/signing/decision secrets to be at least 32 bytes and pairwise distinct. Dashboard and NAD startup checks reject missing/weak workload credentials.
- `deploy/docker/.env.example` now documents independently generated credentials. The dashboard and NAD containers no longer receive the administrator API key.
- `service_auth.py` contains explicit default-deny scopes, with tests for allowed dashboard actions and denied agent/admin/NAD actions.

**Runtime gateway checks now pass:** production-mode tests verify a dashboard request without an assertion is rejected, a valid session-signed dashboard request is accepted, NAD cannot read fleet data, dashboard credentials cannot access agent command routes, and only an admin/operator dashboard assertion can satisfy gateway admin authorization. The audit start/completion writes execute as part of this tested request path. The API route allowlist still needs a complete comparison against every dashboard route and the full Compose deployment must validate audit persistence across services. The shared operator assertion secret remains a symmetric trust key; protect it as a server-only secret and rotate it using the documented deployment process. R3 remains in progress until the remaining acceptance checklist is evidenced.


## Dashboard browser and login hardening progress (2026-11-10)

- Dashboard and login pages now load external CSS and JavaScript from the same origin. Inline script/style blocks, inline event handlers and style attributes have been removed.
- The CSP no longer permits `unsafe-inline`; script/style attributes are explicitly denied. Dynamic UI values are HTML-escaped before insertion, including quotes and apostrophes.
- Production dashboard startup requires Secure cookies. HSTS is emitted only when Secure-cookie mode is enabled; terminate TLS at the trusted reverse proxy and keep the dashboard bound to localhost.
- Login throttling uses the authenticated peer IP unless the immediate peer is inside `CG_TRUSTED_PROXY_IPS`. Only then is `X-Forwarded-For` parsed, walking the proxy chain from right to left and skipping only configured trusted networks. Invalid proxy CIDRs fail production startup.
- Login-attempt storage is bounded by `CG_LOGIN_ATTEMPT_MAX_ROWS` (default 10,000) and pruned by the rolling window. Account-level throttling remains independent of source IP.

CI tests cover the external assets/CSP, HTML escaping, trusted-proxy selection, invalid proxy configuration and bounded login-attempt storage. These are code-level checks; the deployment's actual TLS proxy chain and client-IP forwarding must still be verified during the clone-and-test exercise.


## Latest CI evidence (2026-11-10)

GitHub Actions run [42863774080](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42863774080) passed all five jobs on commit `e686f05324ea0b54a39ff2e282ab8d9ddbad0d97`. The matrix covered Python 3.10/3.11/3.12, Docker API build/container smoke, and the disposable network-namespace containment integration. Python 3.11 reported 75 passing tests. This is automated CI evidence, not a full Docker Compose deployment or client-network validation.


## R3 operator onboarding and production operations

The tenant-scoped user provisioning CLI is available at `scripts/manage_dashboard_user.py`, with its implementation in `dashboard/user_admin.py`. It supports the explicit roles `admin`, `operator`, `analyst` and `viewer`; passwords are prompted interactively, PBKDF2-hashed and atomically written to the credential store. Duplicate users require an explicit `--replace`. Tests cover password hashing, tenant/role persistence, file mode and invalid role/duplicate rejection.

See [R3 production operations](R3_PRODUCTION_OPERATIONS.md) for independent secret generation, first-run setup, operator onboarding, secret rotation, TLS reverse-proxy requirements, trusted proxy configuration, and consistent backup/restore of the persistent data directory.

R3 production-mode Compose acceptance is now part of CI. Latest completed six-job run [42867381433](https://github.com/trintechdigitaldefense/cyberguardian/actions/runs/42867381433) passed on commit `1565851b4675591ef226b6d61078b332a6aead90`, including Python 3.10/3.11/3.12, Docker API smoke, disposable containment integration and the full production-mode Compose stack. R3 is accepted for the engineering roadmap; proceed to R4 on the security branch. This does not certify a client network or replace the R5 soak/pilot gates.
