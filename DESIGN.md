"""
DESIGN DOCUMENTATION
Context-Aware Login Service

Author: Expert System Designer
Date: 2026
Version: 1.0

================================================================================
TABLE OF CONTENTS
================================================================================

1. Architecture Overview
2. Context Inference Logic
3. Authentication Flow State Machine
4. Edge Case Handling
5. Security Considerations
6. Performance Optimization
7. Scalability & Production Deployment
8. Trade-off Analysis

================================================================================
1. ARCHITECTURE OVERVIEW
================================================================================

The system follows a layered architecture with clear separation of concerns:

┌─────────────────────────────────────────────────────────────────┐
│                        Presentation Layer                        │
│  GraphQL Resolver → Input Validation → Response Formatting      │
└────────────────────┬────────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────────┐
│                     Orchestration Layer                          │
│  LoginOrchestrator → State Machine → Challenge Coordination     │
└────────────────────┬────────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────────┐
│                      Business Logic Layer                        │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────┐       │
│  │ Context       │  │ Authentication│  │ MFA Service    │       │
│  │ Inference     │  │ Service       │  │                │       │
│  └───────────────┘  └──────────────┘  └────────────────┘       │
│  ┌───────────────┐  ┌──────────────┐  ┌────────────────┐       │
│  │ Session       │  │ SSO Service   │  │ Rate Limiter   │       │
│  │ Service       │  │               │  │                │       │
│  └───────────────┘  └──────────────┘  └────────────────┘       │
└────────────────────┬────────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────────┐
│                       Domain Layer                               │
│  Value Objects → Entities → Aggregates → Business Rules         │
└────────────────────┬────────────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────────────┐
│                    Infrastructure Layer                          │
│  Repositories → Cache → External Services → Monitoring          │
└─────────────────────────────────────────────────────────────────┘

Key Design Principles:
- **Single Responsibility**: Each service has one clear purpose
- **Dependency Inversion**: High-level modules don't depend on low-level
- **Open/Closed**: Extensible without modifying existing code
- **Interface Segregation**: Clients only depend on methods they use

================================================================================
2. CONTEXT INFERENCE LOGIC
================================================================================

Context inference is THE core differentiator of this system.

Algorithm:
----------
```python
def infer_context(email: EmailAddress) -> AuthenticationContext:
    1. Extract domain from email
    2. Query organizations mapped to domain
    3. If organizations found:
        - Account type = B2B
        - Get user's memberships
        - Filter organizations to those user belongs to
    4. Else:
        - Account type = D2C
        - Organizations = empty list
    5. Determine requirements:
        - SSO required? Check org policies
        - MFA required? Check org + user settings
        - Org selection needed? Multiple orgs?
        - IP allowed? Check whitelists
    6. Return complete context
```

Domain Mapping Example:
-----------------------
Domain: acme.com
Organizations: [Acme Corp (id=org1), Acme Industries (id=org2)]

User: john@acme.com
Memberships: [org1, org2]
→ Requires organization selection

User: jane@acme.com  
Memberships: [org1]
→ Direct login to org1

User: newuser@acme.com
Memberships: []
→ Domain is B2B but user not member (would fail or trigger invite flow)

D2C Example:
------------
Domain: gmail.com
Organizations: []
→ D2C user, password-only authentication

Transition Scenario (Edge Case #3):
------------------------------------
1. User starts as D2C: alice@gmail.com, no org mappings
2. Company maps gmail.com domain (maybe for contractors)
3. Alice added to organization
4. Next login: Context engine detects org mapping → B2B flow
5. Alice sees organization selection / SSO requirements

This handles the "D2C user joins B2B org" edge case transparently.

================================================================================
3. AUTHENTICATION FLOW STATE MACHINE
================================================================================

State Machine Definition:
-------------------------

States:
- INITIAL: Request received
- CONTEXT_INFERRED: Domain and org context determined
- IP_VALIDATED: IP whitelist check complete
- CREDENTIAL_VALIDATED: Password or SSO token verified
- MFA_PENDING: Awaiting MFA verification
- ORG_SELECTION_PENDING: Awaiting org choice
- AUTHENTICATED: All checks passed
- FAILED: Authentication failed
- LOCKED: Account/IP locked

Transitions:
------------

INITIAL 
  → CONTEXT_INFERRED (always)

CONTEXT_INFERRED
  → FAILED (if IP not whitelisted)
  → ORG_SELECTION_PENDING (if multi-org and no preference)
  → CREDENTIAL_VALIDATED (if SSO token provided)
  → CREDENTIAL_VALIDATED (via password auth)

ORG_SELECTION_PENDING
  → CONTEXT_INFERRED (loop back with selected org)

CREDENTIAL_VALIDATED
  → FAILED (if credentials invalid)
  → MFA_PENDING (if MFA required)
  → AUTHENTICATED (if no additional challenges)

MFA_PENDING
  → FAILED (if MFA invalid or max attempts)
  → AUTHENTICATED (if MFA valid)

AUTHENTICATED
  → Session Created (terminal state)

FAILED
  → Rate Limit Check (may transition to LOCKED)

Example Flow: B2B User with MFA
--------------------------------
1. User submits: alice@acme.com + password
2. INITIAL → CONTEXT_INFERRED
   - Domain acme.com maps to Acme Corp
   - User is member of Acme Corp
   - Acme Corp requires MFA
3. CONTEXT_INFERRED → CREDENTIAL_VALIDATED
   - Password verified against bcrypt hash
4. CREDENTIAL_VALIDATED → MFA_PENDING
   - TOTP challenge issued
   - ChallengeSession created
   - Return LoginChallenge response
5. User submits: challengeToken + 6-digit code
6. MFA_PENDING → AUTHENTICATED
   - TOTP verified
   - Session created
   - Return LoginSuccess response

Example Flow: Multi-Org User
-----------------------------
1. User submits: bob@consulting.com + password
2. INITIAL → CONTEXT_INFERRED
   - Domain maps to: ClientA, ClientB, ClientC
   - User is member of all three
3. CONTEXT_INFERRED → ORG_SELECTION_PENDING
   - Return LoginChallenge with OrgSelectionChallenge
4. User selects: ClientA
5. ORG_SELECTION_PENDING → CONTEXT_INFERRED (with ClientA context)
6. CONTEXT_INFERRED → CREDENTIAL_VALIDATED
   - Password already validated (stored in challenge session)
7. CREDENTIAL_VALIDATED → AUTHENTICATED (if ClientA doesn't require MFA)

================================================================================
4. EDGE CASE HANDLING
================================================================================

The interview specifically called out five edge cases. Here's how each is handled:

Edge Case 1: Same email domain maps to multiple organizations
--------------------------------------------------------------
Example: alice@acme.com where acme.com maps to "Acme Corp" and "Acme Labs"

Solution:
1. Context engine detects multi-org scenario
2. Returns LoginChallenge with ChallengeType=ORG_SELECTION
3. Challenge includes list of available organizations
4. User selects organization
5. verifyChallenge mutation processes selection
6. Flow continues with selected org context

Implementation: ContextInferenceEngine._requires_org_selection()

Code:
```python
def _requires_org_selection(user_orgs, metadata):
    if len(user_orgs) <= 1:
        return False
    if metadata.preferred_org_id:
        return False  # User provided preference
    return True  # Multiple orgs, no preference
```

Edge Case 2: Organization supports both SSO and password login
---------------------------------------------------------------
Example: Acme Corp has sso_enabled=True but sso_enforced=False

Solution:
1. Allow both authentication methods
2. If user provides SSO token → SSO path
3. If user provides password → Password path
4. Organization policy: allow_password_auth=True allows password
5. User can choose authentication method by what they submit

Implementation: Organization.supports_password_login()

Code:
```python
def supports_password_login(self):
    return self.allow_password_auth and not self.sso_enforced
```

Design Decision: Password is attempted first if secret looks like password
(length < 100 chars). SSO tokens are typically JWTs > 100 chars.

Edge Case 3: D2C user later joins B2B organization
---------------------------------------------------
Example: 
- Day 1: alice@gmail.com signs up (D2C)
- Day 30: Company adds gmail.com domain mapping
- Day 31: Alice added to organization
- Day 32: Alice logs in

Solution:
1. Context engine re-evaluates on every login
2. Detects gmail.com now maps to organization
3. Account type automatically switches to B2B
4. User experiences B2B flow (org selection, SSO, etc.)
5. No migration needed - it's dynamic

Implementation: ContextInferenceEngine._determine_account_type()

Code:
```python
def _determine_account_type(domain_orgs, user_orgs):
    if domain_orgs:  # Domain mapped to any org
        return AccountType.B2B
    return AccountType.D2C
```

This is why we DON'T store account type on the user - it's inferred fresh
each login based on current domain mappings.

Edge Case 4: MFA-required org but user has no enrolled MFA device
------------------------------------------------------------------
Example: Acme Corp sets mfa_required=True, but user Alice has no MFA devices

Solution:
1. Context engine detects MFA requirement
2. MFA service attempts to initiate challenge
3. Detects no enrolled devices
4. Returns challenge with challenge_data="enrollment_required"
5. Response includes enrollment instructions / QR code
6. User completes enrollment
7. Retry login flow with MFA now enrolled

Implementation: MfaService.initiate_mfa_challenge()

Code:
```python
async def initiate_mfa_challenge(user, correlation_id):
    devices = await get_user_mfa_devices(user.id)
    if not devices:
        return (MfaMethod.TOTP, None, "enrollment_required")
    # ... normal challenge flow
```

Alternative Design: Auto-enroll user in TOTP and return QR code in challenge.

Edge Case 5: MFA provider partially unavailable
------------------------------------------------
Example: SMS provider (Twilio) is down but TOTP still works

Solution - Graceful Degradation:
1. MFA service checks method availability before selection
2. If SMS unavailable → fallback to TOTP
3. If TOTP unavailable → fallback to Email
4. If all unavailable → Two options:
   a. STRICT: Deny login, return SERVICE_UNAVAILABLE
   b. PERMISSIVE: Allow login but flag for security review

Implementation: MfaService._select_mfa_method() with circuit breaker

Code:
```python
async def _select_mfa_method(devices, preferred):
    for method in [TOTP, SMS, EMAIL, BACKUP_CODE]:
        if method in device_methods:
            if await self._is_method_available(method):
                return method
    # All methods down
    raise MfaUnavailableError()
```

Circuit breaker pattern prevents cascading failures:
```python
async def _is_method_available(method):
    if method == TOTP: return True  # Local, always available
    if method == SMS: 
        return await circuit_breaker.check(sms_service)
```

Current Implementation: Permissive fallback with audit log.

================================================================================
5. SECURITY CONSIDERATIONS
================================================================================

5.1 Timing Attack Prevention
-----------------------------
**Threat**: Attacker measures response time to enumerate valid users

**Mitigation**:
```python
def verify_password(password, hash, user_exists):
    # ALWAYS hash, even if user doesn't exist
    hash_to_compare = hash if hash else DUMMY_HASH
    
    result = bcrypt.checkpw(password, hash_to_compare)
    
    # Only return true if BOTH user exists AND password matches
    return user_exists and result
```

This ensures:
- Non-existent user: ~100ms (dummy hash verification)
- Wrong password: ~100ms (real hash verification)
- Correct password: ~100ms (real hash verification)

No timing difference reveals user existence.

5.2 User Enumeration Prevention
--------------------------------
**Threat**: Attacker tries to discover valid email addresses

**Mitigation**:
1. Generic error messages
   - "Invalid credentials" (not "user not found" or "wrong password")
   - "Authentication failed" for all failure modes

2. Constant-time operations
   - Always perform password hash even if user doesn't exist

3. No existence hints in responses
   - Password reset: "If account exists, email sent" (even if it doesn't)
   - Challenge responses: Never indicate "user not found"

5.3 Rate Limiting
------------------
**Implementation**:
- Per-email: 10 attempts/hour
- Per-IP: 50 attempts/hour
- Exponential backoff after threshold
- Account lockout: 15 minutes after 5 failed attempts

**Distributed State**: Redis with sliding window

```python
rate_limit:email:alice@example.com → {attempts: 3, window_start: timestamp}
rate_limit:ip:1.2.3.4 → {attempts: 15, locked_until: timestamp}
```

5.4 Session Security
--------------------
- JWT with HMAC-SHA256 signature
- Short-lived tokens (1 hour default)
- Refresh tokens for extension
- Device fingerprinting for anomaly detection
- IP binding (optional, org-specific)

5.5 Password Security
----------------------
- bcrypt with cost factor 12 (2^12 = 4096 rounds)
- Minimum requirements enforced
- No password in logs or error messages
- Secure comparison (constant-time)

5.6 MFA Security
----------------
- TOTP with 30-second window
- SMS/Email codes: 6 digits, 5-minute validity
- One-time use enforcement
- Backup codes: Hashed, single-use

5.7 SSO Security
----------------
- PKCE for OAuth flows
- State parameter for CSRF protection
- Token signature verification
- Nonce validation for replay prevention

5.8 Correlation IDs
-------------------
Every request gets unique ID for:
- Audit trail
- Distributed tracing
- Support debugging
- Security incident investigation

Format: `secrets.token_urlsafe(16)` → 22 chars, URL-safe base64

================================================================================
6. PERFORMANCE OPTIMIZATION
================================================================================

6.1 Target: P95 Latency < 300ms
--------------------------------

Breakdown:
- Context inference: ~20ms (2 DB queries)
- Password verification: ~100ms (bcrypt cost 12)
- MFA generation: ~10ms (local TOTP)
- Session creation: ~15ms (1 DB write, 1 cache write)
- Response serialization: ~5ms
Total: ~150ms typical case

Optimizations:
1. **Database query optimization**
   - Indexed email lookups
   - Indexed domain lookups
   - Join optimization for memberships

2. **Caching strategy**
   - Organization policies: 5-minute cache
   - Domain mappings: 10-minute cache
   - User data: No cache (security)

3. **Async I/O**
   - All database operations async
   - Concurrent MFA delivery (SMS + Email)
   - Non-blocking external calls

4. **Connection pooling**
   - PostgreSQL: Pool size 20
   - Redis: Pool size 50

6.2 Horizontal Scalability
---------------------------
Stateless design enables horizontal scaling:
- No in-memory state (all in Redis/DB)
- Load balancer distributes requests
- Auto-scaling based on CPU/latency
- Multiple regions for geo-distribution

================================================================================
7. SCALABILITY & PRODUCTION DEPLOYMENT
================================================================================

7.1 Infrastructure
-------------------
```
                   ┌─────────────┐
                   │   Route 53  │  DNS / Global Load Balancing
                   └──────┬──────┘
                          │
                   ┌──────▼──────┐
                   │   CloudFlare│  DDoS Protection, WAF
                   └──────┬──────┘
                          │
              ┌───────────▼───────────┐
              │   Application LB      │  Layer 7 Load Balancer
              └───────────┬───────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
    ┌────▼────┐      ┌────▼────┐     ┌────▼────┐
    │  API    │      │  API    │     │  API    │
    │ Server  │      │ Server  │     │ Server  │
    │  Pod 1  │      │  Pod 2  │     │  Pod N  │
    └────┬────┘      └────┬────┘     └────┬────┘
         │                │                │
         └────────────────┼────────────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
    ┌────▼─────┐    ┌─────▼────┐    ┌─────▼────┐
    │PostgreSQL│    │  Redis   │    │  Kafka   │
    │ Primary  │    │ Cluster  │    │  Events  │
    └────┬─────┘    └──────────┘    └──────────┘
         │
    ┌────▼─────┐
    │PostgreSQL│
    │ Replica  │
    └──────────┘
```

7.2 Database Schema
-------------------
```sql
-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),
    account_type VARCHAR(10),  -- Note: Could be computed
    mfa_enrolled BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    is_locked BOOLEAN DEFAULT FALSE,
    failed_attempts INTEGER DEFAULT 0,
    last_login_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_users_email ON users(email);

-- Organizations table
CREATE TABLE organizations (
    id UUID PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    domain_mappings TEXT[],  -- Array of domains
    sso_enabled BOOLEAN DEFAULT FALSE,
    sso_enforced BOOLEAN DEFAULT FALSE,
    sso_provider VARCHAR(50),
    mfa_required BOOLEAN DEFAULT FALSE,
    ip_whitelist TEXT[],
    allow_password_auth BOOLEAN DEFAULT TRUE,
    session_timeout_seconds INTEGER DEFAULT 3600,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_orgs_domains ON organizations USING GIN(domain_mappings);

-- Organization memberships
CREATE TABLE org_memberships (
    user_id UUID REFERENCES users(id),
    org_id UUID REFERENCES organizations(id),
    role VARCHAR(50),
    permissions TEXT[],
    is_active BOOLEAN DEFAULT TRUE,
    joined_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (user_id, org_id)
);

CREATE INDEX idx_memberships_user ON org_memberships(user_id);
CREATE INDEX idx_memberships_org ON org_memberships(org_id);
```

7.3 Monitoring & Observability
-------------------------------
```python
# Metrics to track
metrics = {
    'login.attempts': Counter,
    'login.success': Counter,
    'login.failures': Counter,
    'login.latency': Histogram,
    'mfa.challenges': Counter,
    'mfa.successes': Counter,
    'rate_limit.hits': Counter,
    'context.inference.latency': Histogram
}

# Distributed tracing
@trace_span('login.execute')
async def execute_login(...):
    with trace_span('context.infer'):
        context = await infer_context()
    
    with trace_span('auth.validate'):
        result = await authenticate()
```

Tools:
- Datadog for metrics
- Jaeger for tracing
- ELK stack for logs
- PagerDuty for alerts

7.4 Disaster Recovery
----------------------
- Multi-region deployment
- Database replication (async for reads)
- Redis persistence (RDB + AOF)
- Automated backups (hourly snapshots)
- Failover automation (<60s RTO)

================================================================================
8. TRADE-OFF ANALYSIS
================================================================================

8.1 Single Mutation vs Multiple Mutations
------------------------------------------
**Decision**: Single `login` mutation

Pros:
- Simpler client integration
- No "which endpoint" decision
- Implicit context inference (meets requirement)
- Consistent error handling

Cons:
- Less explicit intent
- Harder to optimize per-type
- More complex resolver logic

Justification: Requirement explicitly states "single login mutation".

8.2 Polymorphic Response vs Error Codes
----------------------------------------
**Decision**: Polymorphic (LoginSuccess | LoginChallenge | LoginFailure)

Pros:
- Type-safe client code
- Rich challenge data
- Clear state progression
- GraphQL best practice

Cons:
- More complex schema
- Client must handle unions
- Larger response payloads

Justification: Provides best developer experience and type safety.

8.3 Stateful Challenge Sessions vs Stateless
---------------------------------------------
**Decision**: Stateful (Redis-backed challenge tokens)

Pros:
- Can store partial progress
- More secure (no data in token)
- Can invalidate challenges
- Server controls expiration

Cons:
- Requires distributed storage
- Adds latency
- More complex deployment

Justification: Security and user experience outweigh complexity.

8.4 Account Type: Stored vs Computed
-------------------------------------
**Decision**: Computed on every login

Pros:
- No migration when domain mappings change
- Always current
- Handles edge case #3 perfectly
- Simpler data model

Cons:
- Slightly more computation per request
- Can't query "all B2B users" easily

Justification: Dynamic computation is core to implicit context inference.

8.5 MFA Fallback: Strict vs Permissive
---------------------------------------
**Decision**: Permissive (allow login if MFA unavailable)

Pros:
- Better availability
- Reduces support burden
- Graceful degradation

Cons:
- Slightly less secure
- Could mask issues

Justification: Availability is critical for login service. We audit all
permissive decisions and flag for review.

8.6 Error Messages: Specific vs Generic
----------------------------------------
**Decision**: Generic (prevent user enumeration)

Pros:
- Security (no information leakage)
- Consistent experience
- Prevents enumeration attacks

Cons:
- Less helpful for debugging
- User frustration

Justification: Security requirement ("must not leak user or org existence").

================================================================================
END OF DESIGN DOCUMENTATION
================================================================================
"""