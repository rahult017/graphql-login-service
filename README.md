# Context-Aware Login Service

A production-ready GraphQL-based authentication service supporting both D2C and B2B users with implicit context inference.

## 🎯 Project Overview

This service implements a unified login flow that automatically determines whether a user is D2C or B2B based on email domain mapping, without requiring explicit context specification from the client.

### Key Features

✅ **Single Login Mutation** - One endpoint handles all authentication flows
✅ **Implicit Context Inference** - Automatically detects D2C vs B2B from email domain
✅ **Polymorphic Responses** - Type-safe success/challenge/failure responses
✅ **Multi-Organization Support** - Handles users belonging to multiple organizations
✅ **Flexible Authentication** - Supports password, SSO, and mixed policies
✅ **Multi-Factor Authentication** - TOTP, SMS, Email, backup codes
✅ **Security Hardened** - Timing attack prevention, rate limiting, no user enumeration
✅ **Edge Case Coverage** - Comprehensive handling of all specified edge cases

## 📋 Requirements Met

This implementation addresses all requirements from the interview assignment:

1. ✅ Single `login` mutation supporting both D2C and B2B
2. ✅ Customer type inferred implicitly (never passed by client)
3. ✅ LoginInput with identifier, secret, and metadata
4. ✅ Polymorphic responses (LoginSuccess | LoginChallenge | LoginFailure)
5. ✅ No user/organization existence leakage
6. ✅ Deterministic error messages
7. ✅ Timing attack prevention
8. ✅ Correlation IDs for all requests
9. ✅ Target P95 latency < 300ms
10. ✅ All five edge cases handled

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    GraphQL Layer                         │
│  Resolvers → Input Validation → Response Formatting     │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│              Login Orchestrator                          │
│  State Machine → Challenge Coordination → Flow Control  │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                Service Layer                             │
│  ├─ Context Inference Engine (D2C vs B2B detection)     │
│  ├─ Authentication Service (Password & SSO)             │
│  ├─ MFA Service (TOTP, SMS, Email)                      │
│  ├─ Session Service (JWT tokens)                        │
│  └─ Rate Limiter (Distributed rate limiting)            │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│                Domain Layer                              │
│  Value Objects → Entities → Business Rules               │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────▼────────────────────────────────────┐
│             Infrastructure Layer                         │
│  Repositories → Cache → External Services                │
└─────────────────────────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Python 3.11+
- pip or poetry

### Installation

```bash
# Clone repository
git clone <repository-url>
cd login-service

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Service

```bash
# Development mode (with auto-reload)
python start.py

# Production mode
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

The service will start on `http://localhost:8000`

### GraphQL Playground

Open `http://localhost:8000` in your browser to access the GraphQL Playground.

## 📊 Test Data

The service comes with pre-configured test data demonstrating all edge cases:

### Test Users

| Email | Password | Type | Features |
|-------|----------|------|----------|
| alice@gmail.com | SecurePass123! | D2C | Simple password login |
| bob@acme.com | AcmePass456! | B2B | Single organization |
| carol@consulting.com | ConsultPass789! | B2B | Multiple organizations, MFA |
| david@techcorp.com | N/A | B2B | SSO-only (Google) |
| eve@finance.com | FinancePass999! | B2B | MFA required but not enrolled |
| frank@hybrid.com | HybridPass111! | B2B | Both SSO and password allowed |

### Initialize Test Data

```python
from test_data import initialize_test_data
from main import create_app

app = create_app()
container = app.state.container

# In async context:
await initialize_test_data(container)
```

## 🔍 Example Queries

### Simple D2C Login

```graphql
mutation {
  login(input: {
    identifier: "alice@gmail.com"
    secret: "SecurePass123!"
    metadata: {
      ipAddress: "203.0.113.1"
      deviceFingerprint: "alice_laptop"
    }
  }) {
    ... on LoginSuccess {
      sessionToken
      expiresIn
      user {
        email
        accountType
      }
    }
    ... on LoginFailure {
      errorCode
      message
    }
  }
}
```

### B2B Login with Organization Selection

```graphql
# Step 1: Initial login (triggers org selection)
mutation {
  login(input: {
    identifier: "carol@consulting.com"
    secret: "ConsultPass789!"
  }) {
    ... on LoginChallenge {
      challengeType
      challengeToken
      challengeData {
        ... on OrgSelectionChallenge {
          organizations {
            id
            name
          }
        }
      }
    }
  }
}

# Step 2: Select organization
mutation {
  verifyChallenge(
    challengeToken: "cha_abc123..."
    challengeResponse: "org_client_a"
  ) {
    ... on LoginSuccess {
      sessionToken
      organization { name }
    }
  }
}
```

### SSO Login

```graphql
mutation {
  login(input: {
    identifier: "david@techcorp.com"
    secret: "any"  # Ignored - SSO enforced
  }) {
    ... on LoginChallenge {
      challengeType
      challengeData {
        ... on SsoChallenge {
          redirectUrl
          provider
        }
      }
    }
  }
}
```

More examples in `examples/queries.graphql`

## 🎯 Edge Case Handling

### 1. Same Email Domain → Multiple Organizations

**Scenario**: `carol@consulting.com` belongs to Client A and Client B

**Handling**:
- Context engine detects multiple organizations
- Returns `LoginChallenge` with `OrgSelectionChallenge`
- User selects organization via `verifyChallenge`
- Flow continues with selected organization context

### 2. Organization Supports Both SSO and Password

**Scenario**: Hybrid Inc allows both authentication methods

**Handling**:
- If secret looks like password (< 100 chars) → password auth
- If secret looks like SSO token (JWT format) → SSO auth
- Organization policy determines what's allowed
- User chooses by what they submit

### 3. D2C User Joins B2B Organization

**Scenario**: Alice starts as D2C, later company maps gmail.com domain

**Handling**:
- Account type is **computed on every login** (not stored)
- Context engine re-evaluates domain mappings
- Automatically switches to B2B flow when domain mapped
- No migration needed - completely dynamic

### 4. MFA Required but User Not Enrolled

**Scenario**: FinanceCo requires MFA but Eve hasn't enrolled

**Handling**:
- MFA service detects no enrolled devices
- Returns challenge with `challenge_data = "enrollment_required"`
- Includes TOTP QR code in challenge
- User enrolls and retries login

### 5. MFA Provider Partially Unavailable

**Scenario**: SMS provider (Twilio) is down

**Handling**:
- MFA service checks method availability
- Falls back to TOTP (always available locally)
- If all methods down: graceful degradation
- Allows login but flags for security review
- Circuit breaker prevents cascading failures

## 🔒 Security Features

### Timing Attack Prevention

```python
# Always performs hash comparison, even if user doesn't exist
def verify_password(password, hash, user_exists):
    hash_to_compare = hash if hash else DUMMY_HASH
    result = bcrypt.checkpw(password, hash_to_compare)
    return user_exists and result  # Constant time
```

### No User Enumeration

- Generic error messages: "Invalid credentials" (never "user not found")
- Constant-time operations for all authentication paths
- No existence hints in any responses

### Rate Limiting

- Per-email: 10 attempts/hour
- Per-IP: 50 attempts/hour
- Exponential backoff
- Account lockout after 5 failures (15 min)

### Secure Sessions

- JWT with HMAC-SHA256
- Short-lived tokens (1 hour)
- Refresh token support
- Device fingerprinting
- IP binding (optional)

### Password Security

- bcrypt with cost factor 12
- Minimum complexity requirements
- Never logged or exposed

### Correlation IDs

Every request gets unique ID for:
- Audit trail
- Distributed tracing
- Support debugging
- Incident investigation

## 📈 Performance

### Latency Targets

- P50: < 100ms
- P95: < 300ms
- P99: < 500ms

### Optimizations

1. **Database query optimization**
   - Indexed email/domain lookups
   - Connection pooling
   - Read replicas for scaling

2. **Caching strategy**
   - Organization policies: 5-minute cache
   - Domain mappings: 10-minute cache
   - No user data caching (security)

3. **Async I/O**
   - All operations async
   - Concurrent external calls
   - Non-blocking database access

4. **Horizontal scalability**
   - Stateless design
   - Redis for distributed state
   - Load balancer ready

## 🏭 Production Deployment

### Environment Variables

```bash
# Server
HOST=0.0.0.0
PORT=8000
DEBUG=false

# Security
SECRET_KEY=your-256-bit-secret-key
ALLOWED_ORIGINS=https://app.example.com

# Rate Limiting
MAX_ATTEMPTS_PER_HOUR=10
MAX_ATTEMPTS_PER_IP=50

# Session
SESSION_TIMEOUT=3600

# External Services
SMS_PROVIDER=twilio
EMAIL_PROVIDER=sendgrid
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["gunicorn", "main:app", "-w", "4", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000"]
```

### Kubernetes

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: login-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: login-service
  template:
    spec:
      containers:
      - name: login-service
        image: login-service:latest
        ports:
        - containerPort: 8000
        env:
        - name: SECRET_KEY
          valueFrom:
            secretKeyRef:
              name: login-secrets
              key: secret-key
```

## 📚 Documentation

- **Design Documentation**: See `DESIGN.md` for detailed architecture and trade-off analysis
- **API Schema**: See `schema.graphql` for complete GraphQL schema
- **Example Queries**: See `examples/queries.graphql` for usage examples

## 🧪 Testing

```bash
# Run tests
pytest

# With coverage
pytest --cov=. --cov-report=html

# Type checking
mypy .

# Linting
flake8 .
black --check .
```

## 📊 Monitoring

### Metrics to Track

- `login.attempts` - Total login attempts
- `login.success` - Successful logins
- `login.failures` - Failed logins
- `login.latency` - Request latency histogram
- `mfa.challenges` - MFA challenges issued
- `rate_limit.hits` - Rate limit violations

### Logging

All operations logged with correlation IDs:

```
[correlation_id_123] Starting login flow for gmail.com
[correlation_id_123] Context inferred: type=d2c, orgs=0
[correlation_id_123] Password validated successfully
[correlation_id_123] Session created: ses_abc... expires in 3600s
```

### Alerting

- Failed login rate > 10%
- P95 latency > 300ms
- MFA provider down
- Database connection errors

## 🤝 Contributing

1. Fork repository
2. Create feature branch
3. Add tests for new features
4. Ensure all tests pass
5. Submit pull request

## 📝 License

MIT License

## 👤 Author

Expert System Designer

## 🙏 Acknowledgments

Built as a demonstration of production-grade authentication system design for Anthropic interview process.
