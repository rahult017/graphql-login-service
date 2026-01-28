# 🚀 Quick Start Guide

Get the login service running in 5 minutes!

## Prerequisites

- Python 3.11 or higher
- pip (Python package manager)

## Installation

### Step 1: Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- ariadne (GraphQL server)
- starlette (ASGI framework)
- uvicorn (ASGI server)
- bcrypt (password hashing)
- PyJWT (session tokens)
- pyotp (MFA/TOTP)

### Step 2: Start the Server

```bash
python start.py
```

You should see:

```
GraphQL Context-Aware Login Service
================================================================================
✓ Dependency container initialized

Initializing test data...
✅ Test data initialized successfully

Test Users:
1. D2C: alice@gmail.com / SecurePass123!
2. B2B Single: bob@acme.com / AcmePass456!
3. B2B Multi-Org: carol@consulting.com / ConsultPass789!
...

Server Configuration:
  Host: 0.0.0.0
  Port: 8000
  GraphQL Playground: http://0.0.0.0:8000/
================================================================================

Starting server...
```

### Step 3: Open GraphQL Playground

Navigate to: **http://localhost:8000**

## Try It Now!

### Test 1: Simple D2C Login ✅

Paste this into GraphQL Playground:

```graphql
mutation {
  login(input: {
    identifier: "alice@gmail.com"
    secret: "SecurePass123!"
  }) {
    ... on LoginSuccess {
      __typename
      sessionToken
      expiresIn
      user {
        email
        name
        accountType
      }
      organization {
        name
      }
    }
    ... on LoginFailure {
      __typename
      errorCode
      message
    }
  }
}
```

**Expected Result**: LoginSuccess with D2C account type, no organization

### Test 2: B2B Single-Org Login ✅

```graphql
mutation {
  login(input: {
    identifier: "bob@acme.com"
    secret: "AcmePass456!"
  }) {
    ... on LoginSuccess {
      user {
        accountType
      }
      organization {
        name
        role
      }
    }
  }
}
```

**Expected Result**: LoginSuccess with B2B account type, Acme Corporation organization

### Test 3: Multi-Org Login (Triggers Challenge) ✅

```graphql
mutation {
  login(input: {
    identifier: "carol@consulting.com"
    secret: "ConsultPass789!"
  }) {
    ... on LoginChallenge {
      __typename
      challengeType
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
```

**Expected Result**: LoginChallenge with ORG_SELECTION type, showing Client A and Client B

### Test 4: Wrong Password (Security Test) ✅

```graphql
mutation {
  login(input: {
    identifier: "alice@gmail.com"
    secret: "WrongPassword!"
  }) {
    ... on LoginFailure {
      errorCode
      message
      retryAllowed
    }
  }
}
```

**Expected Result**: LoginFailure with AUTHENTICATION_FAILED error (no hint about user existence)

### Test 5: SSO-Enforced Org ✅

```graphql
mutation {
  login(input: {
    identifier: "david@techcorp.com"
    secret: "anything"
  }) {
    ... on LoginChallenge {
      challengeType
      challengeData {
        ... on SsoChallenge {
          provider
          redirectUrl
        }
      }
    }
  }
}
```

**Expected Result**: LoginChallenge with SSO_REDIRECT type, Google OAuth URL

## Understanding the Responses

### LoginSuccess

```json
{
  "__typename": "LoginSuccess",
  "sessionToken": "eyJhbGc...",  // JWT token for authentication
  "expiresIn": 3600,              // Seconds until expiration
  "user": {
    "email": "alice@gmail.com",
    "accountType": "D2C"          // Automatically inferred!
  }
}
```

### LoginChallenge

```json
{
  "__typename": "LoginChallenge",
  "challengeType": "MFA_REQUIRED",
  "challengeToken": "cha_xyz...",  // Use this for verifyChallenge
  "challengeData": {
    "method": "TOTP",
    "deliveryTarget": null
  }
}
```

### LoginFailure

```json
{
  "__typename": "LoginFailure",
  "errorCode": "AUTHENTICATION_FAILED",
  "message": "Invalid credentials. Please check your email and password.",
  "retryAllowed": true
}
```

## Edge Cases Demonstrated

### 1️⃣ Multi-Organization User

Try `carol@consulting.com` - she belongs to two organizations.

**Flow**:
1. Login → Gets ORG_SELECTION challenge
2. Select organization via `verifyChallenge` mutation
3. Complete login with selected org context

### 2️⃣ Hybrid Authentication

Try `frank@hybrid.com` - organization allows both SSO and password.

**Flow**: Password login works. SSO also available (not enforced).

### 3️⃣ D2C → B2B Transition

Alice starts as D2C (`alice@gmail.com`). If we later map `gmail.com` to an organization, her next login automatically becomes B2B!

**Current**: D2C (no org mapping)
**After domain mapping**: Automatic B2B

### 4️⃣ MFA Required But Not Enrolled

Try `eve@finance.com` - organization requires MFA but she hasn't enrolled.

**Flow**: Gets MFA challenge with enrollment instructions.

### 5️⃣ SSO-Only Organization

Try `david@techcorp.com` - organization enforces SSO (no password).

**Flow**: Always redirects to Google SSO, password ignored.

## Common Issues

### Port Already in Use

```bash
# Use different port
export PORT=8001
python start.py
```

### Import Errors

```bash
# Ensure you're in the project directory
cd login-service
pip install -r requirements.txt
```

### bcrypt Installation Issues (Windows)

```bash
# Install Visual C++ build tools first, then:
pip install bcrypt
```

## Next Steps

1. **Read EXECUTIVE_SUMMARY.md** - High-level overview
2. **Read DESIGN.md** - Detailed architecture and trade-offs
3. **Explore schema.graphql** - Full API schema
4. **Check examples/** - More query examples

## Quick Reference

### All Test Users

| Email | Password | Type | Features |
|-------|----------|------|----------|
| alice@gmail.com | SecurePass123! | D2C | Simple login |
| bob@acme.com | AcmePass456! | B2B | Single org |
| carol@consulting.com | ConsultPass789! | B2B | Multi-org, MFA |
| david@techcorp.com | (none) | B2B | SSO-only |
| eve@finance.com | FinancePass999! | B2B | MFA required |
| frank@hybrid.com | HybridPass111! | B2B | Hybrid auth |

### GraphQL Endpoints

- **Playground**: http://localhost:8000/
- **API**: http://localhost:8000/graphql

### Mutations

- `login(input: LoginInput!)` - Main login
- `verifyChallenge(...)` - Verify MFA/org selection
- `refreshSession(...)` - Refresh token

## Need Help?

- Check **README.md** for full documentation
- Review **DESIGN.md** for architecture details
- See **test_data.py** for test data setup
- Contact: [Your contact info]

---

**Happy Testing! 🎉**
