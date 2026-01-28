from datetime import datetime
from models import (
    User, Organization, OrganizationMembership, MfaDevice,
    EmailAddress, AccountType, MfaMethod, SsoProvider
)
from authentication import PasswordService


async def initialize_test_data(container):
    """
    Initialize test data demonstrating all edge cases.
    
    Test Scenarios:
    1. D2C user (gmail.com)
    2. B2B single-org user (acme.com → Acme Corp)
    3. B2B multi-org user (consulting.com → Client A, Client B)
    4. SSO-enforced org (techcorp.com → TechCorp)
    5. MFA-required org (finance.com → FinanceCo)
    6. Mixed policy org (hybrid.com → Hybrid Inc)
    """
    
    password_service = PasswordService()
    
    # ========================================================================
    # SCENARIO 1: D2C USER
    # ========================================================================
    d2c_user = User(
        id="user_d2c_001",
        email=EmailAddress("alice@gmail.com"),
        name="Alice Smith",
        password_hash=password_service.hash_password("SecurePass123!"),
        account_type=AccountType.D2C,
        mfa_enrolled=False,
        mfa_methods=[],
        is_active=True,
        is_verified=True,
        is_locked=False,
        failed_login_attempts=0,
        last_login_at=None,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    await container.user_repo.create(d2c_user)
    
    # ========================================================================
    # SCENARIO 2: B2B SINGLE-ORG USER (ACME CORP)
    # ========================================================================
    acme_corp = Organization(
        id="org_acme_001",
        name="Acme Corporation",
        domain_mappings=["acme.com"],
        sso_enabled=False,
        sso_enforced=False,
        sso_provider=None,
        sso_config={},
        mfa_required=False,
        ip_whitelist=[],
        allow_password_auth=True,
        session_timeout_seconds=3600,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    await container.org_repo.create(acme_corp)
    
    bob_user = User(
        id="user_b2b_001",
        email=EmailAddress("bob@acme.com"),
        name="Bob Johnson",
        password_hash=password_service.hash_password("AcmePass456!"),
        account_type=AccountType.B2B,
        mfa_enrolled=False,
        mfa_methods=[],
        is_active=True,
        is_verified=True,
        is_locked=False,
        failed_login_attempts=0,
        last_login_at=None,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    await container.user_repo.create(bob_user)
    
    bob_membership = OrganizationMembership(
        user_id="user_b2b_001",
        organization_id="org_acme_001",
        role="engineer",
        permissions=["read", "write"],
        is_active=True,
        joined_at=datetime.utcnow()
    )
    await container.membership_repo.create(bob_membership)
    
    # ========================================================================
    # SCENARIO 3: B2B MULTI-ORG USER (CONSULTING FIRM)
    # ========================================================================
    client_a = Organization(
        id="org_client_a",
        name="Client A Inc",
        domain_mappings=["consulting.com"],
        sso_enabled=False,
        sso_enforced=False,
        sso_provider=None,
        sso_config={},
        mfa_required=False,
        ip_whitelist=[],
        allow_password_auth=True,
        session_timeout_seconds=7200,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    await container.org_repo.create(client_a)
    
    client_b = Organization(
        id="org_client_b",
        name="Client B Corp",
        domain_mappings=["consulting.com"],
        sso_enabled=False,
        sso_enforced=False,
        sso_provider=None,
        sso_config={},
        mfa_required=True,  # This org requires MFA
        ip_whitelist=[],
        allow_password_auth=True,
        session_timeout_seconds=3600,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    await container.org_repo.create(client_b)
    
    consultant_user = User(
        id="user_consultant_001",
        email=EmailAddress("carol@consulting.com"),
        name="Carol Consultant",
        password_hash=password_service.hash_password("ConsultPass789!"),
        account_type=AccountType.B2B,
        mfa_enrolled=True,
        mfa_methods=[MfaMethod.TOTP],
        is_active=True,
        is_verified=True,
        is_locked=False,
        failed_login_attempts=0,
        last_login_at=None,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    await container.user_repo.create(consultant_user)
    
    # Memberships in both orgs
    await container.membership_repo.create(OrganizationMembership(
        user_id="user_consultant_001",
        organization_id="org_client_a",
        role="consultant",
        permissions=["read"],
        is_active=True,
        joined_at=datetime.utcnow()
    ))
    
    await container.membership_repo.create(OrganizationMembership(
        user_id="user_consultant_001",
        organization_id="org_client_b",
        role="consultant",
        permissions=["read", "write"],
        is_active=True,
        joined_at=datetime.utcnow()
    ))
    
    # MFA device for consultant
    totp_device = MfaDevice(
        id="mfa_totp_001",
        user_id="user_consultant_001",
        method=MfaMethod.TOTP,
        is_verified=True,
        is_trusted=False,
        device_fingerprint=None,
        last_used_at=None,
        created_at=datetime.utcnow()
    )
    await container.mfa_device_repo.create(totp_device)
    
    # ========================================================================
    # SCENARIO 4: SSO-ENFORCED ORG
    # ========================================================================
    tech_corp = Organization(
        id="org_techcorp_001",
        name="TechCorp",
        domain_mappings=["techcorp.com"],
        sso_enabled=True,
        sso_enforced=True,  # SSO is mandatory
        sso_provider=SsoProvider.GOOGLE,
        sso_config={
            "client_id": "techcorp_google_client_id",
            "redirect_uri": "https://auth.techcorp.com/callback"
        },
        mfa_required=False,
        ip_whitelist=[],
        allow_password_auth=False,  # Password not allowed
        session_timeout_seconds=3600,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    await container.org_repo.create(tech_corp)
    
    david_user = User(
        id="user_sso_001",
        email=EmailAddress("david@techcorp.com"),
        name="David Tech",
        password_hash=None,  # SSO users don't have passwords
        account_type=AccountType.B2B,
        mfa_enrolled=False,
        mfa_methods=[],
        is_active=True,
        is_verified=True,
        is_locked=False,
        failed_login_attempts=0,
        last_login_at=None,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    await container.user_repo.create(david_user)
    
    await container.membership_repo.create(OrganizationMembership(
        user_id="user_sso_001",
        organization_id="org_techcorp_001",
        role="developer",
        permissions=["read", "write", "deploy"],
        is_active=True,
        joined_at=datetime.utcnow()
    ))
    
    # ========================================================================
    # SCENARIO 5: MFA-REQUIRED ORG (NO MFA ENROLLED - EDGE CASE #4)
    # ========================================================================
    finance_co = Organization(
        id="org_finance_001",
        name="FinanceCo",
        domain_mappings=["finance.com"],
        sso_enabled=False,
        sso_enforced=False,
        sso_provider=None,
        sso_config={},
        mfa_required=True,  # MFA is mandatory
        ip_whitelist=["192.168.1.0/24"],  # IP whitelist
        allow_password_auth=True,
        session_timeout_seconds=1800,  # 30 minutes
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    await container.org_repo.create(finance_co)
    
    eve_user = User(
        id="user_finance_001",
        email=EmailAddress("eve@finance.com"),
        name="Eve Finance",
        password_hash=password_service.hash_password("FinancePass999!"),
        account_type=AccountType.B2B,
        mfa_enrolled=False,  # NOT enrolled but org requires it
        mfa_methods=[],
        is_active=True,
        is_verified=True,
        is_locked=False,
        failed_login_attempts=0,
        last_login_at=None,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    await container.user_repo.create(eve_user)
    
    await container.membership_repo.create(OrganizationMembership(
        user_id="user_finance_001",
        organization_id="org_finance_001",
        role="analyst",
        permissions=["read"],
        is_active=True,
        joined_at=datetime.utcnow()
    ))
    
    # ========================================================================
    # SCENARIO 6: HYBRID ORG (BOTH SSO AND PASSWORD ALLOWED)
    # ========================================================================
    hybrid_inc = Organization(
        id="org_hybrid_001",
        name="Hybrid Inc",
        domain_mappings=["hybrid.com"],
        sso_enabled=True,
        sso_enforced=False,  # SSO available but not enforced
        sso_provider=SsoProvider.OKTA,
        sso_config={
            "domain": "hybrid.okta.com",
            "client_id": "hybrid_okta_client"
        },
        mfa_required=False,
        ip_whitelist=[],
        allow_password_auth=True,  # Both SSO and password allowed
        session_timeout_seconds=3600,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    await container.org_repo.create(hybrid_inc)
    
    frank_user = User(
        id="user_hybrid_001",
        email=EmailAddress("frank@hybrid.com"),
        name="Frank Hybrid",
        password_hash=password_service.hash_password("HybridPass111!"),
        account_type=AccountType.B2B,
        mfa_enrolled=False,
        mfa_methods=[],
        is_active=True,
        is_verified=True,
        is_locked=False,
        failed_login_attempts=0,
        last_login_at=None,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow()
    )
    await container.user_repo.create(frank_user)
    
    await container.membership_repo.create(OrganizationMembership(
        user_id="user_hybrid_001",
        organization_id="org_hybrid_001",
        role="manager",
        permissions=["read", "write", "admin"],
        is_active=True,
        joined_at=datetime.utcnow()
    ))
    
    print("✅ Test data initialized successfully")
    print("\nTest Users:")
    print("1. D2C: alice@gmail.com / SecurePass123!")
    print("2. B2B Single: bob@acme.com / AcmePass456!")
    print("3. B2B Multi-Org: carol@consulting.com / ConsultPass789!")
    print("4. SSO Only: david@techcorp.com (no password)")
    print("5. MFA Required (not enrolled): eve@finance.com / FinancePass999!")
    print("6. Hybrid: frank@hybrid.com / HybridPass111!")


# ============================================================================
# EXAMPLE GRAPHQL QUERIES
# ============================================================================

EXAMPLE_QUERIES = """
# ============================================================================
# EXAMPLE 1: D2C User Login (Simple Success)
# ============================================================================

mutation D2C_Login {
  login(input: {
    identifier: "alice@gmail.com"
    secret: "SecurePass123!"
    metadata: {
      ipAddress: "203.0.113.1"
      deviceFingerprint: "alice_laptop_chrome"
      userAgent: "Mozilla/5.0..."
    }
  }) {
    ... on LoginSuccess {
      __typename
      correlationId
      timestamp
      success
      sessionToken
      expiresIn
      user {
        id
        email
        name
        accountType
        mfaEnrolled
      }
      organization {
        id
        name
      }
    }
    ... on LoginFailure {
      __typename
      correlationId
      errorCode
      message
      retryAllowed
    }
  }
}

# Expected Response:
# {
#   "data": {
#     "login": {
#       "__typename": "LoginSuccess",
#       "success": true,
#       "sessionToken": "eyJhbGc...",
#       "user": {
#         "email": "alice@gmail.com",
#         "accountType": "D2C"
#       },
#       "organization": null
#     }
#   }
# }


# ============================================================================
# EXAMPLE 2: B2B Single-Org Login (Success)
# ============================================================================

mutation B2B_SingleOrg_Login {
  login(input: {
    identifier: "bob@acme.com"
    secret: "AcmePass456!"
  }) {
    ... on LoginSuccess {
      __typename
      sessionToken
      user {
        email
        accountType
      }
      organization {
        name
        role
        permissions
      }
    }
  }
}

# Expected Response:
# {
#   "data": {
#     "login": {
#       "__typename": "LoginSuccess",
#       "user": { "accountType": "B2B" },
#       "organization": {
#         "name": "Acme Corporation",
#         "role": "engineer",
#         "permissions": ["read", "write"]
#       }
#     }
#   }
# }


# ============================================================================
# EXAMPLE 3: Multi-Org Login (Organization Selection Challenge)
# ============================================================================

mutation MultiOrg_Login_Step1 {
  login(input: {
    identifier: "carol@consulting.com"
    secret: "ConsultPass789!"
  }) {
    ... on LoginChallenge {
      __typename
      challengeType
      challengeToken
      challengeData {
        ... on OrgSelectionChallenge {
          organizations {
            id
            name
            requiresSso
          }
          passwordValidated
        }
      }
    }
  }
}

# Expected Response:
# {
#   "data": {
#     "login": {
#       "__typename": "LoginChallenge",
#       "challengeType": "ORG_SELECTION",
#       "challengeToken": "cha_abc123...",
#       "challengeData": {
#         "organizations": [
#           {"id": "org_client_a", "name": "Client A Inc"},
#           {"id": "org_client_b", "name": "Client B Corp"}
#         ],
#         "passwordValidated": true
#       }
#     }
#   }
# }

# Step 2: User selects organization
mutation MultiOrg_Login_Step2 {
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


# ============================================================================
# EXAMPLE 4: SSO-Enforced Organization (SSO Redirect Challenge)
# ============================================================================

mutation SSO_Login {
  login(input: {
    identifier: "david@techcorp.com"
    secret: "anything"  # Ignored - SSO enforced
  }) {
    ... on LoginChallenge {
      __typename
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

# Expected Response:
# {
#   "data": {
#     "login": {
#       "__typename": "LoginChallenge",
#       "challengeType": "SSO_REDIRECT",
#       "challengeData": {
#         "provider": "GOOGLE",
#         "redirectUrl": "https://accounts.google.com/o/oauth2/..."
#       }
#     }
#   }
# }


# ============================================================================
# EXAMPLE 5: MFA Required (MFA Challenge)
# ============================================================================

mutation MFA_Login_Step1 {
  login(input: {
    identifier: "carol@consulting.com"
    secret: "ConsultPass789!"
    metadata: {
      preferredOrgId: "org_client_b"  # This org requires MFA
    }
  }) {
    ... on LoginChallenge {
      __typename
      challengeType
      challengeToken
      challengeData {
        ... on MfaChallenge {
          method
          deliveryTarget
          backupCodesAvailable
        }
      }
    }
  }
}

# Expected Response:
# {
#   "data": {
#     "login": {
#       "__typename": "LoginChallenge",
#       "challengeType": "MFA_REQUIRED",
#       "challengeToken": "cha_mfa_xyz...",
#       "challengeData": {
#         "method": "TOTP",
#         "deliveryTarget": null,
#         "backupCodesAvailable": true
#       }
#     }
#   }
# }

# Step 2: User enters TOTP code
mutation MFA_Login_Step2 {
  verifyChallenge(
    challengeToken: "cha_mfa_xyz..."
    challengeResponse: "123456"
  ) {
    ... on LoginSuccess {
      sessionToken
    }
    ... on LoginFailure {
      errorCode
      message
    }
  }
}


# ============================================================================
# EXAMPLE 6: Authentication Failure (Wrong Password)
# ============================================================================

mutation Failed_Login {
  login(input: {
    identifier: "bob@acme.com"
    secret: "WrongPassword!"
  }) {
    ... on LoginFailure {
      __typename
      correlationId
      errorCode
      message
      retryAllowed
      retryAfter
    }
  }
}

# Expected Response:
# {
#   "data": {
#     "login": {
#       "__typename": "LoginFailure",
#       "errorCode": "AUTHENTICATION_FAILED",
#       "message": "Invalid credentials. Please check your email and password.",
#       "retryAllowed": true,
#       "retryAfter": null
#     }
#   }
# }


# ============================================================================
# EXAMPLE 7: Rate Limit Exceeded
# ============================================================================

# After 10 failed attempts...

mutation RateLimited_Login {
  login(input: {
    identifier: "bob@acme.com"
    secret: "WrongPassword!"
  }) {
    ... on LoginFailure {
      errorCode
      message
      retryAfter
    }
  }
}

# Expected Response:
# {
#   "data": {
#     "login": {
#       "errorCode": "RATE_LIMIT_EXCEEDED",
#       "message": "Too many login attempts. Please try again later.",
#       "retryAfter": 900  # 15 minutes in seconds
#     }
#   }
# }


# ============================================================================
# EXAMPLE 8: IP Restricted
# ============================================================================

mutation IPRestricted_Login {
  login(input: {
    identifier: "eve@finance.com"
    secret: "FinancePass999!"
    metadata: {
      ipAddress: "203.0.113.100"  # Not in whitelist
    }
  }) {
    ... on LoginFailure {
      errorCode
      message
    }
  }
}

# Expected Response:
# {
#   "data": {
#     "login": {
#       "errorCode": "IP_RESTRICTED",
#       "message": "Access not permitted from this location."
#     }
#   }
# }


# ============================================================================
# EXAMPLE 9: Refresh Session
# ============================================================================

mutation RefreshSession {
  refreshSession(refreshToken: "ref_abc123...") {
    ... on LoginSuccess {
      sessionToken
      expiresIn
    }
    ... on LoginFailure {
      errorCode
    }
  }
}

"""

# Save example queries to file
with open("examples/queries.graphql", "w") as f:
    f.write(EXAMPLE_QUERIES)
