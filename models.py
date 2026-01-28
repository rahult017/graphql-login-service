from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
import re


class AccountType(Enum):
    """User account classification"""
    D2C = "d2c"
    B2B = "b2b"


class ChallengeType(Enum):
    """Types of authentication challenges"""
    MFA_REQUIRED = "mfa_required"
    SSO_REDIRECT = "sso_redirect"
    ORG_SELECTION = "org_selection"
    PASSWORD_RESET = "password_reset"
    EMAIL_VERIFICATION = "email_verification"
    TOS_ACCEPTANCE = "tos_acceptance"


class MfaMethod(Enum):
    """Supported MFA methods"""
    TOTP = "totp"
    SMS = "sms"
    EMAIL = "email"
    PUSH = "push"
    SECURITY_KEY = "security_key"
    BACKUP_CODE = "backup_code"


class ErrorCode(Enum):
    """Authentication error codes"""
    AUTHENTICATION_FAILED = "authentication_failed"
    INVALID_INPUT = "invalid_input"
    RATE_LIMIT_EXCEEDED = "rate_limit_exceeded"
    SERVICE_UNAVAILABLE = "service_unavailable"
    ACCOUNT_LOCKED = "account_locked"
    SESSION_EXPIRED = "session_expired"
    CHALLENGE_FAILED = "challenge_failed"
    IP_RESTRICTED = "ip_restricted"


class AuthenticationMethod(Enum):
    """How the user authenticated"""
    PASSWORD = "password"
    SSO = "sso"
    MAGIC_LINK = "magic_link"
    API_KEY = "api_key"


class SsoProvider(Enum):
    """Supported SSO providers"""
    GOOGLE = "google"
    OKTA = "okta"
    AZURE_AD = "azure_ad"
    ONELOGIN = "onelogin"
    SAML_GENERIC = "saml_generic"


@dataclass(frozen=True)
class EmailAddress:
    """Email address value object with validation"""
    value: str
    
    def __post_init__(self):
        if not self._is_valid_email(self.value):
            raise ValueError(f"Invalid email address: {self.value}")
    
    @property
    def domain(self) -> str:
        """Extract domain from email"""
        return self.value.split('@')[1].lower()
    
    @property
    def local_part(self) -> str:
        """Extract local part from email"""
        return self.value.split('@')[0]
    
    @staticmethod
    def _is_valid_email(email: str) -> bool:
        """Basic email validation"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class CorrelationId:
    """Correlation ID for request tracing"""
    value: str
    
    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True)
class IpAddress:
    """IP address value object"""
    value: str
    
    def __post_init__(self):
        if not self._is_valid_ip(self.value):
            raise ValueError(f"Invalid IP address: {self.value}")
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Basic IP validation (IPv4 and IPv6)"""
        parts = ip.split('.')
        if len(parts) == 4:
            try:
                return all(0 <= int(part) <= 255 for part in parts)
            except ValueError:
                pass
        # Basic IPv6 check
        return ':' in ip
    
    def __str__(self) -> str:
        return self.value


@dataclass
class User:
    """User entity representing an authenticated user"""
    id: str
    email: EmailAddress
    name: Optional[str]
    password_hash: Optional[str]  # None if SSO-only
    account_type: AccountType
    mfa_enrolled: bool
    mfa_methods: List[MfaMethod]
    is_active: bool
    is_verified: bool
    is_locked: bool
    failed_login_attempts: int
    last_login_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    password_reset_required: bool = False
    
    def requires_mfa(self, org_context: Optional['OrganizationContext'] = None) -> bool:
        """Determine if MFA is required for this user"""
        if org_context and org_context.settings.mfa_required:
            return True
        return self.mfa_enrolled
    
    def can_authenticate(self) -> bool:
        """Check if user can attempt authentication"""
        return self.is_active and not self.is_locked


@dataclass
class Organization:
    """Organization entity for B2B context"""
    id: str
    name: str
    domain_mappings: List[str]  # Email domains mapped to this org
    sso_enabled: bool
    sso_enforced: bool
    sso_provider: Optional[SsoProvider]
    sso_config: Dict[str, Any]
    mfa_required: bool
    ip_whitelist: List[str]  # CIDR notation
    allow_password_auth: bool  # If False, SSO only
    session_timeout_seconds: int
    created_at: datetime
    updated_at: datetime
    is_active: bool = True
    
    def supports_password_login(self) -> bool:
        """Check if password login is allowed"""
        return self.allow_password_auth and not self.sso_enforced
    
    def requires_sso(self) -> bool:
        """Check if SSO is mandatory"""
        return self.sso_enforced
    
    def is_ip_allowed(self, ip: IpAddress) -> bool:
        """Check if IP is whitelisted"""
        if not self.ip_whitelist:
            return True
        # Simplified - production would use proper CIDR matching
        return any(ip.value.startswith(cidr.split('/')[0]) for cidr in self.ip_whitelist)


@dataclass
class OrganizationMembership:
    """User's membership in an organization"""
    user_id: str
    organization_id: str
    role: str
    permissions: List[str]
    is_active: bool
    joined_at: datetime
    
    
@dataclass
class MfaDevice:
    """MFA device enrollment"""
    id: str
    user_id: str
    method: MfaMethod
    is_verified: bool
    is_trusted: bool
    device_fingerprint: Optional[str]
    last_used_at: Optional[datetime]
    created_at: datetime

@dataclass
class LoginMetadata:
    """Enriched metadata from login request"""
    ip_address: Optional[IpAddress]
    device_fingerprint: Optional[str]
    user_agent: Optional[str]
    timezone: Optional[str]
    mfa_session_token: Optional[str]
    preferred_org_id: Optional[str]
    remember_device: bool = False
    
    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> 'LoginMetadata':
        """Create from dictionary (GraphQL input)"""
        if not data:
            return cls(
                ip_address=None,
                device_fingerprint=None,
                user_agent=None,
                timezone=None,
                mfa_session_token=None,
                preferred_org_id=None
            )
        
        ip = data.get('ipAddress')
        return cls(
            ip_address=IpAddress(ip) if ip else None,
            device_fingerprint=data.get('deviceFingerprint'),
            user_agent=data.get('userAgent'),
            timezone=data.get('timezone'),
            mfa_session_token=data.get('mfaSessionToken'),
            preferred_org_id=data.get('preferredOrgId'),
            remember_device=data.get('rememberDevice', False)
        )


@dataclass
class AuthenticationContext:
    """Complete authentication context after inference"""
    user: Optional[User]
    organizations: List[Organization]
    memberships: List[OrganizationMembership]
    account_type: AccountType
    requires_sso: bool
    requires_mfa: bool
    requires_org_selection: bool
    ip_allowed: bool
    correlation_id: CorrelationId
    metadata: LoginMetadata
    
    @property
    def is_multi_org(self) -> bool:
        """Check if user belongs to multiple organizations"""
        return len(self.organizations) > 1
    
    @property
    def primary_organization(self) -> Optional[Organization]:
        """Get primary organization (for single-org users)"""
        if len(self.organizations) == 1:
            return self.organizations[0]
        # Check for preferred org from metadata
        if self.metadata.preferred_org_id:
            for org in self.organizations:
                if org.id == self.metadata.preferred_org_id:
                    return org
        return None


@dataclass
class OrganizationContext:
    """Organization context for authenticated session"""
    organization: Organization
    membership: OrganizationMembership
    
    @property
    def settings(self) -> 'OrganizationSettings':
        """Get organization settings for response"""
        return OrganizationSettings(
            sso_enforced=self.organization.sso_enforced,
            mfa_required=self.organization.mfa_required,
            ip_whitelist=self.organization.ip_whitelist,
            session_timeout=self.organization.session_timeout_seconds
        )


@dataclass
class OrganizationSettings:
    """Organization settings DTO"""
    sso_enforced: bool
    mfa_required: bool
    ip_whitelist: List[str]
    session_timeout: int

@dataclass
class Session:
    """Authenticated session"""
    session_id: str
    user_id: str
    organization_id: Optional[str]
    authentication_method: AuthenticationMethod
    ip_address: Optional[IpAddress]
    device_fingerprint: Optional[str]
    created_at: datetime
    expires_at: datetime
    last_activity_at: datetime
    
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return datetime.utcnow() > self.expires_at


@dataclass
class ChallengeSession:
    """Challenge session for multi-step authentication"""
    challenge_token: str
    user_id: str
    challenge_type: ChallengeType
    challenge_data: Dict[str, Any]
    password_validated: bool
    organization_id: Optional[str]
    created_at: datetime
    expires_at: datetime
    
    def is_expired(self) -> bool:
        """Check if challenge is expired"""
        return datetime.utcnow() > self.expires_at

@dataclass
class RateLimitInfo:
    """Rate limit tracking"""
    key: str
    attempts: int
    window_start: datetime
    locked_until: Optional[datetime] = None
    
    def is_locked(self) -> bool:
        """Check if rate limit is active"""
        if not self.locked_until:
            return False
        return datetime.utcnow() < self.locked_until
    
    def seconds_until_unlock(self) -> int:
        """Get seconds until rate limit expires"""
        if not self.locked_until:
            return 0
        delta = self.locked_until - datetime.utcnow()
        return max(0, int(delta.total_seconds()))
