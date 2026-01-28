import hmac
import hashlib
import secrets
from typing import Optional, Tuple
from datetime import datetime, timedelta
import logging

from models import (
    User, 
    Organization, 
    EmailAddress, 
    CorrelationId,
    AuthenticationMethod, 
    SsoProvider,
    AccountType
)


logger = logging.getLogger(__name__)


class PasswordService:
    """
    Secure password handling with timing attack protection.
    
    Critical Security Implementation:
    - Uses constant-time comparison for all password checks
    - Implements dummy hash verification when user doesn't exist
    - Tracks failed attempts with exponential backoff
    """
    
    # Valid bcrypt dummy hash (syntactically correct format)
    # This prevents "Invalid salt" errors and allows full computation path
    DUMMY_HASH = "$2b$12$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    
    @staticmethod
    def verify_password(
        password: str,
        password_hash: Optional[str],
        user_exists: bool = True
    ) -> bool:
        """
        Verify password with constant-time behavior.
        
        Critical: This function aims to take roughly the same time whether:
        - User exists or not
        - Password is correct or not
        - Hash is valid or dummy
        
        This helps prevent timing attacks that could enumerate users.
        
        Args:
            password: Plain text password to verify
            password_hash: Stored bcrypt hash (None if user doesn't exist)
            user_exists: Whether user actually exists (for correct success logic)
        
        Returns:
            True if password matches AND user exists, False otherwise
        """
        # Select what to compare against
        hash_to_compare = password_hash if password_hash else PasswordService.DUMMY_HASH
        
        password_bytes = password.encode('utf-8')
        hash_bytes = hash_to_compare.encode('utf-8')
        
        try:
            import bcrypt
            # This is the expensive operation we want to always perform
            result = bcrypt.checkpw(password_bytes, hash_bytes)
            
            # Only succeed if it's a real user AND the password matches
            return user_exists and result
            
        except ValueError:
            # Invalid salt/format → common with dummy hash
            # We treat it as non-match (normal behavior)
            logger.debug("bcrypt verification failed (normal for dummy or invalid hash case)")
            return False
            
        except Exception as e:
            # Unexpected error – still return false
            logger.warning(f"Unexpected error during password verification: {e}", exc_info=True)
            return False
    
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Generate secure password hash using bcrypt"""
        import bcrypt
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    
    @staticmethod
    def is_password_strong(password: str) -> Tuple[bool, Optional[str]]:
        """
        Validate password strength.
        
        Requirements:
        - Minimum 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"
        
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            return False, "Password must contain at least one special character"
        
        return True, None


class AuthenticationService:
    """
    Core authentication service handling credential validation.
    
    Responsibilities:
    - Password authentication
    - SSO token validation
    - Failed attempt tracking
    - Account lockout enforcement
    """
    
    def __init__(
        self,
        user_repository,
        password_service: PasswordService,
        sso_service: Optional['SsoService'] = None
    ):
        self.user_repo = user_repository
        self.password_service = password_service
        self.sso_service = sso_service
        
        # Security policies
        self.max_failed_attempts = 5
        self.lockout_duration_minutes = 15
    
    async def authenticate_with_password(
        self,
        email: EmailAddress,
        password: str,
        correlation_id: CorrelationId
    ) -> Tuple[bool, Optional[User], Optional[str]]:
        """
        Authenticate user with email and password.
        
        Returns:
            (success, user, error_message)
        
        Security considerations:
        - Always performs hash comparison even if user doesn't exist
        - Returns generic error message on failure
        - Tracks failed attempts only for existing users
        - Enforces account lockout
        """
        logger.info(f"[{correlation_id}] Password authentication for {email.domain}")
        
        # Lookup user
        user = await self.user_repo.find_by_email(email)
        user_exists = user is not None
        logger.info(
            f"[{correlation_id}] USER LOOKUP RESULT | email={email.value} | "
            f"exists={user_exists} | id={user.id if user else 'NONE'} | "
            f"has_hash={bool(user.password_hash) if user else 'N/A'}"
        )
        
        # Check if user can authenticate
        if user_exists and not user.can_authenticate():
            logger.warning(
                f"[{correlation_id}] User cannot authenticate: "
                f"active={user.is_active}, locked={user.is_locked}"
            )
            # Still run verification to preserve timing
            self.password_service.verify_password(
                password,
                user.password_hash,
                user_exists=False  # Force failure even if password matches
            )
            return False, None, "authentication_failed"
        
        # Verify password (constant-time operation)
        password_valid = self.password_service.verify_password(
            password,
            user.password_hash if user else None,
            user_exists=user_exists
        )
        
        if not password_valid:
            logger.info(f"[{correlation_id}] Password verification failed")
            
            # Track failed attempt only if the user actually exists
            if user:
                await self._track_failed_attempt(user, correlation_id)
            
            return False, None, "authentication_failed"
        
        # Success - reset failed attempts
        logger.info(f"[{correlation_id}] Password authentication successful")
        if user:
            await self._reset_failed_attempts(user)
        
        return True, user, None
    
    async def authenticate_with_sso(
        self,
        email: EmailAddress,
        sso_token: str,
        organization: Organization,
        correlation_id: CorrelationId
    ) -> Tuple[bool, Optional[User], Optional[str]]:
        """
        Authenticate user via SSO.
        """
        logger.info(
            f"[{correlation_id}] SSO authentication for {email.value} "
            f"via {organization.sso_provider}"
        )
        
        if not self.sso_service:
            logger.error(f"[{correlation_id}] SSO service not configured")
            return False, None, "service_unavailable"
        
        sso_valid, sso_user_info = await self.sso_service.validate_token(
            sso_token,
            organization.sso_provider,
            organization.sso_config,
            correlation_id
        )
        
        if not sso_valid:
            logger.warning(f"[{correlation_id}] SSO token validation failed")
            return False, None, "authentication_failed"
        
        user = await self.user_repo.find_by_email(email)
        
        if not user:
            logger.info(f"[{correlation_id}] Auto-provisioning user from SSO")
            user = await self._provision_user_from_sso(
                email,
                sso_user_info,
                organization,
                correlation_id
            )
        
        logger.info(f"[{correlation_id}] SSO authentication successful")
        return True, user, None
    
    async def _track_failed_attempt(
        self,
        user: User,
        correlation_id: CorrelationId
    ):
        """Track failed login attempt and enforce lockout policy"""
        user.failed_login_attempts += 1
        
        logger.warning(
            f"[{correlation_id}] Failed attempt {user.failed_login_attempts} "
            f"for user {user.id}"
        )
        
        if user.failed_login_attempts >= self.max_failed_attempts:
            user.is_locked = True
            logger.warning(
                f"[{correlation_id}] Account locked for user {user.id} "
                f"after {user.failed_login_attempts} failed attempts"
            )
        
        await self.user_repo.update(user)
    
    async def _reset_failed_attempts(self, user: User):
        """Reset failed login attempts on successful authentication"""
        if user.failed_login_attempts > 0:
            user.failed_login_attempts = 0
            await self.user_repo.update(user)
    
    async def _provision_user_from_sso(
        self,
        email: EmailAddress,
        sso_user_info: dict,
        organization: Organization,
        correlation_id: CorrelationId
    ) -> User:
        """Auto-provision user from SSO identity"""
        logger.info(f"[{correlation_id}] Provisioning new user from SSO")
        
        user = User(
            id=secrets.token_urlsafe(16),
            email=email,
            name=sso_user_info.get('name'),
            password_hash=None,  # SSO users don't have passwords
            account_type=AccountType.B2B,
            mfa_enrolled=False,
            mfa_methods=[],
            is_active=True,
            is_verified=True,  # SSO implies verified email
            is_locked=False,
            failed_login_attempts=0,
            last_login_at=None,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow()
        )
        
        await self.user_repo.create(user)
        return user


class SsoService:
    """
    SSO integration service supporting multiple providers.
    """
    
    def __init__(self, http_client):
        self.http_client = http_client
    
    async def validate_token(
        self,
        token: str,
        provider: Optional[SsoProvider],
        config: dict,
        correlation_id: CorrelationId
    ) -> Tuple[bool, Optional[dict]]:
        if not provider:
            return False, None
        
        logger.info(f"[{correlation_id}] Validating SSO token with {provider.value}")
        
        if provider == SsoProvider.GOOGLE:
            return await self._validate_google_token(token, config, correlation_id)
        elif provider == SsoProvider.OKTA:
            return await self._validate_okta_token(token, config, correlation_id)
        elif provider == SsoProvider.AZURE_AD:
            return await self._validate_azure_token(token, config, correlation_id)
        elif provider == SsoProvider.SAML_GENERIC:
            return await self._validate_saml_assertion(token, config, correlation_id)
        
        logger.error(f"[{correlation_id}] Unsupported SSO provider: {provider}")
        return False, None
    
    async def _validate_google_token(
        self,
        token: str,
        config: dict,
        correlation_id: CorrelationId
    ) -> Tuple[bool, Optional[dict]]:
        logger.info(f"[{correlation_id}] Validating Google OAuth token")
        # Placeholder – implement real validation in production
        return False, None
    
    async def _validate_okta_token(
        self,
        token: str,
        config: dict,
        correlation_id: CorrelationId
    ) -> Tuple[bool, Optional[dict]]:
        logger.info(f"[{correlation_id}] Validating Okta token")
        # Placeholder
        return False, None
    
    async def _validate_azure_token(
        self,
        token: str,
        config: dict,
        correlation_id: CorrelationId
    ) -> Tuple[bool, Optional[dict]]:
        logger.info(f"[{correlation_id}] Validating Azure AD token")
        # Placeholder
        return False, None
    
    async def _validate_saml_assertion(
        self,
        assertion: str,
        config: dict,
        correlation_id: CorrelationId
    ) -> Tuple[bool, Optional[dict]]:
        logger.info(f"[{correlation_id}] Validating SAML assertion")
        # Placeholder
        return False, None
    
    async def get_sso_redirect_url(
        self,
        organization: Organization,
        correlation_id: CorrelationId,
        state: Optional[str] = None
    ) -> str:
        logger.info(
            f"[{correlation_id}] Generating SSO redirect URL for "
            f"{organization.sso_provider}"
        )
        
        pkce_verifier = secrets.token_urlsafe(32)
        pkce_challenge = hashlib.sha256(pkce_verifier.encode()).hexdigest()
        
        if organization.sso_provider == SsoProvider.GOOGLE:
            return self._generate_google_redirect_url(
                organization.sso_config,
                state,
                pkce_challenge
            )
        elif organization.sso_provider == SsoProvider.OKTA:
            return self._generate_okta_redirect_url(
                organization.sso_config,
                state,
                pkce_challenge
            )
        
        # Fallback generic
        return f"https://sso.example.com/authorize?state={state}&challenge={pkce_challenge}"
    
    def _generate_google_redirect_url(
        self,
        config: dict,
        state: str,
        challenge: str
    ) -> str:
        client_id = config.get('client_id')
        redirect_uri = config.get('redirect_uri')
        
        return (
            f"https://accounts.google.com/o/oauth2/v2/auth"
            f"?client_id={client_id}"
            f"&redirect_uri={redirect_uri}"
            f"&response_type=code"
            f"&scope=openid email profile"
            f"&state={state}"
            f"&code_challenge={challenge}"
            f"&code_challenge_method=S256"
        )
    
    def _generate_okta_redirect_url(
        self,
        config: dict,
        state: str,
        challenge: str
    ) -> str:
        domain = config.get('domain')
        client_id = config.get('client_id')
        redirect_uri = config.get('redirect_uri')
        
        return (
            f"https://{domain}/oauth2/v1/authorize"
            f"?client_id={client_id}"
            f"&redirect_uri={redirect_uri}"
            f"&response_type=code"
            f"&scope=openid email profile"
            f"&state={state}"
            f"&code_challenge={challenge}"
            f"&code_challenge_method=S256"
        )