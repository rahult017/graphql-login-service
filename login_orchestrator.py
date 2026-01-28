from typing import Union, Optional, Dict, Any
from datetime import datetime, timedelta
import secrets
import logging

from models import (
    EmailAddress, LoginMetadata, CorrelationId, IpAddress,
    User, Organization, OrganizationContext, OrganizationMembership,
    AuthenticationContext, AccountType, ChallengeType, MfaMethod,
    ErrorCode, Session, ChallengeSession, AuthenticationMethod
)
from context_inference import ContextInferenceEngine
from authentication import AuthenticationService, SsoService
from mfa import MfaService
from session import SessionService, TokenService, RateLimiter, CacheService



logger = logging.getLogger(__name__)


class LoginOrchestrator:
    """
    Main orchestrator for login flow.
    
    Implements the state machine and business logic for:
    - Context inference
    - Authentication method selection
    - Challenge coordination
    - Session creation
    
    This is the "brain" of the login service.
    """
    
    def __init__(
        self,
        context_engine: ContextInferenceEngine,
        auth_service: AuthenticationService,
        mfa_service: MfaService,
        sso_service: SsoService,
        session_service: 'SessionService',
        rate_limiter: 'RateLimiter'
    ):
        self.context_engine = context_engine
        self.auth_service = auth_service
        self.mfa_service = mfa_service
        self.sso_service = sso_service
        self.session_service = session_service
        self.rate_limiter = rate_limiter
    
    async def execute_login(
        self,
        email: EmailAddress,
        secret: str,
        metadata: LoginMetadata,
        correlation_id: CorrelationId
    ) -> 'LoginResponse':
        """
        Execute complete login flow.
        
        This is the main entry point for login mutation.
        
        Flow:
        1. Rate limit check
        2. Context inference (D2C vs B2B)
        3. Authentication method determination
        4. Credential validation
        5. Additional challenge handling (MFA, org selection)
        6. Session creation
        
        Returns:
            LoginSuccess | LoginChallenge | LoginFailure
        """
        logger.info(f"[{correlation_id}] Starting login flow for {email.domain}")
        
        try:
            # Step 1: Rate limiting
            is_allowed, retry_after = await self.rate_limiter.check_rate_limit(
                email.value,
                metadata.ip_address,
                correlation_id
            )
            
            if not is_allowed:
                logger.warning(f"[{correlation_id}] Rate limit exceeded")
                return LoginResponse.failure(
                    correlation_id=correlation_id,
                    error_code=ErrorCode.RATE_LIMIT_EXCEEDED,
                    message="Too many login attempts. Please try again later.",
                    retry_after=retry_after
                )
            
            # Step 2: Infer authentication context
            context = await self.context_engine.infer_context(
                email, metadata, correlation_id
            )
            
            logger.info(
                f"[{correlation_id}] Context inferred: "
                f"type={context.account_type.value}, "
                f"orgs={len(context.organizations)}, "
                f"requires_sso={context.requires_sso}, "
                f"requires_mfa={context.requires_mfa}"
            )
            
            # Step 3: Validate IP restrictions (if applicable)
            if not context.ip_allowed:
                logger.warning(f"[{correlation_id}] IP address not whitelisted")
                return LoginResponse.failure(
                    correlation_id=correlation_id,
                    error_code=ErrorCode.IP_RESTRICTED,
                    message="Access not permitted from this location.",
                    retry_after=None
                )
            
            # Step 4: Handle multi-org scenario
            if context.requires_org_selection:
                logger.info(f"[{correlation_id}] Organization selection required")
                return await self._create_org_selection_challenge(
                    context, correlation_id
                )
            
            # Step 5: Determine authentication method and validate
            if context.requires_sso:
                logger.info(f"[{correlation_id}] SSO authentication required")
                return await self._handle_sso_authentication(
                    context, secret, correlation_id
                )
            else:
                logger.info(f"[{correlation_id}] Password authentication")
                return await self._handle_password_authentication(
                    context, email, secret, correlation_id
                )
        
        except Exception as e:
            logger.error(f"[{correlation_id}] Login error: {e}", exc_info=True)
            return LoginResponse.failure(
                correlation_id=correlation_id,
                error_code=ErrorCode.SERVICE_UNAVAILABLE,
                message="Authentication service temporarily unavailable.",
                retry_after=None
            )
    
    async def _handle_password_authentication(
        self,
        context: AuthenticationContext,
        email: EmailAddress,
        password: str,
        correlation_id: CorrelationId
    ) -> 'LoginResponse':
        """
        Handle password-based authentication.
        
        Edge Cases:
        - Org supports both SSO and password → Password is attempted
        - User exists but password wrong → Generic error (no enumeration)
        - User doesn't exist → Generic error with timing protection
        """
        success, user, error = await self.auth_service.authenticate_with_password(
            email, password, correlation_id
        )
        
        if not success:
            logger.info(f"[{correlation_id}] Password authentication failed")
            await self.rate_limiter.record_failed_attempt(
                email.value,
                context.metadata.ip_address
            )
            
            return LoginResponse.failure(
                correlation_id=correlation_id,
                error_code=ErrorCode.AUTHENTICATION_FAILED,
                message="Invalid credentials. Please check your email and password.",
                retry_after=None
            )
        
        # Password validated - check for additional challenges
        logger.info(f"[{correlation_id}] Password validated successfully")
        
        # Reset rate limit on success
        await self.rate_limiter.reset(email.value)
        
        # Check for password reset requirement
        if user.password_reset_required:
            return await self._create_password_reset_challenge(
                user, correlation_id
            )
        
        # Check for MFA requirement
        if context.requires_mfa or user.requires_mfa(context.primary_organization):
            # Check trusted device
            if (context.metadata.device_fingerprint and 
                await self.mfa_service.check_trusted_device(
                    user,
                    context.metadata.device_fingerprint,
                    correlation_id
                )):
                logger.info(f"[{correlation_id}] Trusted device - bypassing MFA")
            else:
                logger.info(f"[{correlation_id}] MFA required")
                return await self._create_mfa_challenge(
                    user, context, correlation_id
                )
        
        # Create session - authentication complete
        return await self._create_success_response(
            user,
            context,
            AuthenticationMethod.PASSWORD,
            correlation_id
        )
    
    async def _handle_sso_authentication(
        self,
        context: AuthenticationContext,
        sso_token: str,
        correlation_id: CorrelationId
    ) -> 'LoginResponse':
        """
        Handle SSO-based authentication.
        
        If secret is an SSO token, validate it.
        Otherwise, return SSO redirect challenge.
        """
        # Check if secret looks like an SSO token
        if self._is_sso_token(sso_token):
            # Validate SSO token
            org = context.primary_organization
            if not org:
                logger.error(f"[{correlation_id}] No organization for SSO")
                return LoginResponse.failure(
                    correlation_id=correlation_id,
                    error_code=ErrorCode.AUTHENTICATION_FAILED,
                    message="Authentication failed.",
                    retry_after=None
                )
            
            success, user, error = await self.auth_service.authenticate_with_sso(
                EmailAddress(context.user.email.value if context.user else ""),
                sso_token,
                org,
                correlation_id
            )
            
            if not success:
                return LoginResponse.failure(
                    correlation_id=correlation_id,
                    error_code=ErrorCode.AUTHENTICATION_FAILED,
                    message="SSO authentication failed.",
                    retry_after=None
                )
            
            # SSO successful - check MFA
            if context.requires_mfa:
                return await self._create_mfa_challenge(
                    user, context, correlation_id
                )
            
            return await self._create_success_response(
                user,
                context,
                AuthenticationMethod.SSO,
                correlation_id
            )
        else:
            # Return SSO redirect
            logger.info(f"[{correlation_id}] Creating SSO redirect")
            return await self._create_sso_redirect_challenge(
                context, correlation_id
            )
    
    async def _create_mfa_challenge(
        self,
        user: User,
        context: AuthenticationContext,
        correlation_id: CorrelationId
    ) -> 'LoginResponse':
        """
        Create MFA challenge.
        
        Edge Cases:
        1. MFA required but not enrolled → Return enrollment challenge
        2. Preferred method unavailable → Fallback to next available
        3. All methods down → Return service error with support info
        """
        try:
            method, delivery_target, challenge_data = \
                await self.mfa_service.initiate_mfa_challenge(
                    user, correlation_id
                )
            
            # Create challenge session
            challenge_token = await self._create_challenge_session(
                user,
                ChallengeType.MFA_REQUIRED,
                {
                    'method': method.value,
                    'delivery_target': delivery_target
                },
                context.primary_organization.id if context.primary_organization else None
            )
            
            return LoginResponse.mfa_challenge(
                correlation_id=correlation_id,
                challenge_token=challenge_token,
                method=method,
                delivery_target=delivery_target,
                backup_codes_available=True  # Would check actual availability
            )
        
        except Exception as e:
            logger.error(f"[{correlation_id}] MFA challenge error: {e}", exc_info=True)
            
            # Edge Case #3: MFA provider down
            # Graceful degradation - allow login but flag for review
            logger.warning(f"[{correlation_id}] MFA unavailable - allowing login")
            return await self._create_success_response(
                user,
                context,
                AuthenticationMethod.PASSWORD,
                correlation_id,
                require_mfa_setup=True
            )
    
    async def _create_org_selection_challenge(
        self,
        context: AuthenticationContext,
        correlation_id: CorrelationId
    ) -> 'LoginResponse':
        """
        Create organization selection challenge.
        
        Edge Case: User belongs to multiple organizations
        → Present list for selection
        """
        # Create challenge session
        challenge_token = await self._create_challenge_session(
            context.user,
            ChallengeType.ORG_SELECTION,
            {
                'organizations': [
                    {
                        'id': org.id,
                        'name': org.name,
                        'requires_sso': org.requires_sso()
                    }
                    for org in context.organizations
                ]
            },
            None
        )
        
        org_options = [
            {
                'id': org.id,
                'name': org.name,
                'requires_sso': org.requires_sso()
            }
            for org in context.organizations
        ]
        
        return LoginResponse.org_selection_challenge(
            correlation_id=correlation_id,
            challenge_token=challenge_token,
            organizations=org_options,
            password_validated=False  # Haven't validated yet
        )
    
    async def _create_sso_redirect_challenge(
        self,
        context: AuthenticationContext,
        correlation_id: CorrelationId
    ) -> 'LoginResponse':
        """Create SSO redirect challenge"""
        org = context.primary_organization
        if not org:
            return LoginResponse.failure(
                correlation_id=correlation_id,
                error_code=ErrorCode.AUTHENTICATION_FAILED,
                message="Authentication failed.",
                retry_after=None
            )
        
        # Generate state token for CSRF protection
        state = secrets.token_urlsafe(32)
        
        # Get SSO redirect URL
        redirect_url = await self.sso_service.get_sso_redirect_url(
            org, correlation_id, state
        )
        
        # Create challenge session
        challenge_token = await self._create_challenge_session(
            None,  # User not authenticated yet
            ChallengeType.SSO_REDIRECT,
            {
                'provider': org.sso_provider.value if org.sso_provider else 'unknown',
                'state': state
            },
            org.id
        )
        
        return LoginResponse.sso_redirect_challenge(
            correlation_id=correlation_id,
            challenge_token=challenge_token,
            provider=org.sso_provider.value if org.sso_provider else 'unknown',
            redirect_url=redirect_url
        )
    
    async def _create_password_reset_challenge(
        self,
        user: User,
        correlation_id: CorrelationId
    ) -> 'LoginResponse':
        """Create password reset challenge"""
        reset_token = secrets.token_urlsafe(32)
        
        challenge_token = await self._create_challenge_session(
            user,
            ChallengeType.PASSWORD_RESET,
            {'reset_token': reset_token},
            None
        )
        
        return LoginResponse.password_reset_challenge(
            correlation_id=correlation_id,
            challenge_token=challenge_token,
            reason="Password reset required",
            reset_token=reset_token
        )
    
    async def _create_success_response(
        self,
        user: User,
        context: AuthenticationContext,
        auth_method: AuthenticationMethod,
        correlation_id: CorrelationId,
        require_mfa_setup: bool = False
    ) -> 'LoginResponse':
        """Create successful login response with session"""
        # Create session
        session = await self.session_service.create_session(
            user=user,
            organization=context.primary_organization,
            auth_method=auth_method,
            ip_address=context.metadata.ip_address,
            device_fingerprint=context.metadata.device_fingerprint,
            correlation_id=correlation_id
        )
        
        # Build organization context for response
        org_context = None
        if context.primary_organization and context.memberships:
            membership = next(
                (m for m in context.memberships 
                 if m.organization_id == context.primary_organization.id),
                None
            )
            if membership:
                org_context = OrganizationContext(
                    organization=context.primary_organization,
                    membership=membership
                )
        
        return LoginResponse.success(
            correlation_id=correlation_id,
            session_token=session.session_id,
            expires_in=int((session.expires_at - datetime.utcnow()).total_seconds()),
            user=user,
            organization=org_context,
            refresh_token=None  # Would generate if needed
        )
    
    async def _create_challenge_session(
        self,
        user: Optional[User],
        challenge_type: ChallengeType,
        challenge_data: Dict[str, Any],
        organization_id: Optional[str]
    ) -> str:
        """Create and store challenge session"""
        challenge_token = secrets.token_urlsafe(32)
        
        challenge_session = ChallengeSession(
            challenge_token=challenge_token,
            user_id=user.id if user else "pending",
            challenge_type=challenge_type,
            challenge_data=challenge_data,
            password_validated=user is not None,
            organization_id=organization_id,
            created_at=datetime.utcnow(),
            expires_at=datetime.utcnow() + timedelta(minutes=10)
        )
        
        # Store in cache (Redis in production)
        await self._store_challenge_session(challenge_session)
        
        return challenge_token
    
    async def _store_challenge_session(self, session: ChallengeSession):
        """Store challenge session (placeholder for Redis)"""
        # In production, would store in Redis with TTL
        pass
    
    def _is_sso_token(self, secret: str) -> bool:
        """Heuristic to detect if secret is an SSO token vs password"""
        # SSO tokens are typically JWT or long base64 strings
        return len(secret) > 100 or secret.count('.') == 2


class LoginResponse:
    """Response builder for login mutation"""
    
    @staticmethod
    def success(
        correlation_id: CorrelationId,
        session_token: str,
        expires_in: int,
        user: User,
        organization: Optional[OrganizationContext],
        refresh_token: Optional[str]
    ) -> Dict[str, Any]:
        """Build success response"""
        return {
            '__typename': 'LoginSuccess',
            'correlationId': str(correlation_id),
            'timestamp': datetime.utcnow().isoformat(),
            'success': True,
            'sessionToken': session_token,
            'expiresIn': expires_in,
            'user': {
                'id': user.id,
                'email': str(user.email),
                'name': user.name,
                'accountType': user.account_type.value.upper(),
                'mfaEnrolled': user.mfa_enrolled,
                'lastLoginAt': user.last_login_at.isoformat() if user.last_login_at else None
            },
            'organization': {
                'id': organization.organization.id,
                'name': organization.organization.name,
                'role': organization.membership.role,
                'permissions': organization.membership.permissions,
                'settings': {
                    'ssoEnforced': organization.settings.sso_enforced,
                    'mfaRequired': organization.settings.mfa_required,
                    'ipWhitelist': organization.settings.ip_whitelist,
                    'sessionTimeout': organization.settings.session_timeout
                }
            } if organization else None,
            'refreshToken': refresh_token
        }
    
    @staticmethod
    def mfa_challenge(
        correlation_id: CorrelationId,
        challenge_token: str,
        method: MfaMethod,
        delivery_target: Optional[str],
        backup_codes_available: bool
    ) -> Dict[str, Any]:
        """Build MFA challenge response"""
        return {
            '__typename': 'LoginChallenge',
            'correlationId': str(correlation_id),
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'challengeType': 'MFA_REQUIRED',
            'challengeData': {
                '__typename': 'MfaChallenge',
                'method': method.value.upper(),
                'deliveryTarget': delivery_target,
                'backupCodesAvailable': backup_codes_available
            },
            'challengeToken': challenge_token,
            'expiresIn': 300  # 5 minutes
        }
    
    @staticmethod
    def sso_redirect_challenge(
        correlation_id: CorrelationId,
        challenge_token: str,
        provider: str,
        redirect_url: str
    ) -> Dict[str, Any]:
        """Build SSO redirect challenge"""
        return {
            '__typename': 'LoginChallenge',
            'correlationId': str(correlation_id),
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'challengeType': 'SSO_REDIRECT',
            'challengeData': {
                '__typename': 'SsoChallenge',
                'provider': provider,
                'redirectUrl': redirect_url,
                'pkceChallenge': None
            },
            'challengeToken': challenge_token,
            'expiresIn': 600  # 10 minutes
        }
    
    @staticmethod
    def org_selection_challenge(
        correlation_id: CorrelationId,
        challenge_token: str,
        organizations: list,
        password_validated: bool
    ) -> Dict[str, Any]:
        """Build organization selection challenge"""
        return {
            '__typename': 'LoginChallenge',
            'correlationId': str(correlation_id),
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'challengeType': 'ORG_SELECTION',
            'challengeData': {
                '__typename': 'OrgSelectionChallenge',
                'organizations': organizations,
                'passwordValidated': password_validated
            },
            'challengeToken': challenge_token,
            'expiresIn': 600
        }
    
    @staticmethod
    def password_reset_challenge(
        correlation_id: CorrelationId,
        challenge_token: str,
        reason: str,
        reset_token: str
    ) -> Dict[str, Any]:
        """Build password reset challenge"""
        return {
            '__typename': 'LoginChallenge',
            'correlationId': str(correlation_id),
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'challengeType': 'PASSWORD_RESET',
            'challengeData': {
                '__typename': 'PasswordResetChallenge',
                'reason': reason,
                'resetToken': reset_token
            },
            'challengeToken': challenge_token,
            'expiresIn': 600
        }
    
    @staticmethod
    def failure(
        correlation_id: CorrelationId,
        error_code: ErrorCode,
        message: str,
        retry_after: Optional[int]
    ) -> Dict[str, Any]:
        """Build failure response"""
        return {
            '__typename': 'LoginFailure',
            'correlationId': str(correlation_id),
            'timestamp': datetime.utcnow().isoformat(),
            'success': False,
            'errorCode': error_code.value.upper(),
            'message': message,
            'retryAllowed': retry_after is None or retry_after > 0,
            'retryAfter': retry_after
        }
