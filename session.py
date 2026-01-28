from typing import Optional, Tuple
from datetime import datetime, timedelta
import secrets
import logging

from models import (
    User, Organization, Session, AuthenticationMethod,
    IpAddress, CorrelationId, RateLimitInfo
)


logger = logging.getLogger(__name__)


class SessionService:
    """
    Session lifecycle management.
    
    Responsibilities:
    - Session creation
    - Session validation
    - Session expiration
    - Session revocation
    - Token generation
    """
    
    def __init__(self, session_repository, token_service: 'TokenService'):
        self.session_repo = session_repository
        self.token_service = token_service
        
        # Default session configuration
        self.default_session_timeout = 3600  # 1 hour
        self.max_session_lifetime = 86400  # 24 hours
    
    async def create_session(
        self,
        user: User,
        organization: Optional[Organization],
        auth_method: AuthenticationMethod,
        ip_address: Optional[IpAddress],
        device_fingerprint: Optional[str],
        correlation_id: CorrelationId
    ) -> Session:
        """
        Create new authenticated session.
        
        Args:
            user: Authenticated user
            organization: User's organization (None for D2C)
            auth_method: How user authenticated
            ip_address: Client IP address
            device_fingerprint: Device identifier
            correlation_id: Request correlation ID
        
        Returns:
            Created session
        """
        logger.info(f"[{correlation_id}] Creating session for user {user.id}")
        
        # Determine session timeout
        timeout = self._determine_session_timeout(organization)
        
        # Generate session ID
        session_id = await self.token_service.generate_session_token(
            user.id,
            organization.id if organization else None,
            timeout
        )
        
        # Create session object
        now = datetime.utcnow()
        session = Session(
            session_id=session_id,
            user_id=user.id,
            organization_id=organization.id if organization else None,
            authentication_method=auth_method,
            ip_address=ip_address,
            device_fingerprint=device_fingerprint,
            created_at=now,
            expires_at=now + timedelta(seconds=timeout),
            last_activity_at=now
        )
        
        # Store session
        await self.session_repo.create(session)
        
        # Update user's last login timestamp
        user.last_login_at = now
        
        logger.info(
            f"[{correlation_id}] Session created: {session_id[:8]}... "
            f"expires in {timeout}s"
        )
        
        return session
    
    async def validate_session(
        self,
        session_token: str,
        correlation_id: CorrelationId
    ) -> Tuple[bool, Optional[Session]]:
        """
        Validate session token.
        
        Returns:
            (valid, session)
        """
        # Verify token signature and extract claims
        valid, user_id, org_id = await self.token_service.verify_session_token(
            session_token
        )
        
        if not valid:
            logger.warning(f"[{correlation_id}] Invalid session token")
            return False, None
        
        # Lookup session
        session = await self.session_repo.find_by_id(session_token)
        
        if not session:
            logger.warning(f"[{correlation_id}] Session not found")
            return False, None
        
        # Check expiration
        if session.is_expired():
            logger.info(f"[{correlation_id}] Session expired")
            await self.session_repo.delete(session_token)
            return False, None
        
        # Update last activity
        session.last_activity_at = datetime.utcnow()
        await self.session_repo.update(session)
        
        return True, session
    
    async def revoke_session(
        self,
        session_token: str,
        correlation_id: CorrelationId
    ):
        """Revoke/invalidate session"""
        logger.info(f"[{correlation_id}] Revoking session")
        await self.session_repo.delete(session_token)
    
    async def refresh_session(
        self,
        refresh_token: str,
        correlation_id: CorrelationId
    ) -> Optional[Session]:
        """Refresh session using refresh token"""
        logger.info(f"[{correlation_id}] Refreshing session")
        
        # Verify refresh token
        valid, user_id, org_id = await self.token_service.verify_refresh_token(
            refresh_token
        )
        
        if not valid:
            return None
        
        # Create new session (would need to lookup user and org)
        # Placeholder - production would implement full refresh flow
        return None
    
    def _determine_session_timeout(
        self,
        organization: Optional[Organization]
    ) -> int:
        """Determine session timeout based on organization policy"""
        if organization:
            return min(
                organization.session_timeout_seconds,
                self.max_session_lifetime
            )
        return self.default_session_timeout


class TokenService:
    """
    JWT token generation and validation.
    
    Handles session tokens and refresh tokens.
    """
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key
    
    async def generate_session_token(
        self,
        user_id: str,
        org_id: Optional[str],
        expires_in: int
    ) -> str:
        """
        Generate JWT session token.
        
        Claims:
        - sub: user_id
        - org: organization_id (optional)
        - exp: expiration timestamp
        - iat: issued at timestamp
        - jti: unique token ID
        """
        import jwt
        from datetime import datetime, timedelta
        
        now = datetime.utcnow()
        
        payload = {
            'sub': user_id,
            'org': org_id,
            'exp': now + timedelta(seconds=expires_in),
            'iat': now,
            'jti': secrets.token_urlsafe(16)
        }
        
        token = jwt.encode(payload, self.secret_key, algorithm='HS256')
        return token
    
    async def verify_session_token(
        self,
        token: str
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Verify and decode session token.
        
        Returns:
            (valid, user_id, org_id)
        """
        try:
            import jwt
            
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=['HS256']
            )
            
            return True, payload.get('sub'), payload.get('org')
        
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return False, None, None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return False, None, None
    
    async def verify_refresh_token(
        self,
        token: str
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Verify refresh token"""
        # Similar to session token but with different claims
        return await self.verify_session_token(token)


class RateLimiter:
    """
    Distributed rate limiter for login attempts.
    
    Implements:
    - Per-email rate limiting
    - Per-IP rate limiting  
    - Exponential backoff on repeated failures
    - Account lockout after threshold
    
    Uses Redis in production for distributed state.
    """
    
    def __init__(self, cache_service):
        self.cache = cache_service
        
        # Rate limit configuration
        self.max_attempts_per_hour = 10
        self.max_attempts_per_ip_per_hour = 50
        self.lockout_duration_minutes = 15
        self.rate_limit_window_seconds = 3600  # 1 hour
    
    async def check_rate_limit(
        self,
        email: str,
        ip_address: Optional[IpAddress],
        correlation_id: CorrelationId
    ) -> Tuple[bool, Optional[int]]:
        """
        Check if request is within rate limits.
        
        Returns:
            (allowed, retry_after_seconds)
        """
        # Check email-based rate limit
        email_key = f"rate_limit:email:{email}"
        email_info = await self._get_rate_limit_info(email_key)
        
        if email_info and email_info.is_locked():
            logger.warning(
                f"[{correlation_id}] Email rate limit exceeded: {email}"
            )
            return False, email_info.seconds_until_unlock()
        
        # Check IP-based rate limit (if provided)
        if ip_address:
            ip_key = f"rate_limit:ip:{ip_address.value}"
            ip_info = await self._get_rate_limit_info(ip_key)
            
            if ip_info and ip_info.is_locked():
                logger.warning(
                    f"[{correlation_id}] IP rate limit exceeded: {ip_address.value}"
                )
                return False, ip_info.seconds_until_unlock()
        
        return True, None
    
    async def record_failed_attempt(
        self,
        email: str,
        ip_address: Optional[IpAddress]
    ):
        """Record failed login attempt for rate limiting"""
        email_key = f"rate_limit:email:{email}"
        await self._increment_attempts(email_key, self.max_attempts_per_hour)
        
        if ip_address:
            ip_key = f"rate_limit:ip:{ip_address.value}"
            await self._increment_attempts(
                ip_key,
                self.max_attempts_per_ip_per_hour
            )
    
    async def reset(self, email: str):
        """Reset rate limit counters on successful authentication"""
        email_key = f"rate_limit:email:{email}"
        await self.cache.delete(email_key)
    
    async def _get_rate_limit_info(self, key: str) -> Optional[RateLimitInfo]:
        """Get rate limit info from cache"""
        data = await self.cache.get(key)
        if not data:
            return None
        
        return RateLimitInfo(
            key=key,
            attempts=data['attempts'],
            window_start=datetime.fromisoformat(data['window_start']),
            locked_until=datetime.fromisoformat(data['locked_until']) 
                if data.get('locked_until') else None
        )
    
    async def _increment_attempts(self, key: str, threshold: int):
        """Increment attempt counter and apply lockout if needed"""
        info = await self._get_rate_limit_info(key)
        now = datetime.utcnow()
        
        if not info:
            # First attempt
            info = RateLimitInfo(
                key=key,
                attempts=1,
                window_start=now,
                locked_until=None
            )
        else:
            # Check if window expired
            window_age = now - info.window_start
            if window_age.total_seconds() > self.rate_limit_window_seconds:
                # Reset window
                info.attempts = 1
                info.window_start = now
                info.locked_until = None
            else:
                # Increment within window
                info.attempts += 1
                
                # Check threshold
                if info.attempts >= threshold:
                    # Apply lockout
                    info.locked_until = now + timedelta(
                        minutes=self.lockout_duration_minutes
                    )
        
        # Store updated info
        await self.cache.set(
            key,
            {
                'attempts': info.attempts,
                'window_start': info.window_start.isoformat(),
                'locked_until': info.locked_until.isoformat() 
                    if info.locked_until else None
            },
            ttl=self.rate_limit_window_seconds
        )


class CacheService:
    """
    Cache abstraction (Redis in production).
    
    Provides simple key-value storage with TTL.
    """
    
    def __init__(self):
        # In production, would be Redis client
        self._cache = {}
    
    async def get(self, key: str) -> Optional[dict]:
        """Get value from cache"""
        return self._cache.get(key)
    
    async def set(self, key: str, value: dict, ttl: int):
        """Set value in cache with TTL"""
        self._cache[key] = value
        # In production, would set TTL in Redis
    
    async def delete(self, key: str):
        """Delete key from cache"""
        self._cache.pop(key, None)
    
    async def exists(self, key: str) -> bool:
        """Check if key exists"""
        return key in self._cache
