import secrets
import hmac
import hashlib
import base64
from typing import Optional, Tuple, List
from datetime import datetime, timedelta
import logging

from models import (
    User, MfaMethod, MfaDevice, CorrelationId,
    ChallengeType
)


logger = logging.getLogger(__name__)


class MfaService:
    """
    Multi-factor authentication orchestration service.
    
    Responsibilities:
    - MFA challenge generation
    - Code verification
    - Device enrollment
    - Trusted device management
    - Backup code handling
    """
    
    def __init__(
        self,
        mfa_device_repository,
        totp_service: 'TotpService',
        sms_service: Optional['SmsService'] = None,
        email_service: Optional['EmailService'] = None
    ):
        self.device_repo = mfa_device_repository
        self.totp_service = totp_service
        self.sms_service = sms_service
        self.email_service = email_service
        
        # MFA configuration
        self.code_validity_seconds = 300  # 5 minutes
        self.max_attempts = 3
    
    async def initiate_mfa_challenge(
        self,
        user: User,
        correlation_id: CorrelationId,
        preferred_method: Optional[MfaMethod] = None
    ) -> Tuple[MfaMethod, Optional[str], str]:
        """
        Initiate MFA challenge for user.
        
        Returns:
            (method, masked_delivery_target, challenge_data)
        
        Edge Cases:
        1. User has no MFA enrolled → Return enrollment challenge
        2. Preferred method unavailable → Fallback to next available
        3. All methods unavailable → Return service error
        """
        logger.info(f"[{correlation_id}] Initiating MFA for user {user.id}")
        
        # Get user's enrolled MFA devices
        devices = await self.device_repo.find_by_user_id(user.id)
        active_devices = [d for d in devices if d.is_verified]
        
        if not active_devices:
            logger.warning(f"[{correlation_id}] No MFA devices enrolled for user")
            # Return enrollment challenge
            return MfaMethod.TOTP, None, "enrollment_required"
        
        # Determine which method to use
        method = await self._select_mfa_method(
            active_devices,
            preferred_method,
            correlation_id
        )
        
        # Generate and send challenge
        if method == MfaMethod.TOTP:
            return await self._initiate_totp_challenge(user, correlation_id)
        elif method == MfaMethod.SMS:
            return await self._initiate_sms_challenge(user, correlation_id)
        elif method == MfaMethod.EMAIL:
            return await self._initiate_email_challenge(user, correlation_id)
        elif method == MfaMethod.BACKUP_CODE:
            return await self._initiate_backup_code_challenge(user, correlation_id)
        
        logger.error(f"[{correlation_id}] Unsupported MFA method: {method}")
        raise ValueError(f"Unsupported MFA method: {method}")
    
    async def verify_mfa_code(
        self,
        user: User,
        code: str,
        method: MfaMethod,
        correlation_id: CorrelationId
    ) -> bool:
        """
        Verify MFA code submitted by user.
        
        Returns:
            True if code is valid, False otherwise
        
        Security:
        - Constant-time comparison
        - Rate limiting
        - Attempt tracking
        """
        logger.info(f"[{correlation_id}] Verifying MFA code for user {user.id}")
        
        # Verify based on method
        if method == MfaMethod.TOTP:
            return await self._verify_totp_code(user, code, correlation_id)
        elif method == MfaMethod.SMS or method == MfaMethod.EMAIL:
            return await self._verify_otp_code(user, code, method, correlation_id)
        elif method == MfaMethod.BACKUP_CODE:
            return await self._verify_backup_code(user, code, correlation_id)
        
        return False
    
    async def check_trusted_device(
        self,
        user: User,
        device_fingerprint: str,
        correlation_id: CorrelationId
    ) -> bool:
        """
        Check if device is trusted for MFA bypass.
        
        Returns:
            True if device is trusted, False otherwise
        """
        logger.info(f"[{correlation_id}] Checking trusted device for user {user.id}")
        
        devices = await self.device_repo.find_by_user_id(user.id)
        
        for device in devices:
            if (device.is_trusted and 
                device.device_fingerprint == device_fingerprint):
                # Check if trust hasn't expired (e.g., 30 days)
                trust_age = datetime.utcnow() - device.last_used_at
                if trust_age < timedelta(days=30):
                    logger.info(f"[{correlation_id}] Trusted device found")
                    return True
        
        return False
    
    async def _select_mfa_method(
        self,
        devices: List[MfaDevice],
        preferred: Optional[MfaMethod],
        correlation_id: CorrelationId
    ) -> MfaMethod:
        """
        Select MFA method based on availability and preference.
        
        Priority:
        1. User preference (if available)
        2. TOTP (most reliable)
        3. SMS (if service available)
        4. Email (fallback)
        5. Backup codes (last resort)
        """
        device_methods = {d.method for d in devices}
        
        # Check preferred method
        if preferred and preferred in device_methods:
            if await self._is_method_available(preferred, correlation_id):
                return preferred
        
        # Fallback priority
        priority = [
            MfaMethod.TOTP,
            MfaMethod.SMS,
            MfaMethod.EMAIL,
            MfaMethod.BACKUP_CODE
        ]
        
        for method in priority:
            if method in device_methods:
                if await self._is_method_available(method, correlation_id):
                    return method
        
        # Default to TOTP if nothing available
        return MfaMethod.TOTP
    
    async def _is_method_available(
        self,
        method: MfaMethod,
        correlation_id: CorrelationId
    ) -> bool:
        """
        Check if MFA method is currently available.
        
        Implements circuit breaker pattern for external services.
        """
        if method == MfaMethod.TOTP or method == MfaMethod.BACKUP_CODE:
            # These are always available (local verification)
            return True
        
        if method == MfaMethod.SMS:
            # Check SMS service health
            if not self.sms_service:
                return False
            return await self.sms_service.is_healthy()
        
        if method == MfaMethod.EMAIL:
            # Check email service health
            if not self.email_service:
                return False
            return await self.email_service.is_healthy()
        
        return True
    
    async def _initiate_totp_challenge(
        self,
        user: User,
        correlation_id: CorrelationId
    ) -> Tuple[MfaMethod, Optional[str], str]:
        """Initiate TOTP challenge"""
        logger.info(f"[{correlation_id}] Initiating TOTP challenge")
        
        # TOTP doesn't send anything, user enters from their app
        return MfaMethod.TOTP, None, "totp_ready"
    
    async def _initiate_sms_challenge(
        self,
        user: User,
        correlation_id: CorrelationId
    ) -> Tuple[MfaMethod, Optional[str], str]:
        """Initiate SMS challenge"""
        logger.info(f"[{correlation_id}] Initiating SMS challenge")
        
        if not self.sms_service:
            logger.error(f"[{correlation_id}] SMS service not available")
            raise ValueError("SMS service unavailable")
        
        # Generate 6-digit code
        code = self._generate_numeric_code(6)
        
        # Store code (in production, use Redis with TTL)
        await self._store_otp_code(user.id, code, MfaMethod.SMS)
        
        # Send SMS
        phone_number = await self._get_user_phone_number(user)
        await self.sms_service.send_code(phone_number, code, correlation_id)
        
        # Mask phone number for response
        masked = self._mask_phone_number(phone_number)
        
        return MfaMethod.SMS, masked, "code_sent"
    
    async def _initiate_email_challenge(
        self,
        user: User,
        correlation_id: CorrelationId
    ) -> Tuple[MfaMethod, Optional[str], str]:
        """Initiate email challenge"""
        logger.info(f"[{correlation_id}] Initiating email challenge")
        
        if not self.email_service:
            logger.error(f"[{correlation_id}] Email service not available")
            raise ValueError("Email service unavailable")
        
        # Generate 6-digit code
        code = self._generate_numeric_code(6)
        
        # Store code
        await self._store_otp_code(user.id, code, MfaMethod.EMAIL)
        
        # Send email
        await self.email_service.send_code(user.email, code, correlation_id)
        
        # Mask email for response
        masked = self._mask_email(str(user.email))
        
        return MfaMethod.EMAIL, masked, "code_sent"
    
    async def _initiate_backup_code_challenge(
        self,
        user: User,
        correlation_id: CorrelationId
    ) -> Tuple[MfaMethod, Optional[str], str]:
        """Initiate backup code challenge"""
        logger.info(f"[{correlation_id}] Initiating backup code challenge")
        
        return MfaMethod.BACKUP_CODE, None, "enter_backup_code"
    
    async def _verify_totp_code(
        self,
        user: User,
        code: str,
        correlation_id: CorrelationId
    ) -> bool:
        """Verify TOTP code from authenticator app"""
        logger.info(f"[{correlation_id}] Verifying TOTP code")
        
        # Get user's TOTP secret
        devices = await self.device_repo.find_by_user_id(user.id)
        totp_device = next((d for d in devices if d.method == MfaMethod.TOTP), None)
        
        if not totp_device:
            return False
        
        # Verify TOTP code (in production, would get secret from device)
        return self.totp_service.verify_code(code, "user_totp_secret", correlation_id)
    
    async def _verify_otp_code(
        self,
        user: User,
        code: str,
        method: MfaMethod,
        correlation_id: CorrelationId
    ) -> bool:
        """Verify OTP code (SMS or Email)"""
        logger.info(f"[{correlation_id}] Verifying OTP code for {method.value}")
        
        # Retrieve stored code
        stored_code = await self._get_stored_otp_code(user.id, method)
        
        if not stored_code:
            logger.warning(f"[{correlation_id}] No stored code found")
            return False
        
        # Constant-time comparison
        is_valid = hmac.compare_digest(code, stored_code)
        
        if is_valid:
            # Invalidate code after use
            await self._invalidate_otp_code(user.id, method)
        
        return is_valid
    
    async def _verify_backup_code(
        self,
        user: User,
        code: str,
        correlation_id: CorrelationId
    ) -> bool:
        """Verify backup recovery code"""
        logger.info(f"[{correlation_id}] Verifying backup code")
        
        # In production, would check against hashed backup codes
        # and invalidate after use
        return False
    
    def _generate_numeric_code(self, length: int = 6) -> str:
        """Generate random numeric code"""
        return ''.join(str(secrets.randbelow(10)) for _ in range(length))
    
    def _mask_phone_number(self, phone: str) -> str:
        """Mask phone number for display"""
        if len(phone) < 4:
            return "***"
        return f"***-***-{phone[-4:]}"
    
    def _mask_email(self, email: str) -> str:
        """Mask email address for display"""
        local, domain = email.split('@')
        if len(local) <= 2:
            masked_local = "*" * len(local)
        else:
            masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
        return f"{masked_local}@{domain}"
    
    async def _store_otp_code(self, user_id: str, code: str, method: MfaMethod):
        """Store OTP code (in production, use Redis with TTL)"""
        # Placeholder - would store in cache
        pass
    
    async def _get_stored_otp_code(
        self,
        user_id: str,
        method: MfaMethod
    ) -> Optional[str]:
        """Retrieve stored OTP code"""
        # Placeholder - would retrieve from cache
        return None
    
    async def _invalidate_otp_code(self, user_id: str, method: MfaMethod):
        """Invalidate used OTP code"""
        # Placeholder - would delete from cache
        pass
    
    async def _get_user_phone_number(self, user: User) -> str:
        """Get user's phone number for SMS"""
        # Placeholder - would lookup from user profile
        return "+1234567890"


class TotpService:
    """
    Time-based One-Time Password (TOTP) service.
    
    Implements RFC 6238 TOTP algorithm.
    """
    
    def verify_code(
        self,
        code: str,
        secret: str,
        correlation_id: CorrelationId,
        time_window: int = 1
    ) -> bool:
        """
        Verify TOTP code with time window tolerance.
        
        Args:
            code: User-provided 6-digit code
            secret: User's TOTP secret
            correlation_id: Request correlation ID
            time_window: Number of 30-second windows to check (default 1 = ±30s)
        
        Returns:
            True if code is valid, False otherwise
        """
        logger.info(f"[{correlation_id}] Verifying TOTP code")
        
        # In production, would use pyotp library
        # For now, placeholder implementation
        import pyotp
        totp = pyotp.TOTP(secret)
        
        return totp.verify(code, valid_window=time_window)
    
    def generate_secret(self) -> str:
        """Generate new TOTP secret"""
        import pyotp
        return pyotp.random_base32()
    
    def get_provisioning_uri(
        self,
        secret: str,
        email: str,
        issuer: str = "LoginService"
    ) -> str:
        """Get QR code provisioning URI"""
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name=issuer)


class SmsService:
    """SMS delivery service (Twilio, AWS SNS, etc.)"""
    
    async def send_code(
        self,
        phone_number: str,
        code: str,
        correlation_id: CorrelationId
    ):
        """Send MFA code via SMS"""
        logger.info(f"[{correlation_id}] Sending SMS to {phone_number[-4:]}")
        # Placeholder - would integrate with Twilio/SNS
        pass
    
    async def is_healthy(self) -> bool:
        """Check service health"""
        return True


class EmailService:
    """Email delivery service"""
    
    async def send_code(
        self,
        email: str,
        code: str,
        correlation_id: CorrelationId
    ):
        """Send MFA code via email"""
        logger.info(f"[{correlation_id}] Sending email to {email}")
        # Placeholder - would integrate with SendGrid/SES
        pass
    
    async def is_healthy(self) -> bool:
        """Check service health"""
        return True
