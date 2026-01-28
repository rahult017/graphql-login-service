import logging
from datetime import datetime
from typing import Dict, Any, Optional
import secrets

from ariadne import QueryType, MutationType, UnionType, InterfaceType
from ariadne.asgi import GraphQL

from models import EmailAddress, LoginMetadata, CorrelationId
from login_orchestrator import LoginOrchestrator
from session import SessionService


logger = logging.getLogger(__name__)

# Interface resolver for LoginResponse
login_response_interface = InterfaceType("LoginResponse")

@login_response_interface.type_resolver
def resolve_login_response_type(obj, *_):
    """Resolve concrete type for LoginResponse interface"""
    return obj.get("__typename", "LoginFailure")


# Union resolver for ChallengeData
challenge_data_union = UnionType("ChallengeData")

@challenge_data_union.type_resolver
def resolve_challenge_data_type(obj, *_):
    """Resolve concrete type for ChallengeData union"""
    return obj.get("__typename", "MfaChallenge")

query = QueryType()

@query.field("health")
async def resolve_health(*_) -> Dict[str, Any]:
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat()
    }

mutation = MutationType()


@mutation.field("login")
async def resolve_login(
    _,
    info,
    input: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Main login mutation resolver.
    
    This is the entry point for all authentication flows.
    
    Args:
        input: LoginInput containing identifier, secret, and optional metadata
    
    Returns:
        LoginResponse (polymorphic: Success, Challenge, or Failure)
    
    Security Notes:
    - Correlation ID generated for every request
    - Rate limiting applied before processing
    - Timing attacks prevented via constant-time operations
    - No user enumeration via deterministic errors
    """
    # Generate correlation ID
    correlation_id = CorrelationId(secrets.token_urlsafe(16))
    
    logger.info(f"[{correlation_id}] Login mutation called")
    
    try:
        # Extract and validate input
        identifier = input.get("identifier")
        secret = input.get("secret")
        metadata_input = input.get("metadata", {})
        
        # Validate required fields
        if not identifier or not secret:
            logger.warning(f"[{correlation_id}] Missing required fields")
            return {
                "__typename": "LoginFailure",
                "correlationId": str(correlation_id),
                "timestamp": datetime.utcnow().isoformat(),
                "success": False,
                "errorCode": "INVALID_INPUT",
                "message": "Email and password are required.",
                "retryAllowed": True,
                "retryAfter": None
            }
        
        # Parse email
        try:
            email = EmailAddress(identifier)
        except ValueError as e:
            logger.warning(f"[{correlation_id}] Invalid email format: {e}")
            return {
                "__typename": "LoginFailure",
                "correlationId": str(correlation_id),
                "timestamp": datetime.utcnow().isoformat(),
                "success": False,
                "errorCode": "INVALID_INPUT",
                "message": "Invalid email format.",
                "retryAllowed": True,
                "retryAfter": None
            }
        
        # Parse metadata
        metadata = LoginMetadata.from_dict(metadata_input)
        
        # Get orchestrator from context
        orchestrator: LoginOrchestrator = info.context["orchestrator"]
        
        # Execute login flow
        response = await orchestrator.execute_login(
            email=email,
            secret=secret,
            metadata=metadata,
            correlation_id=correlation_id
        )
        
        logger.info(
            f"[{correlation_id}] Login completed: "
            f"type={response.get('__typename')}, "
            f"success={response.get('success')}"
        )
        
        return response
    
    except Exception as e:
        logger.error(
            f"[{correlation_id}] Unexpected error in login resolver: {e}",
            exc_info=True
        )
        
        # Return generic error
        return {
            "__typename": "LoginFailure",
            "correlationId": str(correlation_id),
            "timestamp": datetime.utcnow().isoformat(),
            "success": False,
            "errorCode": "SERVICE_UNAVAILABLE",
            "message": "Authentication service temporarily unavailable. Please try again later.",
            "retryAllowed": True,
            "retryAfter": None
        }


@mutation.field("verifyChallenge")
async def resolve_verify_challenge(
    _,
    info,
    challengeToken: str,
    challengeResponse: str,
    metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Verify challenge response (MFA code, org selection, etc.).
    
    Args:
        challengeToken: Token from initial challenge
        challengeResponse: User's response to the challenge
        metadata: Optional updated metadata
    
    Returns:
        LoginResponse (may be Success or another Challenge)
    """
    correlation_id = CorrelationId(secrets.token_urlsafe(16))
    
    logger.info(f"[{correlation_id}] Verify challenge called")
    
    try:
        # Parse metadata if provided
        parsed_metadata = LoginMetadata.from_dict(metadata) if metadata else None
        
        # Get challenge verifier from context
        challenge_verifier = info.context.get("challenge_verifier")
        
        if not challenge_verifier:
            logger.error(f"[{correlation_id}] Challenge verifier not configured")
            return {
                "__typename": "LoginFailure",
                "correlationId": str(correlation_id),
                "timestamp": datetime.utcnow().isoformat(),
                "success": False,
                "errorCode": "SERVICE_UNAVAILABLE",
                "message": "Service temporarily unavailable.",
                "retryAllowed": True,
                "retryAfter": None
            }
        
        # Verify challenge
        response = await challenge_verifier.verify(
            challenge_token=challengeToken,
            challenge_response=challengeResponse,
            metadata=parsed_metadata,
            correlation_id=correlation_id
        )
        
        return response
    
    except Exception as e:
        logger.error(
            f"[{correlation_id}] Error in verify challenge: {e}",
            exc_info=True
        )
        
        return {
            "__typename": "LoginFailure",
            "correlationId": str(correlation_id),
            "timestamp": datetime.utcnow().isoformat(),
            "success": False,
            "errorCode": "CHALLENGE_FAILED",
            "message": "Challenge verification failed.",
            "retryAllowed": True,
            "retryAfter": None
        }


@mutation.field("refreshSession")
async def resolve_refresh_session(
    _,
    info,
    refreshToken: str
) -> Dict[str, Any]:
    """
    Refresh session using refresh token.
    
    Args:
        refreshToken: Valid refresh token
    
    Returns:
        LoginResponse with new session token or failure
    """
    correlation_id = CorrelationId(secrets.token_urlsafe(16))
    
    logger.info(f"[{correlation_id}] Refresh session called")
    
    try:
        session_service: SessionService = info.context["session_service"]
        
        # Refresh session
        new_session = await session_service.refresh_session(
            refreshToken,
            correlation_id
        )
        
        if not new_session:
            return {
                "__typename": "LoginFailure",
                "correlationId": str(correlation_id),
                "timestamp": datetime.utcnow().isoformat(),
                "success": False,
                "errorCode": "SESSION_EXPIRED",
                "message": "Session expired. Please log in again.",
                "retryAllowed": True,
                "retryAfter": None
            }
        
        # Return success with new token
        # (Implementation would mirror login success response)
        return {
            "__typename": "LoginSuccess",
            "correlationId": str(correlation_id),
            "timestamp": datetime.utcnow().isoformat(),
            "success": True,
            "sessionToken": new_session.session_id,
            "expiresIn": int((new_session.expires_at - datetime.utcnow()).total_seconds()),
            "user": {
                "id": new_session.user_id,
                "email": "user@example.com",  # Would lookup user
                "name": None,
                "accountType": "D2C",
                "mfaEnrolled": False,
                "lastLoginAt": None
            },
            "organization": None,
            "refreshToken": None
        }
    
    except Exception as e:
        logger.error(
            f"[{correlation_id}] Error in refresh session: {e}",
            exc_info=True
        )
        
        return {
            "__typename": "LoginFailure",
            "correlationId": str(correlation_id),
            "timestamp": datetime.utcnow().isoformat(),
            "success": False,
            "errorCode": "SERVICE_UNAVAILABLE",
            "message": "Service temporarily unavailable.",
            "retryAllowed": True,
            "retryAfter": None
        }

class ChallengeVerifier:
    """
    Handles verification of challenge responses.
    
    This would be a full service in production, handling:
    - MFA code verification
    - Organization selection processing
    - SSO callback handling
    - Password reset validation
    """
    
    def __init__(
        self,
        orchestrator: LoginOrchestrator,
        mfa_service,
        session_service
    ):
        self.orchestrator = orchestrator
        self.mfa_service = mfa_service
        self.session_service = session_service
    
    async def verify(
        self,
        challenge_token: str,
        challenge_response: str,
        metadata: Optional[LoginMetadata],
        correlation_id: CorrelationId
    ) -> Dict[str, Any]:
        """
        Verify challenge response.
        
        Implementation would:
        1. Lookup challenge session
        2. Verify response based on challenge type
        3. Progress to next step or complete authentication
        """
        logger.info(f"[{correlation_id}] Verifying challenge")
        
        # Placeholder implementation
        # Production would retrieve challenge session and verify based on type
        
        return {
            "__typename": "LoginFailure",
            "correlationId": str(correlation_id),
            "timestamp": datetime.utcnow().isoformat(),
            "success": False,
            "errorCode": "CHALLENGE_FAILED",
            "message": "Challenge verification not implemented.",
            "retryAllowed": True,
            "retryAfter": None
        }

def get_resolvers():
    """Get all GraphQL resolvers"""
    return [
        query,
        mutation,
        login_response_interface,
        challenge_data_union
    ]
