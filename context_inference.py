from typing import List, Optional, Tuple
from datetime import datetime
import logging

from models import (
    EmailAddress, IpAddress, CorrelationId, LoginMetadata,
    User, Organization, OrganizationMembership,
    AuthenticationContext, AccountType
)


logger = logging.getLogger(__name__)


class ContextInferenceEngine:
    """
    Infers authentication context from email domain and user state.
    
    This is the core of the "implicit context" requirement - we never
    ask the user what type of login they want, we figure it out.
    """
    
    def __init__(
        self,
        user_repository,
        organization_repository,
        membership_repository
    ):
        self.user_repo = user_repository
        self.org_repo = organization_repository
        self.membership_repo = membership_repository
    
    async def infer_context(
        self,
        email: EmailAddress,
        metadata: LoginMetadata,
        correlation_id: CorrelationId
    ) -> AuthenticationContext:
        """
        Infer complete authentication context from email and metadata.
        
        Process:
        1. Look up user by email
        2. Find organizations mapped to email domain
        3. Get user's organization memberships
        4. Determine account type (D2C vs B2B)
        5. Resolve authentication requirements
        6. Validate IP restrictions
        
        Args:
            email: User's email address
            metadata: Request metadata
            correlation_id: Request correlation ID
        
        Returns:
            Complete authentication context
        """
        logger.info(
            f"[{correlation_id}] Inferring context for email domain: {email.domain}"
        )
        
        # Step 1: Lookup user (may be None for new users)
        user = await self.user_repo.find_by_email(email)
        
        # Step 2: Find organizations mapped to this email domain
        domain_orgs = await self.org_repo.find_by_domain(email.domain)
        logger.info(
            f"[{correlation_id}] Found {len(domain_orgs)} organizations "
            f"for domain {email.domain}"
        )
        
        # Step 3: Get user's organization memberships
        memberships = []
        user_orgs = []
        if user:
            memberships = await self.membership_repo.find_by_user_id(user.id)
            # Filter to active organizations that user is a member of
            user_org_ids = {m.organization_id for m in memberships if m.is_active}
            user_orgs = [org for org in domain_orgs if org.id in user_org_ids]
        
        # Step 4: Determine account type
        account_type = self._determine_account_type(domain_orgs, user_orgs)
        
        logger.info(
            f"[{correlation_id}] Account type determined: {account_type.value}, "
            f"User orgs: {len(user_orgs)}, Domain orgs: {len(domain_orgs)}"
        )
        
        # Step 5: Resolve authentication requirements
        requires_sso = self._requires_sso(user_orgs, metadata)
        requires_mfa = self._requires_mfa(user, user_orgs)
        requires_org_selection = self._requires_org_selection(user_orgs, metadata)
        
        # Step 6: Validate IP restrictions
        ip_allowed = self._validate_ip_restrictions(user_orgs, metadata.ip_address)
        
        return AuthenticationContext(
            user=user,
            organizations=user_orgs if user_orgs else [],
            memberships=memberships,
            account_type=account_type,
            requires_sso=requires_sso,
            requires_mfa=requires_mfa,
            requires_org_selection=requires_org_selection,
            ip_allowed=ip_allowed,
            correlation_id=correlation_id,
            metadata=metadata
        )
    
    def _determine_account_type(
        self,
        domain_orgs: List[Organization],
        user_orgs: List[Organization]
    ) -> AccountType:
        """
        Determine if this is a D2C or B2B login.
        
        Logic:
        - If email domain maps to any organization → B2B
        - If no domain mapping → D2C
        - User's actual membership is considered separately
        
        Edge Case: User exists as D2C but later joins B2B org
        → They become B2B (org context takes precedence)
        """
        if domain_orgs:
            return AccountType.B2B
        return AccountType.D2C
    
    def _requires_sso(
        self,
        user_orgs: List[Organization],
        metadata: LoginMetadata
    ) -> bool:
        """
        Determine if SSO is required.
        
        Logic:
        - If user belongs to multiple orgs and no preference → defer to org selection
        - If single org or preferred org selected → check that org's SSO policy
        - If any org enforces SSO → require SSO
        
        Edge Case: Multi-org user with mixed SSO policies
        → Org selection challenge allows user to choose
        """
        if not user_orgs:
            return False
        
        # Single org case
        if len(user_orgs) == 1:
            return user_orgs[0].requires_sso()
        
        # Multi-org with preference
        if metadata.preferred_org_id:
            for org in user_orgs:
                if org.id == metadata.preferred_org_id:
                    return org.requires_sso()
        
        # Multi-org without preference - check if ALL require SSO
        # If mixed, we'll let org selection handle it
        return all(org.requires_sso() for org in user_orgs)
    
    def _requires_mfa(
        self,
        user: Optional[User],
        user_orgs: List[Organization]
    ) -> bool:
        """
        Determine if MFA is required.
        
        Logic:
        - If any organization requires MFA → require MFA
        - If user has MFA enrolled → require MFA
        - Otherwise → no MFA required
        
        Edge Case: Org requires MFA but user hasn't enrolled
        → Challenge flow will guide enrollment
        """
        # Organization-level MFA requirement
        if any(org.mfa_required for org in user_orgs):
            return True
        
        # User-level MFA enrollment
        if user and user.mfa_enrolled:
            return True
        
        return False
    
    def _requires_org_selection(
        self,
        user_orgs: List[Organization],
        metadata: LoginMetadata
    ) -> bool:
        """
        Determine if organization selection is required.
        
        Logic:
        - If user belongs to multiple orgs AND no preference → require selection
        - If preferred org is specified → no selection needed
        
        Edge Case: Same email in multiple orgs (common for consultants)
        → Always prompt for org selection unless preference provided
        """
        if len(user_orgs) <= 1:
            return False
        
        # Check if user provided preference
        if metadata.preferred_org_id:
            # Validate preference is valid
            return metadata.preferred_org_id not in {org.id for org in user_orgs}
        
        return True
    
    def _validate_ip_restrictions(
        self,
        user_orgs: List[Organization],
        ip_address: Optional[IpAddress]
    ) -> bool:
        """
        Validate IP address against organization whitelist.
        
        Logic:
        - If no IP provided → allow (may be flagged for additional verification)
        - If no orgs have IP restrictions → allow
        - If any org has restrictions → IP must match at least one whitelist
        
        Edge Case: Multi-org with different IP policies
        → IP must be valid for at least one organization
        """
        if not ip_address:
            # No IP provided - allow but may trigger additional verification
            return True
        
        # Get orgs with IP restrictions
        restricted_orgs = [org for org in user_orgs if org.ip_whitelist]
        
        if not restricted_orgs:
            return True
        
        # IP must be allowed by at least one org
        return any(org.is_ip_allowed(ip_address) for org in restricted_orgs)


class ContextEnrichmentService:
    """
    Enriches authentication context with additional security signals.
    
    Used for anomaly detection and adaptive authentication.
    """
    
    def __init__(self, device_fingerprint_service, geo_ip_service):
        self.fingerprint_service = device_fingerprint_service
        self.geo_service = geo_ip_service
    
    async def enrich_metadata(
        self,
        metadata: LoginMetadata,
        correlation_id: CorrelationId
    ) -> LoginMetadata:
        """
        Enrich metadata with additional context.
        
        Enrichments:
        - Geo-location from IP
        - Device type from user agent
        - Known device detection from fingerprint
        - Anomaly score calculation
        """
        # This would integrate with real services in production
        logger.info(f"[{correlation_id}] Enriching metadata")
        
        # For now, return as-is
        # Production would add:
        # - Geo-location lookup
        # - Device reputation check
        # - Behavioral analysis
        
        return metadata


class PolicyResolver:
    """
    Resolves authentication policies from multiple sources.
    
    Handles policy conflicts and precedence rules.
    """
    
    @staticmethod
    def resolve_session_timeout(
        user_orgs: List[Organization],
        default_timeout: int = 3600
    ) -> int:
        """
        Resolve session timeout from organization policies.
        
        Rule: Use the most restrictive (shortest) timeout
        """
        if not user_orgs:
            return default_timeout
        
        org_timeouts = [org.session_timeout_seconds for org in user_orgs]
        return min(org_timeouts) if org_timeouts else default_timeout
    
    @staticmethod
    def resolve_allowed_auth_methods(
        user_orgs: List[Organization]
    ) -> Tuple[bool, bool]:
        """
        Resolve allowed authentication methods.
        
        Returns:
            (password_allowed, sso_allowed)
        
        Rule: If any org enforces SSO, password is not allowed
        """
        if not user_orgs:
            return (True, False)  # D2C users: password only
        
        password_allowed = any(org.supports_password_login() for org in user_orgs)
        sso_allowed = any(org.sso_enabled for org in user_orgs)
        
        # If all orgs enforce SSO, password is not allowed
        if all(org.sso_enforced for org in user_orgs):
            password_allowed = False
        
        return (password_allowed, sso_allowed)
