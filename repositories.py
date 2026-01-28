from typing import Optional, List
from abc import ABC, abstractmethod

from models import (
    User, 
    Organization, 
    OrganizationMembership, 
    MfaDevice,
    EmailAddress, 
    Session
)


class UserRepository(ABC):
    """User data access interface"""
    
    @abstractmethod
    async def find_by_email(self, email: EmailAddress) -> Optional[User]:
        """Find user by email address"""
        pass
    
    @abstractmethod
    async def find_by_id(self, user_id: str) -> Optional[User]:
        """Find user by ID"""
        pass
    
    @abstractmethod
    async def create(self, user: User) -> User:
        """Create new user"""
        pass
    
    @abstractmethod
    async def update(self, user: User) -> User:
        """Update existing user"""
        pass
    
    @abstractmethod
    async def delete(self, user_id: str):
        """Delete user"""
        pass


class OrganizationRepository(ABC):
    """Organization data access interface"""
    
    @abstractmethod
    async def find_by_domain(self, domain: str) -> List[Organization]:
        """Find organizations mapped to email domain"""
        pass
    
    @abstractmethod
    async def find_by_id(self, org_id: str) -> Optional[Organization]:
        """Find organization by ID"""
        pass
    
    @abstractmethod
    async def create(self, org: Organization) -> Organization:
        """Create new organization"""
        pass
    
    @abstractmethod
    async def update(self, org: Organization) -> Organization:
        """Update organization"""
        pass


class OrganizationMembershipRepository(ABC):
    """Organization membership data access interface"""
    
    @abstractmethod
    async def find_by_user_id(self, user_id: str) -> List[OrganizationMembership]:
        """Find all memberships for a user"""
        pass
    
    @abstractmethod
    async def find_by_org_id(self, org_id: str) -> List[OrganizationMembership]:
        """Find all memberships in an organization"""
        pass
    
    @abstractmethod
    async def create(self, membership: OrganizationMembership) -> OrganizationMembership:
        """Create new membership"""
        pass
    
    @abstractmethod
    async def update(self, membership: OrganizationMembership) -> OrganizationMembership:
        """Update membership"""
        pass


class MfaDeviceRepository(ABC):
    """MFA device data access interface"""
    
    @abstractmethod
    async def find_by_user_id(self, user_id: str) -> List[MfaDevice]:
        """Find all MFA devices for a user"""
        pass
    
    @abstractmethod
    async def find_by_id(self, device_id: str) -> Optional[MfaDevice]:
        """Find device by ID"""
        pass
    
    @abstractmethod
    async def create(self, device: MfaDevice) -> MfaDevice:
        """Create new MFA device"""
        pass
    
    @abstractmethod
    async def update(self, device: MfaDevice) -> MfaDevice:
        """Update MFA device"""
        pass


class SessionRepository(ABC):
    """Session data access interface"""
    
    @abstractmethod
    async def find_by_id(self, session_id: str) -> Optional[Session]:
        """Find session by ID"""
        pass
    
    @abstractmethod
    async def create(self, session: Session) -> Session:
        """Create new session"""
        pass
    
    @abstractmethod
    async def update(self, session: Session) -> Session:
        """Update session"""
        pass
    
    @abstractmethod
    async def delete(self, session_id: str):
        """Delete session"""
        pass

class InMemoryUserRepository(UserRepository):
    """In-memory user repository for testing/demo"""
    
    def __init__(self):
        self._users = {}
        self._email_index = {}
    
    async def find_by_email(self, email: EmailAddress) -> Optional[User]:
        user_id = self._email_index.get(email.value.lower())
        if user_id:
            return self._users.get(user_id)
        return None
    
    async def find_by_id(self, user_id: str) -> Optional[User]:
        return self._users.get(user_id)
    
    async def create(self, user: User) -> User:
        self._users[user.id] = user
        self._email_index[user.email.value.lower()] = user.id
        return user
    
    async def update(self, user: User) -> User:
        self._users[user.id] = user
        return user
    
    async def delete(self, user_id: str):
        user = self._users.pop(user_id, None)
        if user:
            self._email_index.pop(user.email.value.lower(), None)


class InMemoryOrganizationRepository(OrganizationRepository):
    """In-memory organization repository"""
    
    def __init__(self):
        self._orgs = {}
        self._domain_index = {}
    
    async def find_by_domain(self, domain: str) -> List[Organization]:
        org_ids = self._domain_index.get(domain.lower(), [])
        return [self._orgs[org_id] for org_id in org_ids if org_id in self._orgs]
    
    async def find_by_id(self, org_id: str) -> Optional[Organization]:
        return self._orgs.get(org_id)
    
    async def create(self, org: Organization) -> Organization:
        self._orgs[org.id] = org
        
        # Index by domains
        for domain in org.domain_mappings:
            if domain.lower() not in self._domain_index:
                self._domain_index[domain.lower()] = []
            self._domain_index[domain.lower()].append(org.id)
        
        return org
    
    async def update(self, org: Organization) -> Organization:
        self._orgs[org.id] = org
        return org


class InMemoryMembershipRepository(OrganizationMembershipRepository):
    """In-memory membership repository"""
    
    def __init__(self):
        self._memberships = []
    
    async def find_by_user_id(self, user_id: str) -> List[OrganizationMembership]:
        return [m for m in self._memberships if m.user_id == user_id]
    
    async def find_by_org_id(self, org_id: str) -> List[OrganizationMembership]:
        return [m for m in self._memberships if m.organization_id == org_id]
    
    async def create(self, membership: OrganizationMembership) -> OrganizationMembership:
        self._memberships.append(membership)
        return membership
    
    async def update(self, membership: OrganizationMembership) -> OrganizationMembership:
        # Find and update
        for i, m in enumerate(self._memberships):
            if (m.user_id == membership.user_id and 
                m.organization_id == membership.organization_id):
                self._memberships[i] = membership
                break
        return membership


class InMemoryMfaDeviceRepository(MfaDeviceRepository):
    """In-memory MFA device repository"""
    
    def __init__(self):
        self._devices = {}
        self._user_index = {}
    
    async def find_by_user_id(self, user_id: str) -> List[MfaDevice]:
        device_ids = self._user_index.get(user_id, [])
        return [self._devices[did] for did in device_ids if did in self._devices]
    
    async def find_by_id(self, device_id: str) -> Optional[MfaDevice]:
        return self._devices.get(device_id)
    
    async def create(self, device: MfaDevice) -> MfaDevice:
        self._devices[device.id] = device
        
        if device.user_id not in self._user_index:
            self._user_index[device.user_id] = []
        self._user_index[device.user_id].append(device.id)
        
        return device
    
    async def update(self, device: MfaDevice) -> MfaDevice:
        self._devices[device.id] = device
        return device


class InMemorySessionRepository(SessionRepository):
    """In-memory session repository"""
    
    def __init__(self):
        self._sessions = {}
    
    async def find_by_id(self, session_id: str) -> Optional[Session]:
        return self._sessions.get(session_id)
    
    async def create(self, session: Session) -> Session:
        self._sessions[session.session_id] = session
        return session
    
    async def update(self, session: Session) -> Session:
        self._sessions[session.session_id] = session
        return session
    
    async def delete(self, session_id: str):
        self._sessions.pop(session_id, None)
