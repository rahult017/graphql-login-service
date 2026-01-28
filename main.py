import uvicorn
import os
import logging
from typing import Dict, Any

from starlette.applications import Starlette
from starlette.routing import Route
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
from ariadne.asgi import GraphQL
from ariadne import load_schema_from_path, make_executable_schema

from login_orchestrator import LoginOrchestrator
from resolvers import get_resolvers, ChallengeVerifier
from context_inference import ContextInferenceEngine

from session import (
    SessionService, 
    TokenService, 
    RateLimiter, 
    CacheService
)

from mfa import (
    MfaService, 
    TotpService, 
    SmsService, 
    EmailService
)

from repositories import (
    InMemoryUserRepository,
    InMemoryOrganizationRepository,
    InMemoryMembershipRepository,
    InMemoryMfaDeviceRepository,
    InMemorySessionRepository
)

from authentication import AuthenticationService, PasswordService, SsoService
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


class Config:
    """Application configuration"""
    
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", "8000"))
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"
    
    SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "*").split(",")
    
    MAX_ATTEMPTS_PER_HOUR = int(os.getenv("MAX_ATTEMPTS_PER_HOUR", "10"))
    MAX_ATTEMPTS_PER_IP = int(os.getenv("MAX_ATTEMPTS_PER_IP", "50"))
    
    SESSION_TIMEOUT = int(os.getenv("SESSION_TIMEOUT", "3600"))
    
    SMS_PROVIDER = os.getenv("SMS_PROVIDER", "none")
    EMAIL_PROVIDER = os.getenv("EMAIL_PROVIDER", "none")


class DependencyContainer:
    """
    Simplified dependency injection container
    """
    
    def __init__(self, config: Config):
        self.config = config
        self._initialize()
    
    def _initialize(self):
        # Repositories (all in-memory for dev)
        self.user_repo = InMemoryUserRepository()
        self.org_repo = InMemoryOrganizationRepository()
        self.membership_repo = InMemoryMembershipRepository()
        self.mfa_device_repo = InMemoryMfaDeviceRepository()
        self.session_repo = InMemorySessionRepository()
        
        # Core services
        self.cache_service = CacheService()
        self.token_service = TokenService(self.config.SECRET_KEY)
        self.password_service = PasswordService()
        
        # MFA services
        self.totp_service = TotpService()
        self.sms_service = SmsService() if self.config.SMS_PROVIDER != "none" else None
        self.email_service = EmailService() if self.config.EMAIL_PROVIDER != "none" else None
        
        self.mfa_service = MfaService(
            mfa_device_repository=self.mfa_device_repo,
            totp_service=self.totp_service,
            sms_service=self.sms_service,
            email_service=self.email_service
        )
        
        # Authentication
        self.sso_service = SsoService(http_client=None)
        self.auth_service = AuthenticationService(
            user_repository=self.user_repo,
            password_service=self.password_service,
            sso_service=self.sso_service
        )
        
        # Session & rate limiting
        self.session_service = SessionService(
            session_repository=self.session_repo,
            token_service=self.token_service
        )
        self.rate_limiter = RateLimiter(cache_service=self.cache_service)
        
        # Context inference
        self.context_engine = ContextInferenceEngine(
            user_repository=self.user_repo,
            organization_repository=self.org_repo,
            membership_repository=self.membership_repo
        )
        
        # Orchestrator & verifier
        self.orchestrator = LoginOrchestrator(
            context_engine=self.context_engine,
            auth_service=self.auth_service,
            mfa_service=self.mfa_service,
            sso_service=self.sso_service,
            session_service=self.session_service,
            rate_limiter=self.rate_limiter
        )
        
        self.challenge_verifier = ChallengeVerifier(
            orchestrator=self.orchestrator,
            mfa_service=self.mfa_service,
            session_service=self.session_service
        )
        
        logger.info("Dependency container initialized")

    def get_graphql_context(self) -> Dict[str, Any]:
        return {
            "orchestrator": self.orchestrator,
            "session_service": self.session_service,
            "challenge_verifier": self.challenge_verifier,
            "user_repo": self.user_repo,
            "org_repo": self.org_repo,
            "config": self.config,
        }

def create_graphql_app(container: DependencyContainer) -> GraphQL:
    type_defs = load_schema_from_path("schema.graphql")
    resolvers = get_resolvers()
    schema = make_executable_schema(type_defs, *resolvers)
    
    async def get_context_value(request):
        return container.get_graphql_context()
    
    graphql_app = GraphQL(
        schema,
        context_value=get_context_value,
        debug=container.config.DEBUG
    )
    
    logger.info("GraphQL schema loaded")
    return graphql_app


from test_data import initialize_test_data
async def startup():
    container = app.state.container
    logger.info("Application startup - seeding test data")
    await initialize_test_data(container)


async def shutdown():
    logger.info("Application shutdown")


def create_app() -> Starlette:
    config = Config()
    container = DependencyContainer(config)
    
    graphql_app = create_graphql_app(container)
    
    routes = [
        Route("/graphql", graphql_app),
        Route("/", graphql_app),  # GraphQL Playground
    ]
    
    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=config.ALLOWED_ORIGINS,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["Content-Type", "Authorization"],
            allow_credentials=True
        )
    ]
    
    app = Starlette(
        debug=config.DEBUG,
        routes=routes,
        middleware=middleware,
        on_startup=[startup],
        on_shutdown=[shutdown]
    )
    
    # Make container available to startup handler
    app.state.container = container
    
    return app


app = create_app()


if __name__ == "__main__":
    config = Config()
    uvicorn.run(
        "main:app",
        host=config.HOST,
        port=config.PORT,
        reload=True,
        log_level="info"
    )