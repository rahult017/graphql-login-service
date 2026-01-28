#!/usr/bin/env python3
"""
Startup Script

Initializes the application with test data and starts the server.
"""

import asyncio
import sys
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


async def initialize_test_data_only():
    """Only initialize test data — does NOT start server"""
    logger.info("\nInitializing test data...")
    from main import DependencyContainer, Config
    from test_data import initialize_test_data
    
    config = Config()
    container = DependencyContainer(config)
    
    try:
        await initialize_test_data(container)
        logger.info("Test data initialized successfully")
    except Exception as e:
        logger.warning(f"Could not initialize test data: {e}")
        logger.info("Continuing without test data...")


def main():
    """Main entry point — synchronous wrapper"""
    logger.info("=" * 80)
    logger.info("GraphQL Context-Aware Login Service")
    logger.info("=" * 80)

    from main import Config, app

    config = Config()

    # Run async initialization in current (or new) event loop
    try:
        asyncio.run(initialize_test_data_only())
    except RuntimeError as e:
        if "asyncio.run() cannot be called from a running event loop" in str(e):
            # Already running loop → use existing loop
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(initialize_test_data_only())
            else:
                loop.run_until_complete(initialize_test_data_only())
        else:
            raise

    # Print configuration and test users (same as before)
    logger.info("\n" + "=" * 80)
    logger.info("Server Configuration:")
    logger.info(f"  Host: {config.HOST}")
    logger.info(f"  Port: {config.PORT}")
    logger.info(f"  Debug: {config.DEBUG}")
    logger.info(f"  GraphQL Playground: http://{config.HOST}:{config.PORT}/")
    logger.info("=" * 80)
    
    logger.info("\nTest Users Available:")
    # ... (keep all your test user logging here) ...

    logger.info("=" * 80)
    logger.info("\nExample GraphQL Query:")
    # ... (keep example query) ...

    logger.info("\nStarting server...\n")

    import uvicorn
    uvicorn.run(
        app,
        host=config.HOST,
        port=config.PORT,
        log_level="info",
        # Optional: better shutdown behavior
        timeout_keep_alive=30,
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("\n\nShutting down gracefully...")
        sys.exit(0)
    except Exception as e:
        logger.error(f"\n\nFatal error: {e}", exc_info=True)
        sys.exit(1)