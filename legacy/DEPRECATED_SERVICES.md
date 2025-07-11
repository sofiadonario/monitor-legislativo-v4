# Deprecated Services

⚠️ **DEPRECATED** - These services are no longer maintained as part of the Monitor Legislativo v4 refactoring.

## Legacy R-Shiny Services

The following R-Shiny services have been consolidated into the unified deployment:

### Legacy Components:
- `r-shiny-app/` - Original R-Shiny application
- `r-shiny-consolidated/` - Consolidated R-Shiny with advanced features
- `r-shiny-minimal/` - Minimal R-Shiny deployment
- `r-shiny-standalone/` - Standalone R-Shiny service

### Migration Status:
- **Current Active Service**: `railway-unified.toml` (unified R-Shiny service)
- **Status**: Legacy services retained for reference only
- **Deployment**: Do not deploy legacy services in production

## Security Notice

⚠️ **SECURITY**: Legacy configuration files have been sanitized to remove hardcoded credentials. 
Always use Railway environment variables for sensitive configuration.

## Cleanup Actions Performed

1. Removed hardcoded database credentials from `railway.toml` files
2. Marked all legacy services as deprecated
3. Consolidated deployment to unified service architecture

## Contact

For questions about the refactoring or migration, refer to the main project documentation.