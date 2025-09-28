# Auth-Service Deployment Guide

## 1. Configuration Updates

### application.properties
```properties
# Server configuration
base.domain=https://sarlab.dia.uned.es
server.servlet.context-path=/auth

# Endpoint paths (only for dynamic URL construction)
endpoint.auth2=/auth2
endpoint.jwks=/jwks
endpoint.guacamole=/guacamole

# Existing configuration
contract.address=0x1234567890abcdef1234567890abcdef12345678
rpc.url=https://ethereum-rpc.example.com
allowed-origins=https://marketplace.example.com,https://frontend.example.com

# JWT configuration
private.key.path=/path/to/your/private_key.pem
public.key.path=/path/to/your/public_key.pem
public.certificate.path=/path/to/your/certificate.pem

# UPDATED: Dynamic marketplace public key configuration
marketplace.public-key-url=https://marketplace.example.com/.well-known/public-key.pem
```

## 2. Deployment Steps

### Step 1: Update Configuration
1. **Get the public key endpoint URL** from the marketplace team
2. **Add it to application.properties** in the `marketplace.public-key-url` property
3. **Update allowed-origins** to include the marketplace domain
4. **Configure base.domain** and endpoint paths for dynamic URL construction

### Step 2: Deploy the Updated Code
```bash
# Build the project
mvn clean package

# Deploy the WAR file to your application server (Tomcat, etc.)
cp target/auth-1.0-SNAPSHOT.war /path/to/tomcat/webapps/

# Or run with Spring Boot
java -jar target/auth-1.0-SNAPSHOT.war
```

### Step 3: Verify Endpoints
Test that the new endpoints are working:

```bash
# Test marketplace authentication (should fail without valid JWT)
curl -X POST https://auth-service.example.com/auth/marketplace-auth \
  -H "Content-Type: application/json" \
  -d '{
    "marketplaceToken": "invalid-token",
    "labId": "lab123",
    "timestamp": 1693766400
  }'

# Expected response: {"error": "Invalid marketplace token..."}
```

## 3. Security Considerations

### Firewall Rules
Make sure your firewall allows:
- **Inbound**: HTTPS (443) from marketplace servers
- **Outbound**: HTTPS (443) to blockchain RPC endpoints

### Log Monitoring
Monitor logs for:
- Invalid JWT signatures
- Expired tokens
- Suspicious request patterns

### Key Rotation
When marketplace rotates keys:
1. Marketplace updates their public key endpoint
2. Auth-service automatically fetches new key within 24 hours
3. For immediate effect, restart service or wait for signature failure (triggers immediate refresh)
4. No manual configuration changes needed on auth-service side

## 4. Testing with Marketplace

### Integration Test Checklist
- [ ] Marketplace can generate valid JWTs
- [ ] Auth-service validates JWT signatures correctly
- [ ] Expired JWTs are rejected
- [ ] Invalid signatures are rejected
- [ ] User information is extracted correctly
- [ ] Lab booking validation works (if applicable)

### Common Issues and Solutions

**Issue**: "Invalid marketplace token"
- **Solution**: Verify marketplace public key endpoint is accessible
- **Check**: Test the public key URL directly: `curl https://marketplace.example.com/.well-known/public-key.pem`
- **Verify**: Ensure no extra whitespace in PEM format returned by endpoint

**Issue**: "Request timestamp expired"
- **Solution**: Check clock synchronization between marketplace and auth-service
- **Verify**: Timestamp in request matches current time

**Issue**: CORS errors
- **Solution**: Add marketplace domain to `allowed-origins`
- **Update**: CORS configuration in SecurityConfig

## 5. Monitoring and Alerts

### Key Metrics to Monitor
- JWT validation success/failure rates
- Response times for marketplace endpoints
- Error rates by endpoint
- Number of requests per marketplace user

### Recommended Alerts
- High JWT validation failure rate (>5%)
- Response time >2 seconds
- Error rate >1%
- Unusual request patterns

## 6. Backup and Recovery

### Configuration Backup
```bash
# Backup current configuration
cp /path/to/application.properties /backup/application.properties.$(date +%Y%m%d)
```

### Rollback Plan
1. Keep previous WAR file as backup
2. Document configuration changes
3. Have rollback procedure ready
4. Test rollback in staging environment

## 7. Documentation Updates

Update your internal documentation:
- [ ] API documentation with new endpoints
- [ ] Security policies reflecting JWT validation
- [ ] Integration guide for future marketplace integrations
- [ ] Troubleshooting guide for common issues