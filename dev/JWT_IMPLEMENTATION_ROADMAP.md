# Implementation Roadmap

## Phase 1: Preparation

### Marketplace Team Tasks
- [x] **Generate RSA key pair** using Node.js crypto (script: `generate-jwt-keys.js`)
- [x] **Securely store private key** in `/certificates/jwt/` (excluded from git)
- [x] **Implement public key endpoint** at `/.well-known/public-key.pem`
- [x] **Configure public key URL** with proper caching headers (1 hour cache)
- [x] **Set up development environment** with JWT dependencies (`jsonwebtoken` installed)

### Auth-Service Team Tasks  
- [x] **Implement dynamic public key retrieval** with caching and retry logic
- [x] **Update application.properties** with marketplace public key URL
- [x] **Configure dynamic URL construction** using base.domain and endpoint paths
- [ ] **Test the updated code** in development environment
- [ ] **Prepare deployment pipeline**

## Phase 2: Development

### Marketplace Team Tasks
- [x] **Implement MarketplaceJwtService** for JWT generation (`/src/utils/auth/marketplaceJwt.js`)
- [x] **Implement AuthServiceClient** for API calls (`/src/utils/auth/authServiceClient.js`)
- [x] **Update marketplace controller** to use new flow (JWT flow added to `labAuth.js`)
- [x] **Add configuration** for private key and auth-service URL (`.env.jwt.example` created)
- [x] **Write unit tests** for JWT generation and validation (`/api/auth/test-jwt` endpoint)

### Auth-Service Team Tasks
- [ ] **Deploy updated auth-service** to staging environment
- [ ] **Configure monitoring** for new endpoints
- [ ] **Update firewall rules** if needed
- [ ] **Prepare rollback procedures**

## Phase 3: Integration Testing (Week 4)

### Both Teams Together
- [ ] **End-to-end testing** in staging environment
- [x] **Prepare key rotation procedures** in marketplace 


---

## 📊 Current Implementation Status

### ✅ **Phase 1: COMPLETED** (Marketplace Team)
- **RSA Key Generation**: ✅ Implemented with Node.js script
- **Secure Key Storage**: ✅ Keys stored in `/certificates/jwt/` (git-ignored)
- **Public Key Endpoint**: ✅ Available at `/.well-known/public-key.pem`
- **Caching Configuration**: ✅ 1-hour cache with proper headers
- **Development Environment**: ✅ JWT dependencies installed

### 🔄 **Phase 2: IN PROGRESS** (Marketplace Team)
- **MarketplaceJwtService**: ✅ Completed (`/src/utils/auth/marketplaceJwt.js`)
- **AuthServiceClient**: ✅ Completed (`/src/utils/auth/authServiceClient.js`)
- **Configuration Management**: ✅ Environment variables template ready
- **Test Endpoint**: ✅ JWT testing endpoint implemented
- **Controller Integration**: ✅ JWT flow implemented in `labAuth.js` (SSO + Wallet flows available)

### 📋 **Next Steps**
1. **Integration with existing SSO system** in marketplace controllers
2. **Coordinate with Auth-Service Team** for end-to-end testing
3. **Environment configuration** for staging/production
4. **Performance and security testing**

### 🔧 **Files Created/Modified**
```
marketplace/
├── scripts/generate-jwt-keys.js                   # ✅ Key generation script
├── scripts/rotate-jwt-keys.js                     # ✅ Key rotation script
├── certificates/jwt/                              # ✅ RSA key pair storage
├── src/app/.well-known/public-key.pem/route.js    # ✅ Public key endpoint
├── src/app/api/auth/test-jwt/route.js             # ✅ JWT test endpoint
├── src/utils/auth/marketplaceJwt.js               # ✅ JWT service
├── src/utils/auth/authServiceClient.js            # ✅ Auth service client
├── src/utils/auth/labAuth.js                      # ✅ Updated with JWT flow
├── .env.jwt.example                               # ✅ Environment template
├── dev/JWT_CONFIGURATION.md                       # ✅ Guía completa (Node.js)
├── dev/JWT_KEY_ROTATION.md                        # ✅ Procedimientos de rotación
└── package.json                                   # ✅ Added jwt + rotation scripts
```