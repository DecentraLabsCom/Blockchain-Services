# Treasury Administration Dashboard

Dashboard web para administrar el wallet institucional y las operaciones de treasury de DecentraLabs.

## 🚀 Acceso

**URL:** `http://localhost:8080/wallet-dashboard/`

⚠️ **IMPORTANTE:** Este dashboard solo es accesible desde localhost por motivos de seguridad.

## 📋 Funcionalidades

### 1. **System Status**
- Estado de configuración del wallet institucional
- **Wallet Setup:** Si no hay wallet configurado, permite:
  - **Create New Wallet:** Genera un nuevo wallet con mnemonic
  - **Import Wallet:** Importa wallet existente desde mnemonic
- Dirección del contrato Diamond
- Redes blockchain disponibles
- Indicador de conexión en tiempo real con 3 estados:
  - 🟢 **Connected** - Wallet configurado y sistema operativo
  - 🟡 **Wallet Setup Required** - Sistema operativo pero wallet no configurado
  - 🔴 **Disconnected** - Error de conexión con el backend

### 2. **Wallet Balances**
- Balance del institutional wallet en todas las redes configuradas
- Soporte para Mainnet y Sepolia
- Actualización manual y automática (cada 30 segundos)
- Formato en ETH con precisión de 6 decimales

### 3. **Spending Limits**
- Visualización de límites diarios, semanales y mensuales
- Progreso de gasto con barras visuales
- Indicadores de gastos restantes
- Color coding según nivel de utilización

### 4. **Administrative Operations**
Operaciones disponibles desde el dashboard:

#### Modify Spending Limits
- Actualizar límite de gasto por usuario
- Formato: cantidad en wei

#### Manage Spending Period
- Configurar periodo de gasto
- Formato: segundos (ej: 86400 = 1 día)

#### Reset Period
- Resetear contadores del periodo actual
- ⚠️ Requiere confirmación

#### Treasury Operations
- **Deposit:** Depositar fondos al treasury
- **Withdraw:** Retirar fondos del treasury
- ⚠️ Operaciones irreversibles, requieren confirmación

### 5. **Recent Transactions**
- Historial de transacciones recientes
- *Nota:* Requiere implementación de indexing o integración con Etherscan API

## 🎨 Diseño

- **Tema:** Cyber Dark con acentos neón
- **Colores:** 
  - Background: Dark blue (#0a0e27, #141933)
  - Accents: Neon blue (#00d4ff), Purple (#b836ff), Green (#00ff88)
- **Responsive:** Adaptado para desktop, tablet y mobile
- **Animaciones:** Efectos suaves, glow effects, pulsos

## 🛠️ Arquitectura Técnica

### Backend (Java/Spring Boot)

#### Controller: `AdminDashboardController.java`
```
GET  /treasury/admin/status          - Estado general del sistema
GET  /treasury/admin/balance         - Balance del institutional wallet
GET  /treasury/admin/balance?chainId - Balance en red específica
GET  /treasury/admin/limits          - Límites de gasto configurados
GET  /treasury/admin/transactions    - Historial de transacciones
GET  /treasury/admin/contract-info   - Información del contrato
```

#### Seguridad
- Validación de localhost en cada endpoint
- Verifica IP remota: 127.0.0.1, ::1
- Chequea header X-Forwarded-For para proxies
- Error 403 si no es localhost

### Frontend (HTML5 + Vanilla JS + CSS3)

#### Estructura de archivos:
```
src/main/resources/static/wallet-dashboard/
├── index.html              # Dashboard principal
├── assets/
│   ├── css/
│   │   └── admin.css       # Estilos cyber/dark theme
│   └── js/
│       ├── api.js          # Cliente API REST
│       └── admin.js        # Lógica del dashboard
```

#### Características JavaScript:
- **Auto-refresh:** Actualización automática cada 30 segundos
- **Toast notifications:** Feedback visual de operaciones
- **Form validation:** Validación de inputs antes de enviar
- **Error handling:** Manejo robusto de errores de API
- **State management:** Control de estado del dashboard

## 🔧 Configuración

### Requisitos previos:
1. **Servicio corriendo:**
   ```bash
   docker-compose up -d blockchain-services
   ```

2. **Institutional wallet configurado (opcional):**
   - Si no tienes wallet, puedes crearlo desde el dashboard
   - O configurar manualmente en `.env`:
   ```bash
   INSTITUTIONAL_WALLET_ADDRESS=0x...
   INSTITUTIONAL_WALLET_PASSWORD=YourSecurePassword
   ```

3. **Acceso desde localhost:**
   ```
   http://localhost:8080/wallet-dashboard/
   ```

## 📊 Uso del Dashboard

### Configurar Wallet (Primera vez)
1. Acceder al dashboard: `http://localhost:8080/wallet-dashboard/`
2. Si no hay wallet configurado, verás la sección "Wallet Setup Required"
3. Opciones disponibles:
   - **Create New Wallet:** 
     - Click en el botón
     - Ingresa una contraseña segura (mínimo 8 caracteres)
     - Confirma la contraseña
     - **IMPORTANTE:** Guarda el mnemonic y la dirección mostrados
     - El wallet se crea pero NO se configura automáticamente
     - Debes agregar a `.env`:
       ```
       INSTITUTIONAL_WALLET_ADDRESS=<dirección_generada>
       INSTITUTIONAL_WALLET_PASSWORD=<tu_contraseña>
       ```
     - Reiniciar el servicio Docker
   
   - **Import Wallet:**
     - Click en el botón
     - Ingresa tu frase mnemonic de 12 palabras
     - Ingresa contraseña para cifrar (mínimo 8 caracteres)
     - Configura en `.env` como arriba
     - Reiniciar el servicio

### Consultar Balance
1. El dashboard carga automáticamente los balances al iniciar
2. Click en "Refresh" en la sección de balances para actualizar manualmente
3. Los balances se muestran en ETH para todas las redes configuradas

### Modificar Límites de Gasto
1. Navegar a "Administrative Operations"
2. En "Modify Spending Limits", ingresar el nuevo límite en wei
3. Ejemplo: 100 ETH = `100000000000000000000` wei
4. Click en "Update Limit"
5. Confirmar la transacción blockchain
6. Los límites se actualizarán automáticamente tras la confirmación

### Operaciones de Treasury
1. En "Treasury Operations", ingresar cantidad en wei
2. Click en "Deposit" o "Withdraw"
3. Confirmar la operación (muestra conversión a ETH)
4. Esperar confirmación blockchain
5. El balance se actualizará automáticamente

## 🔐 Seguridad

### Protecciones implementadas:
1. **Localhost-only access:** Solo accesible desde 127.0.0.1
2. **Wallet verification:** Valida que la dirección coincida con institutional wallet
3. **Transaction confirmation:** Diálogos de confirmación para operaciones críticas
4. **Rate limiting:** Límites de transacciones por hora (configurado en backend)

### Recomendaciones:
- Nunca exponer este dashboard públicamente
- Usar VPN o SSH tunnel si necesitas acceso remoto
- Considerar autenticación básica HTTP para capa adicional
- Auditar logs de acceso regularmente

## 🚧 TODOs / Mejoras Futuras

### Funcionalidades pendientes:
1. **Transaction History**
   - Integrar Etherscan API
   - O implementar event listener + indexing
   - Mostrar historial completo con filtros

2. **Smart Contract Integration**
   - Leer límites reales desde el contrato
   - Implementar llamadas a métodos view del contrato
   - Sincronizar datos on-chain con dashboard

3. **Enhanced Security**
   - JWT authentication
   - 2FA para operaciones críticas
   - Audit log de todas las operaciones

4. **Analytics**
   - Gráficos de gasto por periodo
   - Estadísticas de uso
   - Alertas de límites próximos

5. **Notifications**
   - WebSocket para actualizaciones en tiempo real
   - Email/Slack notifications para operaciones importantes
   - Alertas de transacciones pendientes

## 🐛 Troubleshooting

### Dashboard no carga:
```bash
# Verificar que el servicio esté corriendo
docker ps | grep blockchain-services

# Ver logs del servicio
docker logs blockchain-services

# Verificar acceso localhost
curl http://localhost:8080/treasury/admin/status
```

### Error 403 (Forbidden):
- Asegúrate de acceder desde localhost (127.0.0.1)
- Si usas proxy/nginx, verifica header X-Forwarded-For
- No funcionará desde IP externa por diseño

### Wallet no configurado:
```bash
# Verificar configuración en .env
grep INSTITUTIONAL_WALLET .env

# Debe estar presente:
# INSTITUTIONAL_WALLET_ADDRESS=0x...
# INSTITUTIONAL_WALLET_PASSWORD=...
```

### Transacción falla:
1. Verificar balance suficiente para gas
2. Comprobar que institutional wallet tiene permisos en contrato
3. Revisar logs del backend para detalles del error

## 📚 Referencias

- **InstitutionalTreasuryController:** Operaciones administrativas del contrato
- **WalletService:** Gestión de wallets y balance
- **InstitutionalWalletService:** Manejo del wallet institucional
- **AdminDashboardController:** Endpoints de consulta para dashboard

## 📝 Changelog

### v1.1 (Current)
- ✅ **Wallet creation/import from dashboard**
- ✅ Changed path from `/admin/` to `/wallet-dashboard/`
- ✅ Removed "Configuration Status" field (redundant)
- ✅ Added wallet setup buttons when not configured
- ✅ Enhanced status indicator with 3 states
- ✅ Improved wallet configuration workflow

### v1.0 (Initial Release)
- ✅ System status monitoring
- ✅ Multi-network balance display
- ✅ Spending limits visualization
- ✅ Administrative operations UI
- ✅ Auto-refresh functionality
- ✅ Toast notifications
- ✅ Cyber/dark theme design
- ✅ Responsive layout
- ✅ Localhost-only security

## 👥 Soporte

Para issues o preguntas sobre el dashboard:
1. Revisar logs del backend: `docker logs blockchain-services`
2. Verificar configuración en `.env`
3. Comprobar que institutional wallet esté correctamente configurado
4. Consultar documentación de InstitutionalTreasuryController

---

**Desarrollado por DecentraLabs © 2025**
