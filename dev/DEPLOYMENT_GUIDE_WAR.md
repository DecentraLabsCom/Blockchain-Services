# Guía de Despliegue - Auth Service Actualización (.war)

## 🎯 Actualización de Producción en Ubuntu 20 con Tomcat

### **📋 Pre-requisitos**
- Ubuntu 20 con Java 11+ instalado
- Tomcat 9+ funcionando
- Auth-service.war actual desplegado
- Acceso SSH al servidor
- Maven instalado (o usar wrapper)

## 🚀 Proceso de Despliegue Seguro para WAR

### **Paso 1: Backup y Preparación**

```bash
# 1. Conectar al servidor
ssh usuario@tu-servidor.com

# 2. Identificar ubicación actual
TOMCAT_HOME=/opt/tomcat  # O /var/lib/tomcat9, ajustar según tu instalación
APP_NAME=auth-service    # O el nombre de tu contexto

# 3. Backup de la aplicación actual
sudo cp $TOMCAT_HOME/webapps/$APP_NAME.war /backup/$APP_NAME-backup-$(date +%Y%m%d_%H%M%S).war
sudo cp -r $TOMCAT_HOME/webapps/$APP_NAME /backup/$APP_NAME-exploded-backup/

# 4. Backup de configuración (si está en Tomcat)
sudo cp $TOMCAT_HOME/webapps/$APP_NAME/WEB-INF/classes/application.properties /backup/application.properties.$(date +%Y%m%d_%H%M%S)

# 5. Verificar el servicio actual está funcionando
curl http://localhost:8080/auth/.well-known/openid-configuration
curl http://localhost:8080/auth/jwks
```

### **Paso 2: Preparar Nueva Versión**

```bash
# Opción A: Subir WAR compilado (desde tu máquina local)
scp target/auth-service.war usuario@tu-servidor.com:/tmp/

# Opción B: Compilar en servidor (recomendado)
cd /path/to/auth-service-source
git pull origin main
mvn clean package -DskipTests

# Verificar que se compiló correctamente
ls -la target/*.war
```

### **Paso 3: Actualizar Configuración**

```bash
# 1. Actualizar application.properties ANTES del despliegue
# Si la configuración está en el WAR:
mkdir /tmp/war-update
cd /tmp/war-update
jar -xf /tmp/auth-service.war
nano WEB-INF/classes/application.properties

# O si usas configuración externa (recomendado):
sudo nano $TOMCAT_HOME/conf/application.properties
# O en: /etc/auth-service/application.properties
```

**Configuración CRÍTICA a actualizar:**
```properties
# Server configuration (NUEVO)
base.domain=https://sarlab.dia.uned.es
server.servlet.context-path=/auth

# Endpoint paths (NUEVO)
endpoint.auth=/auth
endpoint.auth2=/auth2
endpoint.jwks=/jwks
endpoint.message=/message
endpoint.marketplace-auth=/marketplace-auth
endpoint.marketplace-auth2=/marketplace-auth2
endpoint.guacamole=/guacamole
endpoint.health=/health

# Marketplace JWT authentication (ACTUALIZADO)
marketplace.public-key-url=https://marketplace-decentralabs.vercel.app/.well-known/public-key.pem

### **Paso 4: Despliegue con Hot Deployment**

```bash
# 1. Parar la aplicación (manteniendo Tomcat funcionando)
sudo $TOMCAT_HOME/bin/catalina.sh stop

# O usando manager si está habilitado:
# curl -u admin:password "http://localhost:8080/manager/text/stop?path=/auth"

# 2. Remover aplicación anterior
sudo rm -rf $TOMCAT_HOME/webapps/$APP_NAME
sudo rm -f $TOMCAT_HOME/webapps/$APP_NAME.war

# 3. Limpiar trabajo temporal de Tomcat
sudo rm -rf $TOMCAT_HOME/work/Catalina/localhost/$APP_NAME

# 4. Copiar nuevo WAR
sudo cp target/auth-service.war $TOMCAT_HOME/webapps/
# O si tu contexto tiene otro nombre:
# sudo cp target/auth-service.war $TOMCAT_HOME/webapps/$APP_NAME.war

# 5. Ajustar permisos
sudo chown tomcat:tomcat $TOMCAT_HOME/webapps/*.war
sudo chmod 644 $TOMCAT_HOME/webapps/*.war

# 6. Iniciar Tomcat
sudo $TOMCAT_HOME/bin/catalina.sh start

# O si usas systemd:
# sudo systemctl restart tomcat9
```

### **Paso 5: Verificación Post-Despliegue**

```bash
# 1. Verificar que Tomcat está funcionando
sudo systemctl status tomcat9
# O verificar proceso:
ps aux | grep tomcat

# 2. Esperar a que la aplicación se despliegue (puede tardar 30-60 segundos)
tail -f $TOMCAT_HOME/logs/catalina.out

# Buscar líneas como:
# "Started AuthApplication in X.XXX seconds"
# "Tomcat started on port(s): 8080"

# 3. Probar endpoints NUEVOS primero
# Health check (NUEVO ENDPOINT)
curl http://localhost:8080/auth/health

# Debe devolver algo como:
# {"status":"UP","timestamp":"2025-09-27T...","service":"auth-service",...}

# 4. Verificar endpoints existentes
curl http://localhost:8080/auth/.well-known/openid-configuration
curl http://localhost:8080/auth/jwks

# 5. Probar desde exterior (reemplaza con tu dominio)
curl https://sarlab.dia.uned.es/auth/health
curl https://sarlab.dia.uned.es/auth/.well-known/openid-configuration
```

### **Paso 6: Pruebas de Integración**

```bash
# 1. Probar marketplace endpoints (deben responder con error esperado)
curl -X POST https://sarlab.dia.uned.es/auth/marketplace-auth \
  -H "Content-Type: application/json" \
  -d '{"marketplaceToken": "invalid", "timestamp": 1695825600}'

# Respuesta esperada: {"error": "Invalid marketplace token or could not extract user information."}

# 2. Verificar clave pública marketplace se puede obtener
curl -I https://marketplace-decentralabs.vercel.app/.well-known/public-key.pem

# 3. Probar autenticación wallet (si usas esta función)
curl -X POST https://sarlab.dia.uned.es/auth/message \
  -H "Content-Type: application/json" \
  -d '{"wallet": "0x123456789abcdef"}'
```