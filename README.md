# ms-security

Servicio de autenticación y autorización de EduAirControl (dominio **seguridad**).

- Spring Boot 4.0.5 / Java 17 — arquitectura hexagonal (ADR-009)
- PostgreSQL 15 con esquema propio `seguridad` (ADR-003), migraciones Liquibase (ADR-008)
- JWT **RS256** con claves RSA y publicación **JWKS** (`/api/v1/auth/jwks`); el resto de
  servicios y el gateway validan sin llamar a este servicio (ADR-006)
- Refresh tokens **stateful** (UUID, hash SHA-256, rotación de un solo uso)
- **Lista negra en Redis** (`blacklist:{jti}`) al hacer logout: el gateway la consulta en
  solo lectura para invalidar el access token antes de su expiración
- Bloqueo de cuenta por intentos fallidos (5 intentos / 15 min) en columnas PostgreSQL
- **Multi-tenant**: instituciones (`institution`, `code` = `companyCode`, ej. `SEN-444`);
  cada usuario pertenece a **una institución y una sede** (`institution_id`, `campus_id`);
  el access token lleva los claims `institutionId`/`campusId` (ADR-016)
- Roles `SUPER_ADMIN`, `ADMIN`, `USER`, `VIEWER` (sembrados por `RoleBootstrap`)
- Puerto **8081**, Swagger UI en `/swagger-ui.html`

## Endpoints

| Método | Ruta | Auth | Notas |
|--------|------|------|-------|
| GET | `/api/v1/auth/health` | público | estado del servicio y de sus dependencias |
| POST | `/api/v1/auth/register` | público | crea cuenta, valida `companyCode`, asigna rol `USER` |
| POST | `/api/v1/auth/login` | público | 401 credenciales/institución inválidas, 423 cuenta bloqueada |
| POST | `/api/v1/auth/refresh` | público | rota el refresh token; el anterior queda revocado |
| POST | `/api/v1/auth/logout` | Bearer | revoca el refresh token y añade el `jti` a la lista negra Redis |
| GET | `/api/v1/auth/jwks` | público | clave pública RSA (JWKS) para validar access tokens |
| GET/POST/PUT | `/api/v1/institutions` | SUPER_ADMIN | gestión de instituciones (tenants) |

El access token es un JWT RS256 de 1 h con `sub`, `email`, `username`, `roles`,
`institutionId`, `campusId` y `permissions` (vacío hasta que exista autorización granular).

## Ejecutar

```bash
# local (necesita PostgreSQL con la BD eduaircontrol_security y Redis)
POSTGRES_USER=security_user POSTGRES_PASSWORD=security_pass ./mvnw spring-boot:run

# o stack completo
docker compose up --build
```

Las claves de desarrollo están en `src/main/resources/keys/dev-{private,public}.pem`; en
producción se sustituyen por variables de entorno (`SECURITY_RSA_*_KEY_PATH`).

## Pruebas

```bash
./mvnw verify        # 44 tests: unit + controllers sobre H2
```
