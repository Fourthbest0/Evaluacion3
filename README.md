# Seguridad OAuth2 para MS-A, MS-B y frontend

## Estructura
- `auth-server/`  → proyecto NUEVO (Spring Authorization Server, puerto 9000)
- `MS-A/`, `MS-B/` → solo archivos nuevos o modificados: copiarlos encima de tus proyectos
  (`pom.xml`, `application.properties`, `config/SecurityConfig.java`, y en MS-B `config/FeignAuthInterceptor.java`)
- `frontend/index.html` → SPA con login (Authorization Code + PKCE)

## Orden de arranque
1. Eureka
2. `auth-server` (9000)
3. MS-A (81) y MS-B (82)
4. Frontend: `cd frontend && python -m http.server 3000 --bind 127.0.0.1`
   y abrir **http://127.0.0.1:3000** (debe ser 127.0.0.1, no localhost: Spring Authorization Server rechaza `localhost` en redirect URIs)

## Usuarios (solo desarrollo)
| Usuario | Contraseña | Roles |
|---|---|---|
| admin | admin123 | ADMIN, USER |
| usuario | usuario123 | USER |

## Reglas de acceso
| Endpoint | Requiere |
|---|---|
| GET /api/entity-a/**, POST /api/entity-a/by-ids | scope `entity-a.read` |
| POST, PUT /api/entity-a | scope `entity-a.write` |
| DELETE /api/entity-a/{id} | rol ADMIN |
| GET /api/entity-b | scope `entity-b.read` (+ `entity-a.read` porque MS-B consulta a MS-A) |
| POST /api/entity-b | scope `entity-b.write` |

MS-B reenvía el JWT del usuario a MS-A en la llamada Feign (`FeignAuthInterceptor`).

## Pruebas en Postman / Thunder Client
- Sin token → 401.
- Token por client credentials:
  `curl -u postman-client:postman-secret -d grant_type=client_credentials -d "scope=entity-a.read entity-b.read" http://localhost:9000/oauth2/token`
- Token como usuario: OAuth 2.0 → Authorization Code, Auth URL `http://localhost:9000/oauth2/authorize`,
  Token URL `http://localhost:9000/oauth2/token`, Client ID `postman-client`, Secret `postman-secret`,
  Callback `https://oauth.pstmn.io/v1/callback`, scope `openid entity-a.read entity-a.write entity-b.read entity-b.write`.
- Con `usuario`, DELETE en MS-A → 403; con `admin` → 204.

## Notas
- La llave RSA se genera al arrancar: si reinicias el auth-server, vuelve a iniciar sesión.
- Si el auth-server no está en localhost, define `AUTH_SERVER_URL` en MS-A y MS-B y cambia `app.issuer` en auth-server.
- Usuarios y clientes están en memoria; en producción van en base de datos.
