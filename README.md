# OpenSSL Web

Una web sencilla para generar peticiones de certificado SSL/TLS (**CSR**) y su **clave privada**, y para desglosar y validar CSR existentes.

- **Algoritmos a elegir:** RSA 2048/3072/4096 o ECDSA P-256/P-384/P-521, firma **SHA-256/384/512** y cifrado opcional de la clave con **AES-128/192/256** (PKCS#8 o formato tradicional).
- **Todos los campos del certificado:** CN, O, OU, L, ST, C, email, Subject Alternative Names (DNS, IP, email, URI), Key Usage, Extended Key Usage y OCSP Must-Staple.
- **Descargas:** solo la KEY, solo el CSR, o ambos en un `.zip`, con extensión `.csr`/`.key` o `.txt` (`nombre-csr.txt`, `nombre-key.txt`) para las plataformas que solo admiten texto.
- **Desglose de CSR:** pega un CSR (o abre el fichero) y verás el sujeto, la clave pública, la firma, los SAN y las extensiones, con comprobaciones de buenas prácticas (firma válida, tamaño de clave, SHA-1, CN dentro de los SAN…) y la salida completa de `openssl`.
- **Interfaz:** limpia, con modo día y noche, adaptada a móvil y **sin dependencias externas** de CSS ni JavaScript.

## Privacidad: qué guarda el servidor y qué no

| Dónde | Qué se guarda |
|-------|---------------|
| **Navegador del usuario** | Los CSR y las claves generadas, en `localStorage` (pestaña *Guardados*). Se pueden borrar de una en una o todas a la vez. |
| **Servidor** | **Nada.** Ni ficheros, ni logs, ni registros de operaciones. |

Cómo trata cada petición el servidor:

- **Generar:** `openssl` recibe la clave, la contraseña y los datos por *pipes* en memoria (stdin y descriptores de fichero), así que nunca se escriben ficheros temporales. El servidor devuelve la clave y el CSR al navegador y no se queda con nada.
- **ZIP:** el navegador envía la clave y el CSR. El ZIP se construye en memoria (`BytesIO`) y se devuelve en esa misma respuesta. No se toca el disco.
- **Desglose:** el CSR (que es un dato público) se analiza en memoria.
- **Sin logs:** el registro de peticiones de `http.server` está desactivado y las trazas de error se suprimen. El journal de systemd solo recibe la línea de arranque.
- **Cabeceras:** todas las respuestas de la API llevan `Cache-Control: no-store`. Hay una CSP estricta (`default-src 'none'`, sin scripts inline), anti-framing y comprobación de `Origin` (anti-CSRF).
- **Servicio aislado:** no genera volcados de memoria (`LimitCORE=0`), corre con un usuario sin privilegios y un sistema de ficheros de solo lectura (`ProtectSystem=strict`), y tiene `PrivateTmp`. La puntuación de `systemd-analyze security` es **1.5 (OK)**.

> ⚠️ La clave privada viaja entre el servidor y el navegador. Si el servicio no es solo local, publícalo **siempre por HTTPS**, ya sea con un proxy inverso (nginx, Apache…) o con el HTTPS integrado (ver la configuración).

## Requisitos

Debian 13 (trixie) con `python3` y `openssl` (el instalador los instala si faltan). Solo usa la biblioteca estándar de Python, sin `pip`.

## Instalación inicial

```bash
git clone https://github.com/0xenca/openssl-web.git
cd openssl-web
sudo ./install.sh
```

El instalador:

1. Comprueba que el sistema es Debian 13 e instala `python3` y `openssl` si faltan.
2. Crea el usuario de sistema `opensslweb`, sin shell y sin home.
3. Prepara la nueva versión y **ejecuta los tests** con el Python y el OpenSSL del sistema. Si fallan, no despliega nada.
4. Copia la aplicación a **`/opt/opensslweb`**. La versión anterior queda en `/opt/opensslweb.prev`.
5. Crea `/etc/opensslweb/opensslweb.env` si no existe. Las actualizaciones nunca lo sobrescriben.
6. Instala y habilita el servicio **`opensslweb.service`**, que arranca con la máquina, y lo reinicia.
7. Comprueba que responde en `/healthz`. Si no responde, **vuelve automáticamente a la versión anterior**.

## Actualizaciones y administración

```bash
sudo opensslweb-admin update      # git pull del repositorio + tests + redespliegue
sudo opensslweb-admin rollback    # volver a la versión anterior
sudo opensslweb-admin status      # versión instalada, estado del servicio y healthz
sudo opensslweb-admin test        # ejecutar los tests sobre la versión instalada
sudo opensslweb-admin uninstall   # desinstalar (añade --purge para borrar config y usuario)
```

`update` se acuerda del repositorio desde el que se instaló y hace `git pull --ff-only` como el propietario de ese directorio. Después ejecuta el instalador de la **nueva** versión. Equivale a ejecutar `sudo ./install.sh update` desde el repositorio. Opciones: `--no-pull`, `--skip-tests`, `--force`.

## Configuración

Fichero: `/etc/opensslweb/opensslweb.env`. Tras cambiarlo, ejecuta `sudo systemctl restart opensslweb`.

| Variable | Por defecto | Descripción |
|----------|-------------|-------------|
| `OPENSSLWEB_HOST` | `127.0.0.1` | Dirección de escucha (`0.0.0.0` para todas las interfaces IPv4, `::` para IPv4+IPv6) |
| `OPENSSLWEB_PORT` | `8080` | Puerto (se permiten puertos < 1024, p. ej. 443) |
| `OPENSSLWEB_TLS_CERT` | — | Certificado PEM para servir HTTPS directamente |
| `OPENSSLWEB_TLS_KEY` | — | Clave PEM de ese certificado |
| `OPENSSLWEB_MAX_JOBS` | `4` | Generaciones de claves simultáneas |

Si usas HTTPS directo, los ficheros deben ser legibles por el grupo `opensslweb`, por ejemplo:

```bash
sudo install -d -m 0750 -g opensslweb /etc/opensslweb/tls
sudo install -m 0640 -g opensslweb fullchain.pem privkey.pem /etc/opensslweb/tls/
```

Ejemplo detrás de nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    access_log off;            # coherente con la política de no registrar nada
}
```

## Tests

```bash
python3 -B -m unittest discover -s tests -t .
```

Cubren, entre otras cosas:

- todas las combinaciones de clave y SHA, y el cifrado AES (se comprueba que la clave se descifra con la contraseña correcta y no con otra);
- el formato tradicional y los caracteres especiales en el sujeto;
- SAN y extensiones, y la validación e intentos de inyección;
- el ZIP en memoria y el desglose (SHA-1, firma manipulada, cabecera `NEW CERTIFICATE REQUEST`, challenge password oculto);
- que no se escribe ningún fichero temporal;
- en el servidor HTTP: cabeceras de seguridad, *path traversal*, CSRF, límites de tamaño y que no se registra nada;
- que la interfaz no tiene dependencias externas ni código inline.

## Estructura

```
app/server.py            Servidor HTTP (biblioteca estándar)
app/csrtool.py           Generación, validación, ZIP y desglose de CSR
app/openssl-req.cnf      Configuración estática mínima para openssl req
app/static/              Interfaz (HTML + CSS + JS propios)
deploy/opensslweb.service  Unidad systemd endurecida
deploy/opensslweb.env      Configuración por defecto
install.sh               Instalador / actualizador
tests/                   Tests (unittest)
VERSION                  Versión desplegada
```
