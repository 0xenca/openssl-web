# Política de seguridad — Enca's SGEN

## Actualizaciones

Se realizan **actualizaciones periódicas en función de las vulnerabilidades que reporta GitHub a través de Dependabot** (`.github/dependabot.yml`) sobre este repositorio.

- La aplicación no usa librerías descargadas de Internet: solo la biblioteca estándar de Python, el binario `openssl` y el paquete de Debian `python3-cryptography`. En el navegador se usa WebCrypto, que viene integrado.
- Python, `python3-cryptography` y OpenSSL proceden de los repositorios oficiales de Debian 13 y se actualizan con sus parches de seguridad (`apt`).
- El CI (`.github/workflows/tests.yml`) ejecuta los tests en Debian 13 en cada cambio y una vez por semana.
- `install.sh` vuelve a ejecutar los tests en el servidor antes de cada despliegue. Si el servicio no arranca, revierte a la versión anterior.

Para aplicar una actualización en el servidor:

```bash
sudo apt update && sudo apt upgrade        # parches de seguridad de Debian (OpenSSL, Python, python3-cryptography…)
sudo opensslweb-admin update               # nueva versión de la aplicación
```

## Cifrado de las comunicaciones

Además de HTTPS, cada petición con datos se cifra con un par de claves ECDH P-256 efímero (HKDF-SHA256 + AES-256-GCM). El servidor guarda la clave privada solo en memoria, la usa una única vez y la destruye al terminar la petición, o a los 60 s si no se usa. Los detalles están en `app/e2e.py` y en el apartado «Información» de la web.

## Notificar una vulnerabilidad

Usa la opción **«Report a vulnerability»** de la pestaña *Security* del repositorio en GitHub (aviso privado), en lugar de abrir una incidencia pública.

## Sin garantías

Enca's SGEN es un servicio gratuito, libre y sin coste para el usuario final, desarrollado por Andre Lopez Araujo. No se garantiza ningún SLA ni se ofrecen garantías finales en caso de ataques u otros incidentes de seguridad. Consulta el apartado «Información» de la web.
