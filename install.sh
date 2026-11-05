#!/usr/bin/env bash
# =============================================================================
#  OpenSSL Web — instalador / actualizador para Debian 13 (trixie)
#
#  Uso (como root):
#    ./install.sh [install]     Instalación inicial o redespliegue desde este directorio
#    ./install.sh update        git pull del repositorio de origen + redespliegue
#    ./install.sh rollback      Vuelve a la versión anterior (/opt/opensslweb.prev)
#    ./install.sh status        Estado del servicio y versión instalada
#    ./install.sh test          Ejecuta los tests sobre la versión instalada
#    ./install.sh uninstall [--purge]
#
#  Opciones:
#    --skip-tests   No ejecuta los tests antes de desplegar (no recomendado)
#    --no-pull      En "update", no hace git pull (solo redespliega)
#    --force        Permite ejecutar en un sistema que no sea Debian 13
#    --purge        En "uninstall", borra también la configuración y el usuario
#
#  Tras la primera instalación también está disponible como:
#    opensslweb-admin update | rollback | status | test | uninstall
# =============================================================================
set -Eeuo pipefail
umask 022

APP=opensslweb
INSTALL_DIR=/opt/opensslweb
PREV_DIR=/opt/opensslweb.prev
STAGE_DIR=/opt/opensslweb.new
CONF_DIR=/etc/opensslweb
ENV_FILE=$CONF_DIR/opensslweb.env
UNIT_FILE=/etc/systemd/system/opensslweb.service
ADMIN_LINK=/usr/local/sbin/opensslweb-admin
SOURCE_FILE=$INSTALL_DIR/.source
SERVICE_USER=opensslweb
PAYLOAD=(app deploy tests VERSION README.md install.sh)

SKIP_TESTS=0
NO_PULL=0
FORCE=0
PURGE=0

SCRIPT_PATH=$(readlink -f "${BASH_SOURCE[0]}")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

if [[ -t 1 ]]; then
  C_OK=$'\e[32m'; C_WARN=$'\e[33m'; C_ERR=$'\e[31m'; C_B=$'\e[1m'; C_0=$'\e[0m'
else
  C_OK=; C_WARN=; C_ERR=; C_B=; C_0=
fi
info() { printf '%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '%s ✓ %s %s\n' "$C_OK" "$C_0" "$*"; }
warn() { printf '%s ! %s %s\n' "$C_WARN" "$C_0" "$*" >&2; }
die()  { printf '%s ✗ %s %s\n' "$C_ERR" "$C_0" "$*" >&2; exit 1; }

usage() { sed -n '3,22p' "$SCRIPT_PATH" | sed 's/^#  \{0,1\}//'; }

# -----------------------------------------------------------------------------
# Comprobaciones
# -----------------------------------------------------------------------------
require_root() {
  [[ $EUID -eq 0 ]] || die "Ejecuta este script como root (sudo $0 $*)"
}

check_os() {
  local id="" ver=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    id=$(. /etc/os-release && echo "${ID:-}")
    ver=$(. /etc/os-release && echo "${VERSION_ID:-}")
  fi
  if [[ $id == debian && $ver == 13 ]]; then
    ok "Sistema: Debian 13"
  elif [[ $FORCE -eq 1 ]]; then
    warn "Sistema '$id $ver' no soportado; continuando por --force"
  else
    die "Este instalador solo soporta Debian 13 (detectado: '$id $ver'). Usa --force bajo tu responsabilidad."
  fi
  command -v systemctl >/dev/null || die "systemd no está disponible"
}

install_deps() {
  local missing=()
  dpkg-query -W -f='${Status}' python3 2>/dev/null | grep -q "install ok installed" || missing+=(python3)
  dpkg-query -W -f='${Status}' openssl 2>/dev/null | grep -q "install ok installed" || missing+=(openssl)
  if ((${#missing[@]})); then
    info "Instalando dependencias: ${missing[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
      -o Dpkg::Use-Pty=0 "${missing[@]}" >/dev/null
  fi
  python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
    || die "Se necesita Python >= 3.9"
  ok "Dependencias: $(python3 --version 2>&1), $(openssl version | cut -d' ' -f1-2)"
}

ensure_user() {
  if ! getent group "$SERVICE_USER" >/dev/null; then
    groupadd --system "$SERVICE_USER"
  fi
  if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --gid "$SERVICE_USER" --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin --comment "OpenSSL Web" "$SERVICE_USER"
    ok "Usuario de sistema '$SERVICE_USER' creado"
  fi
}

# -----------------------------------------------------------------------------
# Despliegue
# -----------------------------------------------------------------------------
stage() {
  local src=$1
  for item in "${PAYLOAD[@]}"; do
    [[ -e $src/$item ]] || die "Falta '$item' en $src: ¿es el directorio correcto?"
  done
  rm -rf "$STAGE_DIR"
  mkdir -p "$STAGE_DIR"
  for item in "${PAYLOAD[@]}"; do
    cp -a "$src/$item" "$STAGE_DIR/"
  done
  find "$STAGE_DIR" -name '__pycache__' -type d -prune -exec rm -rf {} +
  chown -R root:root "$STAGE_DIR"
  find "$STAGE_DIR" -type d -exec chmod 0755 {} +
  find "$STAGE_DIR" -type f -exec chmod 0644 {} +
  chmod 0755 "$STAGE_DIR/install.sh" "$STAGE_DIR/app/server.py"
  # Recordamos el origen (repositorio git) para futuras actualizaciones.
  if [[ $src != "$INSTALL_DIR" ]]; then
    printf '%s\n' "$src" >"$STAGE_DIR/.source"
  elif [[ -f $SOURCE_FILE ]]; then
    cp "$SOURCE_FILE" "$STAGE_DIR/.source"
  fi
  ok "Versión $(cat "$STAGE_DIR/VERSION") preparada"
}

run_tests() {
  local dir=$1 out rc=0
  info "Ejecutando tests (python3 + openssl del sistema)…"
  out=$(cd "$dir" && runuser -u "$SERVICE_USER" -- env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
        python3 -B -m unittest discover -s tests -t . 2>&1) || rc=$?
  if [[ $rc -eq 0 ]]; then
    ok "Tests superados ($(printf '%s\n' "$out" | grep -E '^Ran [0-9]+ tests' || echo 'OK'))"
    return 0
  fi
  printf '%s\n' "$out" | tail -n 40 >&2
  return 1
}

install_config() {
  install -d -m 0750 -o root -g "$SERVICE_USER" "$CONF_DIR"
  if [[ ! -f $ENV_FILE ]]; then
    install -m 0640 -o root -g "$SERVICE_USER" "$STAGE_DIR/deploy/opensslweb.env" "$ENV_FILE"
    ok "Configuración creada en $ENV_FILE"
  else
    install -m 0640 -o root -g "$SERVICE_USER" "$STAGE_DIR/deploy/opensslweb.env" "$ENV_FILE.dist"
    ok "Configuración existente conservada ($ENV_FILE); referencia nueva en $ENV_FILE.dist"
  fi
}

install_unit() {
  install -m 0644 -o root -g root "$INSTALL_DIR/deploy/opensslweb.service" "$UNIT_FILE"
  if command -v systemd-analyze >/dev/null; then
    systemd-analyze verify "$UNIT_FILE" >/dev/null 2>&1 || warn "systemd-analyze verify ha emitido avisos"
  fi
  systemctl daemon-reload
  systemctl enable "$APP.service" >/dev/null 2>&1
  ln -sfn "$INSTALL_DIR/install.sh" "$ADMIN_LINK"
  ok "Servicio $APP.service instalado y habilitado en el arranque"
}

swap_in() {
  rm -rf "$PREV_DIR"
  if [[ -d $INSTALL_DIR ]]; then
    mv "$INSTALL_DIR" "$PREV_DIR"
  fi
  mv "$STAGE_DIR" "$INSTALL_DIR"
}

health_check() {
  local tries=${1:-20}
  python3 -I - "$ENV_FILE" "$tries" <<'PY'
import json, ssl, sys, time, urllib.request
env = {}
try:
    with open(sys.argv[1]) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip('"').strip("'")
except OSError:
    pass
host = env.get("OPENSSLWEB_HOST", "127.0.0.1")
if host in ("0.0.0.0", ""):
    host = "127.0.0.1"
elif host == "::":
    host = "::1"
if ":" in host:
    host = f"[{host}]"
port = env.get("OPENSSLWEB_PORT", "8080")
tls = bool(env.get("OPENSSLWEB_TLS_CERT") and env.get("OPENSSLWEB_TLS_KEY"))
url = f"{'https' if tls else 'http'}://{host}:{port}/healthz"
ctx = ssl._create_unverified_context() if tls else None
for _ in range(int(sys.argv[2])):
    try:
        with urllib.request.urlopen(url, timeout=2, context=ctx) as r:
            data = json.load(r)
            if data.get("status") == "ok":
                print(f"{url} -> versión {data.get('version')}")
                sys.exit(0)
    except Exception:
        pass
    time.sleep(0.5)
print(f"Sin respuesta en {url}")
sys.exit(1)
PY
}

restart_and_check() {
  systemctl restart "$APP.service"
  if health_check 30; then
    ok "Servicio en marcha"
    return 0
  fi
  return 1
}

do_install() {
  local src=$1
  require_root
  check_os
  install_deps
  ensure_user
  info "Preparando despliegue desde $src"
  stage "$src"
  if [[ $SKIP_TESTS -eq 0 ]]; then
    run_tests "$STAGE_DIR" || { rm -rf "$STAGE_DIR"; die "Los tests han fallado: no se despliega nada (la versión actual sigue activa)"; }
  else
    warn "Tests omitidos (--skip-tests)"
  fi
  install_config
  swap_in
  install_unit
  if restart_and_check; then
    ok "${C_B}OpenSSL Web $(cat "$INSTALL_DIR/VERSION") desplegado en $INSTALL_DIR${C_0}"
    print_access
  else
    warn "El servicio no responde tras el despliegue"
    journalctl -u "$APP.service" -n 20 --no-pager 2>/dev/null || true
    if [[ -d $PREV_DIR ]]; then
      warn "Restaurando la versión anterior…"
      do_rollback_internal
      die "Despliegue revertido. Revisa la configuración ($ENV_FILE)."
    fi
    die "El servicio no arranca. Revisa: journalctl -u $APP"
  fi
}

print_access() {
  local host port
  host=$(grep -E '^OPENSSLWEB_HOST=' "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)
  port=$(grep -E '^OPENSSLWEB_PORT=' "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)
  echo
  echo "  Escuchando en ${host:-127.0.0.1}:${port:-8080}  (config: $ENV_FILE)"
  echo "  Actualizar:     sudo opensslweb-admin update"
  echo "  Volver atrás:   sudo opensslweb-admin rollback"
  echo
}

source_dir() {
  # Directorio de origen (repositorio) a partir del que actualizar.
  if [[ $SCRIPT_DIR == "$INSTALL_DIR" ]]; then
    [[ -f $SOURCE_FILE ]] || die "No se conoce el repositorio de origen. Ejecuta install.sh desde el repositorio."
    cat "$SOURCE_FILE"
  else
    echo "$SCRIPT_DIR"
  fi
}

do_update() {
  require_root
  local src owner
  src=$(source_dir)
  [[ -d $src ]] || die "El repositorio de origen '$src' ya no existe"
  if [[ $NO_PULL -eq 0 ]]; then
    if [[ -d $src/.git ]]; then
      command -v git >/dev/null || die "git no está instalado (apt install git)"
      owner=$(stat -c %U "$src")
      info "Actualizando el repositorio $src (git pull)"
      local git_cmd=(git -C "$src" pull --ff-only)
      [[ $owner == root ]] || git_cmd=(runuser -u "$owner" -- "${git_cmd[@]}")
      "${git_cmd[@]}" || die "git pull ha fallado en $src (¿cambios locales o sin rama remota?). No se ha desplegado nada."
    else
      warn "$src no es un repositorio git: se redespliega su contenido actual"
    fi
  fi
  # Se ejecuta el instalador de la NUEVA versión.
  local args=(install)
  [[ $SKIP_TESTS -eq 1 ]] && args+=(--skip-tests)
  [[ $FORCE -eq 1 ]] && args+=(--force)
  exec bash "$src/install.sh" "${args[@]}"
}

do_rollback_internal() {
  [[ -d $PREV_DIR ]] || die "No hay versión anterior en $PREV_DIR"
  rm -rf "$STAGE_DIR"
  mv "$INSTALL_DIR" "$STAGE_DIR"
  mv "$PREV_DIR" "$INSTALL_DIR"
  mv "$STAGE_DIR" "$PREV_DIR"
  install_unit
  systemctl restart "$APP.service" || true
}

do_rollback() {
  require_root
  do_rollback_internal
  if health_check 30; then
    ok "Restaurada la versión $(cat "$INSTALL_DIR/VERSION")"
  else
    die "La versión restaurada no responde. Revisa: journalctl -u $APP"
  fi
}

do_status() {
  if [[ -f $INSTALL_DIR/VERSION ]]; then
    echo "Versión instalada: $(cat "$INSTALL_DIR/VERSION")"
  else
    echo "OpenSSL Web no está instalado"
  fi
  [[ -f $PREV_DIR/VERSION ]] && echo "Versión anterior:  $(cat "$PREV_DIR/VERSION")"
  [[ -f $SOURCE_FILE ]] && echo "Repositorio:       $(cat "$SOURCE_FILE")"
  systemctl --no-pager status "$APP.service" 2>/dev/null | head -n 5 || true
  health_check 1 || true
}

do_test() {
  require_root
  [[ -d $INSTALL_DIR ]] || die "OpenSSL Web no está instalado"
  ensure_user
  run_tests "$INSTALL_DIR" || die "Los tests han fallado"
}

do_uninstall() {
  require_root
  systemctl disable --now "$APP.service" >/dev/null 2>&1 || true
  rm -f "$UNIT_FILE" "$ADMIN_LINK"
  systemctl daemon-reload || true
  rm -rf "$INSTALL_DIR" "$PREV_DIR" "$STAGE_DIR"
  if [[ $PURGE -eq 1 ]]; then
    rm -rf "$CONF_DIR"
    userdel "$SERVICE_USER" >/dev/null 2>&1 || true
    getent group "$SERVICE_USER" >/dev/null && groupdel "$SERVICE_USER" >/dev/null 2>&1 || true
    ok "OpenSSL Web desinstalado (configuración y usuario eliminados)"
  else
    ok "OpenSSL Web desinstalado (se conserva $CONF_DIR; usa --purge para borrarlo)"
  fi
}

# -----------------------------------------------------------------------------
CMD=install
ARGS=()
for arg in "$@"; do
  case $arg in
    --skip-tests) SKIP_TESTS=1 ;;
    --no-pull) NO_PULL=1 ;;
    --force) FORCE=1 ;;
    --purge) PURGE=1 ;;
    -h|--help|help) usage; exit 0 ;;
    install|update|rollback|status|test|uninstall) CMD=$arg ;;
    *) ARGS+=("$arg") ;;
  esac
done
((${#ARGS[@]} == 0)) || die "Argumento desconocido: ${ARGS[*]} (usa --help)"

case $CMD in
  install)
    if [[ $SCRIPT_DIR == "$INSTALL_DIR" ]]; then
      do_install "$(source_dir)"
    else
      do_install "$SCRIPT_DIR"
    fi
    ;;
  update) do_update ;;
  rollback) do_rollback ;;
  status) do_status ;;
  test) do_test ;;
  uninstall) do_uninstall ;;
esac
