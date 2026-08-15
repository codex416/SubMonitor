#!/bin/sh

RULES_DIR="/opt/SubMonitor/rules"
SSL_DIR="/etc/nginx/ssl"
ACME_HOME="/opt/SubMonitor/rules/acme"
DOMAIN_FILE="$RULES_DIR/domain.conf"
LOCK_FILE="$RULES_DIR/.domain_locked"
ALLOW_FILE="$RULES_DIR/domain_allow.conf"

mkdir -p /etc/nginx/conf.d "$RULES_DIR" "$SSL_DIR" "$ACME_HOME"

touch "$RULES_DIR/ip_blacklist.conf" "$RULES_DIR/ua_blacklist.conf" "$RULES_DIR/token_blacklist.conf"
# Nginx 启动前必须存在，否则 include 会导致启动失败。
touch "$ALLOW_FILE"

chmod -R 777 "$RULES_DIR" /etc/nginx/conf.d "$SSL_DIR" 2>/dev/null || true
chmod 666 "$RULES_DIR"/*.conf "$RULES_DIR"/*.json "$ALLOW_FILE" 2>/dev/null || true

echo "[Init] 正在安装依赖..."
apk add --no-cache curl openssl socat >/dev/null 2>&1

# 初始安装使用临时自签名证书；正式 ACME 证书成功后会覆盖它。
if [ ! -s "$SSL_DIR/cert.pem" ] || [ ! -s "$SSL_DIR/key.pem" ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.pem" \
    -subj "/CN=localhost" >/dev/null 2>&1
  chmod 666 "$SSL_DIR"/*.pem 2>/dev/null || true
  echo "[Init] 自签名证书已生成"
fi

# acme.sh 放到 /opt/SubMonitor/rules，避免运行数据落到 /root。
if [ ! -f "$ACME_HOME/acme.sh" ]; then
  echo "[Init] 正在安装 acme.sh..."
  curl -s https://get.acme.sh | sh -s email=admin@qq.com --home "$ACME_HOME" >/dev/null 2>&1
fi

ACME="$ACME_HOME/acme.sh"
if [ -f "$ACME" ]; then
  "$ACME" --set-default-ca --server letsencrypt >/dev/null 2>&1 || true
fi

# 生成 Nginx domain allow map。
write_allow_file() {
  domain="$1"
  : > "$ALLOW_FILE"
  if [ -n "$domain" ]; then
    # 精确 Host 匹配；同时允许该域名的大小写变体由 Nginx $host 规范化处理。
    printf '"%s" 1;\n' "$domain" > "$ALLOW_FILE"
  fi
  chmod 666 "$ALLOW_FILE" 2>/dev/null || true
}

# 判断当前证书是否为正式证书，并且 CN 与绑定域名一致。
is_formal_cert_for_domain() {
  domain="$1"
  [ -n "$domain" ] || return 1
  [ -s "$SSL_DIR/cert.pem" ] || return 1
  subject=$(openssl x509 -in "$SSL_DIR/cert.pem" -noout -subject 2>/dev/null || true)
  issuer=$(openssl x509 -in "$SSL_DIR/cert.pem" -noout -issuer 2>/dev/null || true)
  printf '%s' "$subject" | grep -Eiq "CN[[:space:]]*=[[:space:]]*${domain}([, /]|$)" || return 1
  # 排除默认 CN=localhost 自签名证书；正式证书应来自 ACME CA。
  printf '%s' "$issuer" | grep -Eiq 'Let.s Encrypt|ZeroSSL|Google Trust Services|Buypass' || return 1
  return 0
}

# 每次容器启动先根据持久化状态恢复访问模式。
DOMAIN=$(cat "$DOMAIN_FILE" 2>/dev/null | tr -d '
 ' || true)
if is_formal_cert_for_domain "$DOMAIN"; then
  echo "1" > "$LOCK_FILE"
  write_allow_file "$DOMAIN"
  echo "[Init] 检测到正式证书：$DOMAIN，已恢复域名锁定模式"
else
  rm -f "$LOCK_FILE"
  write_allow_file ""
  echo "[Init] 当前未检测到有效正式证书，保持 IP 可访问模式"
fi

# 用 include 的方式把锁定状态变成 Nginx 变量；文件始终存在。
write_lock_map() {
  if [ -f "$LOCK_FILE" ]; then
    echo 'map $host $domain_locked { default 1; }' > "$RULES_DIR/domain_lock.conf"
  else
    echo 'map $host $domain_locked { default 0; }' > "$RULES_DIR/domain_lock.conf"
  fi
  chmod 666 "$RULES_DIR/domain_lock.conf" 2>/dev/null || true
}
write_lock_map

# 后台任务：证书申请 + 配置重载监听
(
while true; do
  if [ -f "$RULES_DIR/.cert_flag" ]; then
    DOMAIN=$(cat "$RULES_DIR/.cert_flag" | tr -d '
 ')
    rm -f "$RULES_DIR/.cert_flag"

    if [ -z "$DOMAIN" ]; then
      echo '{"status":"error","msg":"域名为空，跳过申请"}' > "$RULES_DIR/cert_status.json"
      sleep 3
      continue
    fi

    # 域名变更/申请期间先解除锁定，避免旧域名与新证书状态混在一起。
    rm -f "$LOCK_FILE"
    write_allow_file ""
    write_lock_map
    nginx -s reload >/dev/null 2>&1 || true

    echo "[Cert] 开始申请域名证书：$DOMAIN"
    echo "{"status":"processing","msg":"正在申请 $DOMAIN 证书，请稍候..."}" > "$RULES_DIR/cert_status.json"

    "$ACME" --issue -d "$DOMAIN" -w /opt/SubMonitor/html \
      --accountemail admin@qq.com --force --keylength 2048

    if [ $? -eq 0 ]; then
      "$ACME" --install-cert -d "$DOMAIN" \
        --key-file "$SSL_DIR/key.pem" \
        --fullchain-file "$SSL_DIR/cert.pem" \
        --reloadcmd "nginx -s reload"

      if is_formal_cert_for_domain "$DOMAIN"; then
        echo "$DOMAIN" > "$DOMAIN_FILE"
        echo "1" > "$LOCK_FILE"
        write_allow_file "$DOMAIN"
        write_lock_map
        chmod 666 "$SSL_DIR"/*.pem 2>/dev/null || true
        nginx -s reload >/dev/null 2>&1 || true
        echo "[Cert] ✅ $DOMAIN 正式证书已生效，已切换为强制域名模式"
        echo "{"status":"success","msg":"✅ $DOMAIN 证书申请成功，已自动生效；IP 与未绑定域名已禁止访问。"}" > "$RULES_DIR/cert_status.json"
      else
        rm -f "$LOCK_FILE"
        write_allow_file ""
        write_lock_map
        echo "[Cert] ❌ ACME 命令成功但证书校验失败，保持 IP 可访问"
        echo "{"status":"error","msg":"证书已返回，但未检测到与绑定域名匹配的正式 CA 证书。"}" > "$RULES_DIR/cert_status.json"
      fi
    else
      rm -f "$LOCK_FILE"
      write_allow_file ""
      write_lock_map
      nginx -s reload >/dev/null 2>&1 || true
      echo "[Cert] ❌ $DOMAIN 证书申请失败，保持 IP 可访问模式"
      echo "{"status":"error","msg":"❌ 申请失败！请确认域名已解析到本机IP、80端口开放且未被 CDN/代理拦截。"}" > "$RULES_DIR/cert_status.json"
    fi
  fi

  if [ -f "$RULES_DIR/.reload_flag" ]; then
    rm -f "$RULES_DIR/.reload_flag"
    nginx -t >/dev/null 2>&1 && nginx -s reload >/dev/null 2>&1 || true
  fi

  sleep 3
done
) &

echo "[Init] 启动 Nginx 服务..."
exec nginx -g 'daemon off;'
