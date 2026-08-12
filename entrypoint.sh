#!/bin/sh

# ========================================================
# 1. 初始化目录与权限
# ========================================================
echo "[Init] 正在初始化部署权限与目录..."

mkdir -p /etc/nginx/conf.d
mkdir -p /etc/nginx/rules
mkdir -p /etc/nginx/ssl

chmod -R 777 /etc/nginx/conf.d
chmod -R 777 /etc/nginx/rules
chmod -R 777 /etc/nginx/ssl 2>/dev/null || true

touch /etc/nginx/rules/ip_blacklist.conf
touch /etc/nginx/rules/ua_blacklist.conf
touch /etc/nginx/rules/token_blacklist.conf
chmod 666 /etc/nginx/rules/*.conf 2>/dev/null || true

echo "[Init] 权限初始化完成！"

# ========================================================
# ✅ 新增：自动生成管理员密码（仅首次）
# ========================================================
if [ ! -f /etc/nginx/rules/.htpasswd ]; then
    echo "[Init] 首次部署，正在生成管理员密码..."
    # 生成 16 位随机强密码
    ADMIN_PASS=$(openssl rand -base64 12)
    SALT=$(openssl rand -hex 8)
    PASS_HASH=$(printf "%s%s" "$ADMIN_PASS" "$SALT" | sha256sum | awk '{print $1}')
    echo "sha256:${SALT}:${PASS_HASH}" > /etc/nginx/rules/.htpasswd
    chmod 666 /etc/nginx/rules/.htpasswd
    echo "[Init] ==================================================="
    echo "[Init] ✅ 管理员密码已生成！"
    echo "[Init] 🔑 用户名: admin"
    echo "[Init] 🔑 密码: $ADMIN_PASS"
    echo "[Init] ⚠️  请立即保存此密码！以后可在面板修改！"
    echo "[Init] ==================================================="
fi

# ========================================================
# 2. 安装依赖与证书环境
# ========================================================
apk add --no-cache curl openssl socat >/dev/null 2>&1

# 生成自签名证书
if [ ! -f /etc/nginx/ssl/cert.pem ] || [ ! -f /etc/nginx/ssl/key.pem ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/key.pem \
    -out /etc/nginx/ssl/cert.pem \
    -subj "/CN=localhost" >/dev/null 2>&1
  chmod 666 /etc/nginx/ssl/*.pem 2>/dev/null || true
  echo "[Init] 自签名证书已生成"
fi

# 安装 acme.sh
if [ ! -f /root/.acme.sh/acme.sh ]; then
  echo "[Init] 正在安装 acme.sh..."
  curl -s https://get.acme.sh | sh -s email=admin@befriends.wiki >/dev/null 2>&1
  /root/.acme.sh/acme.sh --set-default-ca --server zerossl >/dev/null 2>&1
  echo "[Init] acme.sh 安装完成"
fi

# ========================================================
# 3. 后台轮询：证书申请 + 配置重载
# ========================================================
(while true; do
  # 域名证书申请
  if [ -f /etc/nginx/rules/.cert_flag ]; then
    DOMAIN=$(cat /etc/nginx/rules/.cert_flag | tr -d '\r\n ')
    rm -f /etc/nginx/rules/.cert_flag

    if [ -z "$DOMAIN" ]; then
      echo '{"status":"error","msg":"域名为空，跳过申请"}' > /etc/nginx/rules/cert_status.json
      sleep 5
      continue
    fi

    echo "[Cert] 开始申请域名证书：$DOMAIN"
    echo "{\"status\":\"processing\",\"msg\":\"正在申请 $DOMAIN 证书，请稍候...\"}" > /etc/nginx/rules/cert_status.json

    nginx -s reload >/dev/null 2>&1
    sleep 2

    /root/.acme.sh/acme.sh --issue -d "$DOMAIN" -w /var/www/html \
      --accountemail admin@befriends.wiki --force --keylength 2048

    if [ $? -eq 0 ]; then
      /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
        --key-file /etc/nginx/ssl/key.pem \
        --fullchain-file /etc/nginx/ssl/cert.pem \
        --reloadcmd "nginx -s reload"

      chmod 666 /etc/nginx/ssl/*.pem 2>/dev/null || true
      nginx -s reload >/dev/null 2>&1

      echo "[Cert] ✅ $DOMAIN 证书申请成功并已生效"
      echo "{\"status\":\"success\",\"msg\":\"✅ $DOMAIN 证书申请成功，已自动生效！\"}" > /etc/nginx/rules/cert_status.json
    else
      echo "[Cert] ❌ $DOMAIN 证书申请失败"
      echo "{\"status\":\"error\",\"msg\":\"❌ 申请失败！请确认：域名已解析到本机IP + 80端口开放 + 无CDN\"}" > /etc/nginx/rules/cert_status.json
    fi
  fi

  # Nginx 配置重载
  if [ -f /etc/nginx/rules/.reload_flag ]; then
    rm -f /etc/nginx/rules/.reload_flag
    nginx -s reload >/dev/null 2>&1
    echo "[Reload] Nginx 配置已重载"
  fi

  sleep 3
done) &

# ========================================================
# 4. 启动 Nginx
# ========================================================
echo "[Init] 启动 Nginx 服务..."
exec nginx -g 'daemon off;'
