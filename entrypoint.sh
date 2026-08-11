#!/bin/sh

# ========================================================
# 1. 自动初始化所有挂载目录与文件的写权限（免手动 chmod）
# ========================================================
echo "[Init] 正在初始化部署权限与目录..."

# 创建必要目录
mkdir -p /etc/nginx/conf.d
mkdir -p /etc/nginx/rules
mkdir -p /etc/nginx/ssl

# 自动提升挂载目录写权限，确保 PHP 与 Nginx 均可自由读写
chmod -R 777 /etc/nginx/conf.d
chmod -R 777 /etc/nginx/rules
chmod -R 777 /etc/nginx/ssl 2>/dev/null || true

# 预先创建黑名单配置文件并赋予可写权限，防止 Nginx 启动缺失文件报错
touch /etc/nginx/rules/ip_blacklist.conf
touch /etc/nginx/rules/ua_blacklist.conf
touch /etc/nginx/rules/token_blacklist.conf
chmod 666 /etc/nginx/rules/*.conf 2>/dev/null || true

echo "[Init] 权限初始化完成！"

# ========================================================
# 2. 安装依赖与基础配置
# ========================================================
apk add --no-cache curl openssl socat >/dev/null 2>&1

# 检查并生成初始临时自签名证书，防止 Nginx 启动崩溃
if [ ! -f /etc/nginx/ssl/cert.pem ] || [ ! -f /etc/nginx/ssl/key.pem ]; then
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/key.pem \
    -out /etc/nginx/ssl/cert.pem \
    -subj "/CN=localhost" >/dev/null 2>&1
  chmod 666 /etc/nginx/ssl/*.pem 2>/dev/null || true
fi

# 安装 acme.sh[cite: 2]
if [ ! -f /root/.acme.sh/acme.sh ]; then
  curl https://get.acme.sh | sh -s email=admin@befriends.wiki >/dev/null 2>&1
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
fi

# ========================================================
# 3. 轮询后台监控线程[cite: 2]
# ========================================================
(while true; do
  if [ -f /etc/nginx/rules/.cert_flag ]; then
    DOMAIN=$(cat /etc/nginx/rules/.cert_flag)
    rm -f /etc/nginx/rules/.cert_flag
    echo '{"status":"processing","msg":"正在向 Let'\''s Encrypt 申请证书，请稍候..."}' > /etc/nginx/rules/cert_status.json
    
    # 申请证书前先 reload 确保 Nginx 已应用最新 server_name[cite: 2]
    nginx -s reload >/dev/null 2>&1
    
    /root/.acme.sh/acme.sh --issue -d "$DOMAIN" -w /var/www/html --accountemail admin@befriends.wiki --force
    if [ $? -eq 0 ]; then
      /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
        --key-file /etc/nginx/ssl/key.pem \
        --fullchain-file /etc/nginx/ssl/cert.pem
      
      # 重新给新证书赋予全权限，方便 PHP 实时读取过期时间
      chmod 666 /etc/nginx/ssl/*.pem 2>/dev/null || true
      
      nginx -s reload
      echo '{"status":"success","msg":"证书申请并安装成功，已实时生效！"}' > /etc/nginx/rules/cert_status.json
    else
      echo '{"status":"error","msg":"申请失败！请检查域名 DNS 是否解析到本 VPS，且 80 端口已开放。"}' > /etc/nginx/rules/cert_status.json
    fi
  fi
  if [ -f /etc/nginx/rules/.reload_flag ]; then
    rm -f /etc/nginx/rules/.reload_flag
    nginx -s reload
  fi
  sleep 2
done) &

# ========================================================
# 4. 启动 Nginx 主进程[cite: 2]
# ========================================================
exec nginx -g 'daemon off;'
