#!/bin/sh

# ========================================================
# 初始化目录与权限
# ========================================================
echo "[Init] 正在初始化部署权限与目录..."

mkdir -p /etc/nginx/conf.d
mkdir -p /opt/SubMonitor/rules
mkdir -p /etc/nginx/ssl

chmod -R 777 /etc/nginx/conf.d
chmod -R 777 /opt/SubMonitor/rules
chmod -R 777 /etc/nginx/ssl 2>/dev/null || true

touch /opt/SubMonitor/rules/ip_blacklist.conf
touch /opt/SubMonitor/rules/ua_blacklist.conf
touch /opt/SubMonitor/rules/token_blacklist.conf
chmod 666 /opt/SubMonitor/rules/*.conf 2>/dev/null || true

echo "[Init] 权限初始化完成！"

# ========================================================
# 安装依赖与自签名证书
# ========================================================
apk add --no-cache curl openssl socat >/dev/null 2>&1

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
  # 已更改为 Let's Encrypt
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
  echo "[Init] acme.sh 安装完成"
fi

# ========================================================
# 后台任务：证书申请 + 配置重载监听
# ========================================================
(while true; do
  # 1. 检查是否有证书申请任务
  if [ -f /opt/SubMonitor/rules/.cert_flag ]; then
    DOMAIN=$(cat /opt/SubMonitor/rules/.cert_flag | tr -d '\r\n ')
    rm -f /opt/SubMonitor/rules/.cert_flag

    if [ -z "$DOMAIN" ]; then
      echo '{"status":"error","msg":"域名为空，跳过申请"}' > /opt/SubMonitor/rules/cert_status.json
      sleep 5
      continue
    fi

    echo "[Cert] 开始申请域名证书：$DOMAIN"
    echo "{\"status\":\"processing\",\"msg\":\"正在申请 $DOMAIN 证书，请稍候...\"}" > /opt/SubMonitor/rules/cert_status.json

    nginx -s reload >/dev/null 2>&1
    sleep 2

    # 注意此处修改了 -w 指向的网站根目录为 /opt/SubMonitor/html
    /root/.acme.sh/acme.sh --issue -d "$DOMAIN" -w /opt/SubMonitor/html \
      --accountemail admin@befriends.wiki --force --keylength 2048

    if [ $? -eq 0 ]; then
      /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
        --key-file /etc/nginx/ssl/key.pem \
        --fullchain-file /etc/nginx/ssl/cert.pem \
        --reloadcmd "nginx -s reload"

      chmod 666 /etc/nginx/ssl/*.pem 2>/dev/null || true
      nginx -s reload >/dev/null 2>&1

      echo "[Cert] ✅ $DOMAIN 证书申请成功并已生效"
      echo "{\"status\":\"success\",\"msg\":\"✅ $DOMAIN 证书申请成功，已自动生效！\"}" > /opt/SubMonitor/rules/cert_status.json
    else
      echo "[Cert] ❌ $DOMAIN 证书申请失败"
      echo "{\"status\":\"error\",\"msg\":\"❌ 申请失败！请确认：域名已解析到本机IP + 80端口开放 + 无CDN\"}" > /opt/SubMonitor/rules/cert_status.json
    fi
  fi

  # 2. 检查是否有配置重载请求
  if [ -f /opt/SubMonitor/rules/.reload_flag ]; then
    rm -f /opt/SubMonitor/rules/.reload_flag
    nginx -s reload >/dev/null 2>&1
    echo "[Reload] Nginx 配置已重载"
  fi

  sleep 3
done) &

# ========================================================
# 启动 Nginx 主服务（前台运行）
# ========================================================
echo "[Init] 启动 Nginx 服务..."
exec nginx -g 'daemon off;'
