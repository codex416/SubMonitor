#!/bin/sh

# 安装依赖
apk add --no-cache curl openssl socat >/dev/null 2>&1

# 安装 acme.sh
if [ ! -f /root/.acme.sh/acme.sh ]; then
  curl https://get.acme.sh | sh -s email=admin@befriends.wiki >/dev/null 2>&1
  /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt >/dev/null 2>&1
fi

# 轮询后台监控线程
(while true; do
  if [ -f /etc/nginx/rules/.cert_flag ]; then
    DOMAIN=$(cat /etc/nginx/rules/.cert_flag)
    rm -f /etc/nginx/rules/.cert_flag
    echo '{"status":"processing","msg":"正在向 Let'\''s Encrypt 申请证书，请稍候..."}' > /etc/nginx/rules/cert_status.json
    /root/.acme.sh/acme.sh --issue -d "$DOMAIN" -w /var/www/html --accountemail admin@befriends.wiki --force
    if [ $? -eq 0 ]; then
      /root/.acme.sh/acme.sh --install-cert -d "$DOMAIN" \
        --key-file /etc/nginx/ssl/key.pem \
        --fullchain-file /etc/nginx/ssl/cert.pem
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

# 启动 Nginx 主进程
exec nginx -g 'daemon off;'
