#!/bin/bash
mkdir -p /otp/service/resources

if [ -z "$(ls -A /otp/service/resources)" ]; then
    echo "📂 Thư mục /app/resources trống. Copy dữ liệu mặc định..."
    cp -r /opt/service/resources_default/* /otp/service/resources
else
  echo "✅ Thư mục /otp/service/resources đã có dữ liệu."
fi

exec java -jar app.jar