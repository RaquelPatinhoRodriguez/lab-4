#!/bin/bash
sudo mkdir -p /var/www/html/health
echo "OK" | sudo tee /var/www/html/health/healthcheck.html
# Instala el paquete nfs-utils si es necesario para montar EFS
yum install -y nfs-utils

# Crea el directorio de montaje y monta el sistema de archivos EFS en /mnt/efs
mkdir -p /mnt/efs
sudo mount -t nfs4 fs-${aws_efs_file_system.terrafom_efs.id}.efs.us-east-1.amazonaws.com:/ /mnt/efs

# Agrega la entrada a /etc/fstab para que se monte automáticamente al reiniciar
echo "fs-${aws_efs_file_system.terrafom_efs.id}.efs.us-east-1.amazonaws.com:/ /mnt/efs nfs4 _netdev,tls 0 0" >> /etc/fstab