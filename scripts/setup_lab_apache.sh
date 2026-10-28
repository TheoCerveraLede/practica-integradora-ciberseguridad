#!/bin/bash
# ==============================================================================
# SCRIPT DE REPRODUCCIÓN DEL LABORATORIO DEFENSIVO: APACHE 2.4.49 (CVE-2021-41773)
# Entorno: Kali Linux (Debian 64-bit)
# Autores: Theo Cervera, Ale Modica - Comisión 1
# ==============================================================================
set -e

echo "[+] 1. Creando archivo sensible de prueba fuera de DocumentRoot..."
sudo mkdir -p /opt/laboratorio_ypf
echo "CONTRASENIA_INVENTADA=YPF_Comision1_Segura_2026" | sudo tee /opt/laboratorio_ypf/clave_inventada.txt >/dev/null
sudo chmod 755 /opt/laboratorio_ypf
sudo chmod 644 /opt/laboratorio_ypf/clave_inventada.txt

echo "[+] 2. Instalando dependencias de compilación para Apache..."
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    libapr1-dev libaprutil1-dev libpcre3-dev libexpat1-dev gcc make wget curl

echo "[+] 3. Descargando y compilando Apache HTTP Server 2.4.49..."
mkdir -p ~/laboratorio_apache && cd ~/laboratorio_apache
if [ ! -f httpd-2.4.49.tar.gz ]; then
    wget -q https://archive.apache.org/dist/httpd/httpd-2.4.49.tar.gz
fi
tar -xzf httpd-2.4.49.tar.gz
cd httpd-2.4.49
./configure --prefix=/opt/apache-2.4.49 --enable-cgid --enable-cgi --quiet
make -j$(nproc) -s
sudo make install -s

echo "[+] 4. Configurando Apache 2.4.49 en puertos 80 y 8080 con directiva de prueba..."
sudo cp /opt/apache-2.4.49/conf/original/httpd.conf /opt/apache-2.4.49/conf/httpd.conf
sudo sed -i "s/^Listen 80$/Listen 80\nListen 8080/" /opt/apache-2.4.49/conf/httpd.conf
sudo sed -i "s/^#ServerName www.example.com:80$/ServerName 127.0.0.1:80/" /opt/apache-2.4.49/conf/httpd.conf
sudo sed -i "/^<Directory \/>/,/^<\/Directory>/ s/Require all denied/Require all granted/" /opt/apache-2.4.49/conf/httpd.conf

# Permisos para el usuario daemon / www-data
sudo chmod 755 /opt /opt/apache-2.4.49 /opt/apache-2.4.49/htdocs /opt/apache-2.4.49/logs
sudo chmod 644 /opt/apache-2.4.49/htdocs/index.html

echo "[+] 5. Creando subcarpeta pública permitida..."
sudo mkdir -p /opt/apache-2.4.49/htdocs/publico
echo "Archivo publico permitido en DocumentRoot (/opt/apache-2.4.49/htdocs/publico/aviso.txt)" | sudo tee /opt/apache-2.4.49/htdocs/publico/aviso.txt >/dev/null
sudo chmod 644 /opt/apache-2.4.49/htdocs/publico/aviso.txt

echo "[+] 6. Iniciando Apache 2.4.49..."
sudo /opt/apache-2.4.49/bin/apachectl restart

echo "[✓] Laboratorio montado exitosamente."
echo "    - Web: http://127.0.0.1:8080/ o http://127.0.0.1/"
echo "    - Archivo objetivo local: /opt/laboratorio_ypf/clave_inventada.txt"
