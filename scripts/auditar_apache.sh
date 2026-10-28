#!/bin/bash
# =======================================================================
# AUDITORIA COMPARATIVA DE LABORATORIO - CVE-2021-41773 (APACHE)
# Integrantes: Theo Cervera, Ale Modica - Comisión 1
# =======================================================================

echo "======================================================================="
echo " AUDITORIA COMPARATIVA DE LABORATORIO - CVE-2021-41773 (APACHE)"
echo " Integrantes: Theo Cervera, Ale Modica - Comision 1"
echo "======================================================================="
echo ""
echo "[1] Activo sensible de prueba (fuera de la carpeta web):"
echo "    Archivo: /opt/laboratorio_ypf/clave_inventada.txt"
if [ -f /opt/laboratorio_ypf/clave_inventada.txt ]; then
    echo "    Contenido: $(cat /opt/laboratorio_ypf/clave_inventada.txt)"
else
    echo "    [!] Archivo no encontrado. Ejecutar primero setup_lab_apache.sh"
fi
echo ""
echo "[2] Escaneo comparativo de versiones con Nmap (Puerto 80 vs Puerto 8080):"
nmap -sV -p 80,8080 127.0.0.1 | grep -E "PORT|80/tcp|8080/tcp"
echo ""
echo "[3] Auditoria de Configuracion - Servidor VULNERABLE (Apache 2.4.49 - Puerto 8080):"
if [ -f /opt/apache-2.4.49/conf/httpd.conf ]; then
    echo "    Archivo: /opt/apache-2.4.49/conf/httpd.conf"
    grep -n -A 4 "^<Directory />" /opt/apache-2.4.49/conf/httpd.conf
    echo "    -> RIESGO CRITICO: Version 2.4.49 + Require all granted en <Directory />"
fi
echo ""
echo "[4] Auditoria de Configuracion - Servidor MITIGADO (Apache 2.4.68 - Puerto 80):"
if [ -f /etc/apache2/apache2.conf ]; then
    echo "    Archivo: /etc/apache2/apache2.conf"
    grep -n -A 4 "^<Directory />" /etc/apache2/apache2.conf
    echo "    -> ESTADO SEGURO: Version 2.4.68 + Require all denied en <Directory />"
fi
echo ""
echo "[5] Auditoria de Codigo Fuente en httpd-2.4.49/server/util.c (ap_normalize_path):"
if [ -f ~/laboratorio_apache/httpd-2.4.49/server/util.c ]; then
    sed -n "532,541p;570,572p" ~/laboratorio_apache/httpd-2.4.49/server/util.c
fi
echo "======================================================================="
