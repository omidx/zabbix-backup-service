# Companion utility image for Docker deployments whose database image does not
# include mysqlbinlog (including Docker Official mysql:8.4 server-minimal).
#
# Keep this image client-only so it does not conflict with server-minimal
# packages from the database image.
FROM oraclelinux:9-slim

RUN microdnf install -y ca-certificates curl \
    && microdnf clean all \
    && curl -fsSL https://repo.mysql.com/RPM-GPG-KEY-mysql-2025 \
       -o /etc/pki/rpm-gpg/RPM-GPG-KEY-mysql-2025 \
    && { \
         echo '[mysql-8.4-lts-community]'; \
         echo 'name=MySQL 8.4 LTS Community'; \
         echo 'baseurl=https://repo.mysql.com/yum/mysql-8.4-community/el/9/$basearch/'; \
         echo 'enabled=1'; \
         echo 'gpgcheck=1'; \
         echo 'gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-mysql-2025'; \
         echo 'module_hotfixes=true'; \
       } > /etc/yum.repos.d/mysql-community.repo \
    && microdnf install -y mysql-community-client \
    && microdnf clean all \
    && mysqlbinlog --version
