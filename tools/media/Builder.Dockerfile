FROM docker.io/library/debian@sha256:1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d
ADD --chmod=0644 --checksum=sha256:ed56aac47e7911e65ee63aae8d67e29f20e023f840e49f8ed037043a33de138a https://snapshot.debian.org/archive/debian/20261028T000000Z/dists/trixie/Release /opt/flexmodule-builder/Release
ADD --chmod=0644 --checksum=sha256:01476fcf0edacd5675787aa3b5c2003099f0ed3dee76bbb8632b4b8cf80a2e00 https://snapshot.debian.org/archive/debian-security/20261028T000000Z/dists/trixie-security/Release /opt/flexmodule-builder/security-Release
RUN set -eu; \
    rm -f /etc/apt/sources.list.d/debian.sources; \
    printf '%s\n' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/20261028T000000Z trixie main' \
      'deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/20261028T000000Z trixie-security main' \
      > /etc/apt/sources.list; \
    apt-get update; \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build pkg-config nasm git ca-certificates python3 unzip xz-utils \
      libssl-dev=3.5.7-1~deb13u3 libssl3t64=3.5.7-1~deb13u3 openssl-provider-legacy=3.5.7-1~deb13u3; \
    dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' > /opt/flexmodule-builder/packages.txt; \
    cp /etc/apt/sources.list /opt/flexmodule-builder/sources.list; \
    chmod 0755 /opt/flexmodule-builder; \
    chmod 0644 /opt/flexmodule-builder/Release /opt/flexmodule-builder/security-Release \
      /opt/flexmodule-builder/packages.txt /opt/flexmodule-builder/sources.list; \
    ln -s /work/install /opt/flexmodule; \
    rm -rf /var/lib/apt/lists/*
