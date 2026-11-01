FROM docker.io/library/almalinux@sha256:7b72041988f07ef5020f7f5da036a9aad9165d996d02946bce29c9a38e99ba59
# Only the small compiler environment is an image layer. vcpkg, downloads,
# source trees, Go caches, TMPDIR and compiler products are bind-mounted /home.
# The prepared SDK, native lock and patches remain in the read-only /source
# mount; no project dependency sources are copied into image layers.
COPY repositories.repo /etc/yum.repos.d/flexmodule-pinned.repo
RUN set -eu; \
    for item in \
      BaseOS:723b20c4ccba9794afd8db85a28aff88d1f5ae3c5daaf83b00008275c6c75fdf \
      AppStream:7b3ec4bd8ed70cd91fb54ff1dae82484a92947caba5b103876a0e63c745515c0 \
      CRB:90cbbf8c7395ba2d05c141c838aa7a675b97330a19cd427a49fd1ff42305daeb; do \
      repo=${item%%:*}; hash=${item#*:}; \
      curl --fail --location --proto '=https' "https://repo.almalinux.org/vault/9.7/$repo/x86_64/os/repodata/repomd.xml" -o /tmp/repomd.xml; \
      echo "$hash  /tmp/repomd.xml" | sha256sum -c -; \
    done; \
    dnf -y --disablerepo='*' --enablerepo='flexmodule-*' --setopt=install_weak_deps=False install \
      python3 gcc gcc-c++ glibc-devel git cmake ninja-build make nasm perl tar gzip unzip zip patch pkgconf-pkg-config diffutils autoconf automake libtool; \
    mkdir -p /opt/flexmodule-builder; \
    rpm -qa --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n' | sort > /opt/flexmodule-builder/packages.txt; \
    cp /etc/yum.repos.d/flexmodule-pinned.repo /opt/flexmodule-builder/; \
    dnf clean all; rm -f /tmp/repomd.xml
