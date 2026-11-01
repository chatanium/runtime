# Keep this public trust source aligned with tools/native/native-lock.json.
FROM docker.io/library/almalinux@sha256:7b72041988f07ef5020f7f5da036a9aad9165d996d02946bce29c9a38e99ba59 AS trust

FROM scratch
# Copy the extracted PEM file, not the distro's ca-bundle.crt symlink.
# This is a standard Go crypto/x509 system-root path.
# Preserve its source mode; --chmod would also remove parent traversal.
COPY --from=trust /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem
COPY --chmod=0555 module /opt/flexmodule/module
COPY manifest.json /opt/flexmodule/manifest.json
USER 65532:65532
WORKDIR /opt/flexmodule
ENTRYPOINT ["/opt/flexmodule/module"]
