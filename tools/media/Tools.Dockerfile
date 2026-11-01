FROM docker.io/library/debian@sha256:1e1a22175fbf1b32157ddaf0219e1db4e5401fab2b94ed285add64d18587cd2d
COPY rootfs/ /
ENV LD_LIBRARY_PATH=/opt/flexmodule/lib \
    DENO_NO_UPDATE_CHECK=1 \
    DENO_NO_PROMPT=1 \
    DENO_DIR=/var/lib/flexmodule/scratch/deno \
    HOME=/var/lib/flexmodule/scratch
USER 65532:65532
WORKDIR /opt/flexmodule
