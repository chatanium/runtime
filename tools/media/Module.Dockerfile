ARG MEDIA_BASE
FROM ${MEDIA_BASE}
COPY --chmod=0555 module /opt/flexmodule/module
COPY manifest.json /opt/flexmodule/manifest.json
USER 65532:65532
WORKDIR /opt/flexmodule
ENTRYPOINT ["/opt/flexmodule/module"]
