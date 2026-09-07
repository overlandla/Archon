# Immutable reference toolchain used by controlled conformance, not an installer
# for the operator's existing Archon/GitHub/Codex/Telegram service.
FROM mcr.microsoft.com/playwright@sha256:6446946a1d9fd62d9ae501312a2d76a43ee688542b21622056a372959b65d63d
COPY --chmod=0555 worker /runtime/worker
COPY --chmod=0555 codex /runtime/codex
COPY --chmod=0444 gateway.py oci_gateway.py git_gateway.py /runtime/
RUN mkdir -p /home/worker/.codex /broker /input /workspace /state /runtime/empty-template \
    && chmod 0555 /runtime /home/worker /home/worker/.codex /broker /input
USER 65532:65532
ENV HOME=/home/worker CODEX_HOME=/home/worker/.codex ARCHON_HOME=/state
ENTRYPOINT ["/usr/bin/python3", "-I", "/runtime/oci_gateway.py"]
