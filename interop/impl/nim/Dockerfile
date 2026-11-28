# syntax=docker/dockerfile:1.5-labs
FROM nimlang/nim:2.2.12 AS builder

WORKDIR /app

COPY .pinned libp2p.nimble nim-libp2p/

RUN --mount=type=cache,target=/var/cache/apt apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates binutils \
    && rm -rf /var/lib/apt/lists/*

# Install lock entries separately to keep Nimble's SAT solver from combining
# each package's current registry metadata into one unsatisfiable graph. Remove
# transitive versions afterward so compilation sees only the locked commits.
RUN set -eu; \
    nimble --nimbleDir:/app/nim-libp2p/nimbledeps install -y redis; \
    while IFS=';' read -r _name uri; do \
      nimble --nimbleDir:/app/nim-libp2p/nimbledeps install -y "$uri"; \
    done < nim-libp2p/.pinned; \
    cut -d'#' -f2 nim-libp2p/.pinned > /tmp/pinned-hashes; \
    for dependency in nim-libp2p/nimbledeps/pkgs2/*; do \
      case "$(basename "$dependency")" in \
        redis-*) continue ;; \
      esac; \
      grep -Fq -f /tmp/pinned-hashes "$dependency/nimblemeta.json" \
        || rm -rf "$dependency"; \
    done

COPY . nim-libp2p/

RUN cd nim-libp2p \
    && nim c -d:release --skipProjCfg --skipParentCfg \
      --NimblePath:./nimbledeps/pkgs2 --mm:refc \
      -d:chronicles_log_level=INFO \
      -d:chronicles_default_output_device=stderr \
      -d:chronicles_colors=None --threads:on \
      -o:/app/perf-interop ./interop/perf/main.nim

FROM debian:trixie-slim AS runtime

COPY --from=builder /app/perf-interop /app/perf-interop

ENTRYPOINT ["/app/perf-interop"]
