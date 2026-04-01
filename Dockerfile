FROM --platform=${BUILDPLATFORM} alpine:edge AS builder

RUN apk add --no-cache mise build-base mimalloc

ENV PATH="$PATH:/mise/shims"
ENV MISE_DATA_DIR=/mise
ENV MISE_CONFIG_DIR=/mise
ENV MISE_CACHE_DIR=/cache/mise
ENV MISE_ALWAYS_KEEP_DOWNLOAD=true
ENV MISE_TRUSTED_CONFIG_PATHS=/

WORKDIR /
ADD mise.toml mise.toml
RUN --mount=type=cache,target=${MISE_CACHE_DIR} \
  --mount=type=cache,target=${MISE_DATA_DIR}/downloads \
  --mount=type=cache,target=/root/.rustup \
  --mount=type=cache,target=/root/.cargo/git/db \
  --mount=type=cache,target=/root/.cargo/registry \
  mise install && \
  rustup target add aarch64-unknown-linux-musl x86_64-unknown-linux-musl \
  aarch64-unknown-linux-gnu x86_64-unknown-linux-gnu

WORKDIR /build
RUN --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
  --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
  --mount=type=cache,target=/build/target/ \
  --mount=type=cache,target=/root/.rustup \
  --mount=type=cache,target=/root/.cargo/git/db \
  --mount=type=cache,target=/root/.cargo/registry \
  cargo fetch --locked

ARG TARGETARCH
ENV TARGETARCH=${TARGETARCH}
WORKDIR /build
RUN --mount=type=bind,source=docker/build.sh,target=docker/build.sh \
  --mount=type=bind,source=src,target=src \
  --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
  --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
  --mount=type=cache,target=/build/target/ \
  --mount=type=cache,target=/root/.rustup \
  --mount=type=cache,target=/root/.cargo/git/db \
  --mount=type=cache,target=/root/.cargo/registry \
  sh docker/build.sh

FROM scratch AS operator

WORKDIR /app
COPY --from=builder /out/static/operator /app/operator

USER 65535:65535
ENTRYPOINT [ "/app/operator" ]
