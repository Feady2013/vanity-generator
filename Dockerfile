# 两阶段构建：vendor 内置依赖 → scratch 静态镜像（约 3.4MB）
# 依赖已全部内置 vendor/（cargo vendor），构建全程零网络下载，
# 适合中国大陆境内封海外网络的机器。
FROM rust:1-slim-bookworm AS builder
RUN rustup target add x86_64-unknown-linux-musl \
    && apt-get update && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
# 全依赖树纯 Rust：musl 目标无需外部 C 工具链（aarch64 除外，本镜像仅 x86_64）
RUN cargo build --release --offline --target x86_64-unknown-linux-musl

FROM scratch
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/vanity-generator /vanity-generator
# 入口即主程序；配置经挂载传入：
#   docker run -v ./config:/config ghcr.io/<owner>/vanity-generator \
#     --config /config/config.yaml
# config.yaml 内 gpg_key_file 用绝对路径 /config/gpg.asc，
# 命中加密产物会落在配置文件所在目录（即挂载的 ./config）。
ENTRYPOINT ["/vanity-generator"]
