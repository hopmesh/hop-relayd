# Container image for the Cloud Run relay fleet (path B). Built with the firestore
# feature so the node's durable store is the per-node Firestore mailbox, and served
# over the WebSocket bearer so Cloud Run / the global LB can front it.
#
# Build context is the repo root:
#   docker build -f services/hop-relayd/Dockerfile -t hop-relayd .

FROM rust:1.97.0-bookworm@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073 AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY core ./core
COPY services ./services
COPY examples ./examples
RUN cargo build --release -p hop-relayd --features firestore

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates=20230311+deb12u1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/hop-relayd /usr/local/bin/hop-relayd

# Cloud Run sets $PORT; the relay serves its WebSocket bearer there. HOP_* come
# from the Cloud Run env (see infra/cloud_run.tf). Shell form so $PORT expands.
ENV PORT=8080
CMD hop-relayd \
      --ws 0.0.0.0:${PORT} \
      --firestore ${HOP_FIRESTORE_PROJECT} \
      --identity-file ${HOP_IDENTITY_FILE}
