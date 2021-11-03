# Program builder
FROM rust:1.56.1-slim-buster as BUILDER
RUN apt update && apt install -y \
    musl-tools \
    pkgconf

RUN rustup target add x86_64-unknown-linux-musl

COPY ./src /usr/src/authlander/src/
COPY ./Cargo.toml /usr/src/authlander
WORKDIR /usr/src/authlander/
RUN cargo build --release --target x86_64-unknown-linux-musl

# Runtime image
FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=BUILDER /usr/src/authlander/target/x86_64-unknown-linux-musl/release/authlander /usr/local/bin/authlander
COPY ./log4rs.yaml /usr/local/bin/
COPY ./templates /usr/local/bin/templates/

RUN chmod a+rx /usr/local/bin/*
RUN adduser authlander -s /bin/false -D -H
USER authlander
EXPOSE 8080
WORKDIR /usr/local/bin
ENTRYPOINT [ "/usr/local/bin/authlander" ]