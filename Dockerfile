FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p kestreld

FROM debian:bookworm-slim
COPY --from=build /src/target/release/kestreld /usr/local/bin/kestreld
EXPOSE 7777
ENTRYPOINT ["kestreld"]
