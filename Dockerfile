# do analysis of app and create recipe file
#stage -1 generate recipie for dependencies
FROM rust as planner
WORKDIR /app
RUN cargo install cargo-chef
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# stage - 2 -build our dependencies
FROM rust as cacher
WORKDIR /app
RUN cargo install cargo-chef
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json

#stage 3

# use official rust docker image as builder
FROM rust as builder

# Create appuser
ENV USER=web
ENV UID=1001

RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

# copy the app into the docker image
COPY . /app

# set work working directory
WORKDIR /app

# Copy dependencies
COPY --from=cacher /app/target target
# all dependencies have been pre-built
COPY --from=cacher /usr/local/cargo /usr/local/cargo

# build the app
RUN cargo build --release

# second stage
# use google distroless as runtime image
FROM gcr.io/distroless/cc-debian11

# Import from builder.
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# copy app from builder
COPY --from=builder /app/target/release/carbonadod /app/carbonadod
WORKDIR /app

USER web:web
# start the app
CMD ["./carbonadod"]
