FROM rust AS windows-builder

WORKDIR /usr/src/app

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y g++-mingw-w64-x86-64

RUN rustup target add x86_64-pc-windows-gnu

COPY ./src ./src

COPY ./Cargo.lock .
COPY ./Cargo.toml .

CMD ["sleep", "infinity"]