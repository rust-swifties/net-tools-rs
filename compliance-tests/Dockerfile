FROM rust:1-trixie

RUN apt-get update && apt-get install -y \
    net-tools \
    iproute2

WORKDIR /workspace
COPY . /workspace/

RUN cargo build --release

RUN chmod +x compliance-tests/tests/*.sh
WORKDIR /workspace/compliance-tests

CMD ["./run-tests.sh"]
