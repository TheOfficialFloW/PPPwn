FROM --platform=amd64 ubuntu:latest
ARG PS4FWVER=1100
RUN apt update && apt install -y build-essential
RUN mkdir /build
COPY . ./build
WORKDIR /build
RUN mkdir /output
RUN make -C stage1 FW=$PS4FWVER clean && make -C stage1 FW=$PS4FWVER && cp stage1/stage1.bin /output
RUN make -C stage2 FW=$PS4FWVER clean && make -C stage2 FW=$PS4FWVER && cp stage2/stage2.bin /output
ENTRYPOINT ["/bin/sh", "-c", "cp -Rvr /output/* /host"]