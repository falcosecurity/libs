FROM debian:buster

WORKDIR /tests
ENV CONTAINERIZED=1

RUN mkdir -p /logs && \
    apt-get update && \
    apt-get install -y python3 \
    python3-pip \
    curl \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Install docker CLI
RUN mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg && \
    echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
        $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null && \
    apt-get update && \
    apt-get install -y docker-ce-cli

COPY /tests/requirements.txt /tests/
RUN pip3 install -r /tests/requirements.txt

COPY /tests/commons/ /tests/commons/
RUN pip3 install /tests/commons/

COPY /tests/test_* /tests/
COPY /tests/conftest.py /tests/conftest.py

# TODO: tagging for containers built on PRs
ARG SINSP_TAG=latest
ENV SINSP_TAG=${SINSP_TAG}

ENTRYPOINT [ "pytest", "--html=/report/report.html" ]
