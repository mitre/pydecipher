# docker build . -t pydecipher/sbg
# docker run --volume "$(pwd):/bc" pydecipher/sbg 2.7.15

FROM ubuntu

ENV DEBIAN_FRONTEND noninteractive

# Install dependencies and change shell - ubuntu
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends git \
      build-essential \
      curl \
      libbz2-dev \
      libffi-dev \
      liblzma-dev ca-certificates \
      libncurses5-dev \
      libreadline-dev \
      libsqlite3-dev \
      libssl-dev \
      libxml2-dev \
      libxmlsec1-dev \
      llvm \
      make \
      tk-dev \
      wget \
      xz-utils \
      zlib1g-dev && \
    apt-get purge -y libssl-dev && apt-get install -y libssl1.0-dev && \
    rm -rf /var/lib/apt/lists/*
SHELL ["/bin/bash", "-c"]

WORKDIR /root

# Install pyenv
RUN git clone -v https://github.com/pyenv/pyenv.git ./.pyenv
ENV HOME  /root
ENV PYENV_ROOT $HOME/.pyenv
ENV PATH $PYENV_ROOT/shims:$PYENV_ROOT/bin:$PATH
RUN echo -e 'if command -v pyenv 1>/dev/null 2>&1; then\n  eval "$(pyenv init -)"\nfi' >> ~/.bashrc
RUN pyenv install -k 2.7.18
RUN pyenv install -k 3.8.3
RUN pyenv global 3.8.3
RUN pyenv rehash

# Copy in entrypoint
COPY bytecode_producer.py bytecode_producer.py
RUN chmod +x /root/bytecode_producer.py

# Set up container internal output dir
RUN mkdir /bc
ENV BYTECODE_DUMP_DIR /bc

CMD ["-h"]
ENTRYPOINT ["./bytecode_producer.py"]
