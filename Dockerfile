FROM python:3.9.2

ENV PYTHONUNBUFFERED 1

WORKDIR /usr/src/app

# Upgrade python pip
RUN pip install --upgrade pip

# Install pydecipher
WORKDIR /usr/src/app
COPY setup.py ./
COPY README.rst ./
COPY pydecipher/ ./pydecipher/
RUN pip install .

WORKDIR /root/
ENTRYPOINT ["pydecipher"]
CMD ["--version"]
