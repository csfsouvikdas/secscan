FROM python:3.12-slim
COPY pyproject.toml README.md /opt/secscan/
COPY src /opt/secscan/src
RUN pip install --no-cache-dir /opt/secscan && useradd -m scanner
USER scanner
WORKDIR /src
ENTRYPOINT ["secscan"]
CMD ["."]
