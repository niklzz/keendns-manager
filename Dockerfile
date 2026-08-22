FROM python:3.12-slim

# No dependencies to install: the manager is stdlib-only.
WORKDIR /app
COPY keendns.py keendns.html ./
# Build contexts on SMB shares arrive as mode 700; nobody must be able to read them.
RUN chmod 644 keendns.py keendns.html

# Inside the container it must listen on all interfaces; publish the port to
# 127.0.0.1 on the host so the manager is not exposed to the network.
ENV KEENDNS_BIND=0.0.0.0 \
    KEENETIC_HOST=192.168.1.1 \
    KEENETIC_USER=admin \
    PYTHONUNBUFFERED=1

USER nobody
EXPOSE 8765
ENTRYPOINT ["python3", "keendns.py", "--no-browser"]
