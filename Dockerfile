FROM python:3.11-slim

# 运行时仅使用标准库，无需联网安装任何依赖
WORKDIR /app

COPY app ./app
COPY tests ./tests
COPY verify ./verify
RUN chmod +x ./verify && python3 -m compileall -q app tests

ENV PORT=8080 \
    AUDIT_DB=/data/audits.json \
    PYTHONUNBUFFERED=1

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --retries=10 --start-period=2s \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+__import__('os').environ.get('PORT','8080')+'/healthz').status==200 else 1)"

CMD ["python3", "-m", "app.server"]
