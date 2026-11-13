FROM python:3.12-slim
WORKDIR /app
# libpst's readpst powers PST/OST extraction (app/parsers.py)
RUN apt-get update && apt-get install -y --no-install-recommends pst-utils \
    && rm -rf /var/lib/apt/lists/*
# Tầng ML (tùy chọn): bỏ comment nếu muốn chạy model.onnx trong container
# RUN pip install --no-cache-dir onnxruntime==1.19.2
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PORT=8000
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
