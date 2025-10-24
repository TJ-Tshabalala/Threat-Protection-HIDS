FROM python:3.11-slim
RUN addgroup --system hids && adduser --system --ingroup hids hids
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . /app
RUN chown -R hids:hids /app
USER hids
EXPOSE 8000
ENV LOG_DIR=/app/logs
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
