FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV DB_PATH=/tmp/retroflix.db
EXPOSE 5000

# Inicializa la base de datos (semilla + flags) y levanta el servidor.
CMD ["python", "app.py"]
