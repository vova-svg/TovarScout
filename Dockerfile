# Dockerfile 
FROM python:3.11-slim
WORKDIR /app
COPY TovarScout.py ./TovarScout.py
COPY requirements.txt ./requirements.txt
COPY secrets.example.json ./secrets.json
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "TovarScout.py"]
