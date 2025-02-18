FROM python:3.9-slim

#Installation des dependences necessaire
RUN apt-get update && apt-get install -y \
    iputils-ping \
    net-tools\
    nmap \
    && rm -rf /var/lib/apt/list/*

#Definition du repertoire de travail
WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir -r requirements.txt

RUN chmod +x astsu.py

# CMD ["python3", "astsu.py", "-h"]
ENTRYPOINT ["python3", "astsu.py"]
