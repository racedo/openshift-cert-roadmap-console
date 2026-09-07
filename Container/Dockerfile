FROM registry.redhat.io/ubi9/python-311:latest

WORKDIR /opt/app-root/src

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install --no-cache-dir -r /tmp/requirements.txt

COPY app.py .

EXPOSE 8080

CMD ["python3", "app.py"]
