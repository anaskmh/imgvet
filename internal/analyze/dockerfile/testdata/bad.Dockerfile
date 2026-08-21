FROM ubuntu
ENV API_KEY=supersecret123
RUN apt-get update && apt-get install -y gcc make curl
RUN pip install requests
ADD app.py /app/app.py
COPY . .
RUN make build
