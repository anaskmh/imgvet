# An intentionally wasteful image used by the e2e test: it installs packages
# without cleaning caches, writes a large file and deletes it in a later
# layer, and overwrites a file — imgvet must flag all of it.
FROM alpine:3.20
RUN apk add curl
RUN dd if=/dev/zero of=/tmp/bigfile bs=1M count=20
RUN rm /tmp/bigfile
RUN echo "v1" > /config.txt
RUN echo "version two" > /config.txt
ENV DB_PASSWORD=hunter2
COPY . .
