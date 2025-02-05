FROM ubuntu
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y nginx libnginx-mod-http-headers-more-filter && \
    apt-get clean

COPY nginx/nginx.conf /etc/nginx/nginx.conf
COPY certs /etc/nginx/certs

CMD ["nginx", "-g", "daemon off;"]