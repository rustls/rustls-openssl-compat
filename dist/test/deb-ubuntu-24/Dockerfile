FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt install -y curl nginx
ADD rustls-libssl_*.deb /root
ADD --chown=nobody:nogroup server.cert /
ADD --chown=nobody:nogroup server.key /
ADD ca.cert /root
ADD nginx.conf /etc/nginx/sites-enabled/default
RUN dpkg -i /root/rustls-libssl_*.deb

# nb, this only affects systemd runs, but check it works at least
RUN rustls-libssl-nginx enable

CMD /usr/bin/with-rustls-libssl nginx -g 'daemon off;'
