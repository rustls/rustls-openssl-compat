FROM fedora:40
RUN yum install -y curl nginx
ADD rustls-libssl-*.rpm /root
ADD --chown=nobody:nogroup server.cert /
ADD --chown=nobody:nogroup server.key /
ADD ca.cert /root
ADD nginx.conf /etc/nginx/
RUN yum install -y /root/rustls-libssl-*.rpm

# nb, this only affects systemd runs, but check it works at least
RUN rustls-libssl-nginx enable

CMD /usr/bin/with-rustls-libssl nginx -g 'daemon off;'
