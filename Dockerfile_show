# This Dockerfile creates an image that uses tnsrids to print the current firewall ACL list then quit.
# It is useful for testing the Docker configuration

FROM ubuntu:latest

COPY tnsrids /usr/local/sbin/
COPY tnsrids.conf /etc/tnsrids/
COPY ca.crt /etc/tnsrids/.tls/
COPY tnsr.crt /etc/tnsrids/.tls/
COPY tnsr.key /etc/tnsrids/.tls/

CMD ["tnsrids", "-show"]