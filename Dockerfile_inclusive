# All of the resources required by tnsrids are copied to the container from the directory in which the docker build command is run.
 
FROM ubuntu:latest

COPY tnsrids /usr/local/sbin/
COPY tnsrids.conf /etc/tnsrids/
COPY ca.crt /etc/tnsrids/.tls/
COPY tnsr.crt /etc/tnsrids/.tls/
COPY tnsr.key /etc/tnsrids/.tls/

# CMD ["/tnsrids"]