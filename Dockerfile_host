# The container is run specifying a directory on the host as a container mount. THe config file may then be read from that mount and should contain
# resource specifications (ca, cert, key) that are also located in the mounted directory

FROM ubuntu:latest

COPY tnsrids /usr/local/sbin/

CMD /bin/bash /usr/local/sbin/tnsrids