FROM fedora:41

MAINTAINER Daiki Ueno <dueno@redhat.com>

RUN dnf -y update && \
    dnf -y install 'dnf-command(builddep)' && \
    dnf -y builddep golang && \
    dnf -y install gcc-go openssl-devel && \
    dnf clean all
