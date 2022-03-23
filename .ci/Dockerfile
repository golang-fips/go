FROM fedora:35

MAINTAINER Daiki Ueno <dueno@redhat.com>

RUN dnf -y update
RUN dnf -y install 'dnf-command(builddep)'
RUN dnf -y builddep golang
RUN dnf -y install gcc-go
RUN dnf clean all
