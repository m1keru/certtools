FROM centos:7

MAINTAINER tyurin@m1ke.ru

#LABELS
LABEL version="1.10"
LABEL purpose="certbot"

#YUM
RUN yum -y update --nogpgcheck
RUN yum -y install yum-utils
RUN yum -y install epel-release --nogpgcheck
RUN yum -y install wget git vim rsync ntpdate lsb openmotif22 make sudo glibc.i686 \                     
        --nogpgcheck

#LOCALE
RUN localedef  -i ru_RU -f UTF-8 ru_RU.UTF-8 && echo "export LANG=ru_RU.UTF-8" >> /etc/bashrc



#CRYPTOPRO
ADD ./cryptopro/rpm/linux-amd64.tar.gz /tmp/
RUN cd /tmp/linux-amd64 && ./install.sh && \
sed -ie 's#^.*libcurl.so.*$#"libcurl\.so"="/usr/lib64/libcurl\.so\.4"#' /etc/opt/cprocsp/config64.ini

#CERTBOT
ADD ./build/certbot /opt/

ENTRYPOINT ["/opt/certbot","--daemon","--forceupdate","--list=/ucs_grabbed.list"]
