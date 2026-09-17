FROM alpine:3.20 AS openssl_builder

# we have to build the fips module from 3.0.9
# see https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4282
RUN <<HEREDOC
    apk add --no-cache --virtual .build-deps make gcc libgcc musl-dev linux-headers perl vim
    wget https://www.openssl.org/source/openssl-3.0.9.tar.gz
    tar -xf openssl-3.0.9.tar.gz
    cd openssl-3.0.9
    ./Configure enable-fips --libdir=lib --prefix=/usr
    make
    make install_fips
    apk del .build-deps
    cd ..
    rm -rf openssl-3.0.9.tar.gz openssl-3.0.9
HEREDOC


FROM golang:1.22.5-alpine3.20 AS golang_patcher

RUN <<HEREDOC
    apk add --no-cache git bash
    git clone -b go1.22.5-3-openssl-fips --depth=1 https://github.com/golang-fips/go.git
    git config --global user.email "gopatcher@ory.sh"
    git config --global user.name "gopatcher"
    cd go
    ./scripts/full-initialize-repo.sh
    cd go/src
    ./make.bash
HEREDOC


FROM openssl_builder AS crypto_test

ENV GOLANG_FIPS=1

COPY --from=golang_patcher /go/go/ /tmp/go
RUN <<HEREDOC
    apk add --no-cache -U openssl
    openssl fipsinstall -out /usr/ssl/fipsmodule.cnf -module /usr/lib/ossl-modules/fips.so
    sed -i "s/# .include fipsmodule.cnf/.include \/usr\/ssl\/fipsmodule.cnf/g" /etc/ssl/openssl.cnf
    sed -i "s/# fips = fips_sect/fips = fips_sect/g" /etc/ssl/openssl.cnf
    sed -i "s/# activate = 1/activate = 1/g" /etc/ssl/openssl.cnf
    sed -i "/providers = provider_sect/aalg_section = algorithm_sect\n\n[algorithm_sect]\ndefault_properties = fips=yes" /etc/ssl/openssl.cnf
    openssl list -providers -provider fips -provider base
    apk add --no-cache bash
    cd /tmp/go
    ./scripts/configure-crypto-tests.sh
    ./scripts/crypto-test.sh
HEREDOC


FROM openssl_builder AS hydra_builder

ENV GOLANG_FIPS=1

COPY --from=golang_patcher /go/go/go /usr/local/go
RUN <<HEREDOC
    apk add --no-cache --upgrade git
    cd /
    git clone -b v2.3.0 --depth=1 https://github.com/ory/hydra.git
HEREDOC
WORKDIR /hydra
RUN /usr/local/go/bin/go build


FROM openssl_builder AS final

ENV GOLANG_FIPS=1

RUN apk upgrade --no-cache -U

RUN <<HEREDOC
    apk add --no-cache --upgrade ca-certificates

    # Add a user/group for nonroot with a stable UID + GID. Values are from nonroot from distroless
    # for interoperability with other containers.
    addgroup --system --gid 65532 nonroot
    adduser --system --uid 65532 \
      --gecos "nonroot User" \
      --home /home/nonroot \
      --ingroup nonroot \
      --shell /sbin/nologin \
      nonroot
HEREDOC

RUN <<HEREDOC
    apk add --no-cache -U openssl
    openssl fipsinstall -out /usr/ssl/fipsmodule.cnf -module /usr/lib/ossl-modules/fips.so
    sed -i "s/# .include fipsmodule.cnf/.include \/usr\/ssl\/fipsmodule.cnf/g" /etc/ssl/openssl.cnf
    sed -i "s/# fips = fips_sect/fips = fips_sect/g" /etc/ssl/openssl.cnf
    sed -i "s/# activate = 1/activate = 1/g" /etc/ssl/openssl.cnf
    sed -i "/providers = provider_sect/aalg_section = algorithm_sect\n\n[algorithm_sect]\ndefault_properties = fips=yes" /etc/ssl/openssl.cnf
    openssl list -providers -provider fips -provider base
HEREDOC

COPY --from=hydra_builder /hydra/hydra /usr/bin/hydra

USER nonroot

ENTRYPOINT ["/usr/bin/hydra"]
CMD ["serve", "all"]
