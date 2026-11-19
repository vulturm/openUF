# The suite's environment, as CI builds it (.github/workflows/test.yml): Lua 5.1, the
# device's interpreter, so code a newer Lua accepts and the APs reject fails here too.
# `make test` builds this image once (its tag is a hash of this file) and runs the tree
# mounted at /src. CI runs the same targets in the same image, so this file is the one
# list of what the suite needs.
#
# pycryptodome from pip, not apt's python3-pycryptodome: that ships the Cryptodome
# namespace and test_controller.py imports Crypto.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
	&& apt-get install -y --no-install-recommends \
		lua5.1 liblua5.1-dev lua-bitop lua-socket luarocks \
		openssl libssl-dev gcc libc6-dev make git curl ca-certificates \
		dash python3 python3-pip \
	&& ln -sf /usr/bin/lua5.1 /usr/local/bin/lua \
	&& luarocks --lua-version 5.1 install lua-cjson LUA_INCDIR=/usr/include/lua5.1 \
	&& luarocks --lua-version 5.1 install openssl LUA_INCDIR=/usr/include/lua5.1 \
	&& pip3 install --break-system-packages pycryptodome \
	&& rm -rf /var/lib/apt/lists/* /root/.cache

# The tree is mounted as the caller's uid, which has no home in the image.
ENV HOME=/tmp
WORKDIR /src
