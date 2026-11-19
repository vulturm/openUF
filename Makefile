# Developer entry points. Every target runs inside the Lua 5.1 image built from
# tools/testenv/Dockerfile, so a dev machine needs only podman or docker -- not Lua, not
# luarocks, not the rocks. LOCAL=1 runs on the host instead (Lua 5.1 + rocks on LUA_PATH).
# CI runs these same targets in the same image (.github/workflows/*.yml, ENGINE=docker),
# so the Dockerfile is the one list of what the suite needs and this file the one list
# of what is checked.
#
#   make test       the Lua suite, GCM required (as CI runs it)
#   make verify     tools/dist.sh --verify: strip, compare bytecode, rerun the suite
#   make dist       the release tarball only
#   make sh-check   bash -n and dash -n on every shipped shell script
#   make simulate   adoption round-trip against tools/test_controller.py
#   make ci         all of the above, in CI's order
#   make rrb-compat tools/rrb-unifi-compat.sh (ARGS=--bump to move the pin)
#   make deps-update   move the rrb-unifi pin to the latest release that passes both suites
#   make deps-check HOST="ip ..."   on the APs: upgradable dependency packages, rrb-unifi vs pin
#   make deps-deploy HOST="ip ..."  upgrade them and install the pinned rrb-unifi (tools/deps.sh)
#   make release-archive VERSION=x.y.z
#   make shell      an interactive shell in the image
#   make image      (re)build the image; every other target does this when it is missing

ENGINE ?= $(shell command -v podman 2>/dev/null || command -v docker 2>/dev/null)
DOCKERFILE := tools/testenv/Dockerfile
# Tagged by the Dockerfile's content: editing it builds a fresh image, no stamp file.
IMAGE := openuf-testenv:$(shell sha256sum $(DOCKERFILE) | cut -c1-12)

# podman (rootless) maps the caller to the container's root and back with keep-id;
# docker needs --user, or build/ and openuf.tar.gz come out owned by root. :z relabels
# the mount for SELinux (Fedora), and is ignored where SELinux is off.
ifneq ($(findstring podman,$(ENGINE)),)
USERFLAGS := --userns=keep-id
else
USERFLAGS := --user $(shell id -u):$(shell id -g)
endif

# In a git worktree .git is a file naming a directory under the main checkout, outside
# the mount, and dist.sh's `git describe` stamped BUILD "unknown" (the first deploy from
# a worktree). Mount that directory too, at its own path, when it is not under the tree.
# :z (shared), not :Z, because two trees' containers may label the same .git.
GIT_COMMON := $(shell git rev-parse --path-format=absolute --git-common-dir 2>/dev/null)
GITMOUNT := $(if $(GIT_COMMON),$(if $(filter $(CURDIR)/%,$(GIT_COMMON)),,-v $(GIT_COMMON):$(GIT_COMMON):z))

ifeq ($(LOCAL),1)
RUN := sh -c
ENSURE :=
else
RUN := $(ENGINE) run --rm $(if $(filter shell,$(MAKECMDGOALS)),-it) $(USERFLAGS) \
	-v $(CURDIR):/src:z $(GITMOUNT) -w /src -e OPENUF_REQUIRE_GCM=1 $(IMAGE) sh -c
ENSURE := ensure-image
endif

# Every shipped shell script, checked by BOTH bash -n and dash -n: the device runs busybox
# ash, and dash is the strictest POSIX shell available here -- it catches bashisms bash -n
# accepts. Globs, not a hand list, so a new hook or uci-defaults script is covered without
# anyone remembering to add it (CI's own list had drifted to name a deleted openuf-rrb.sh).
SH_SCRIPTS := setup.sh install.sh update.sh \
	$(wildcard tools/*.sh) $(wildcard openuf/hook/*.sh) openuf/etc/init.d/openuf \
	package/openuf/test.sh \
	$(wildcard package/luci-app-openuf/root/etc/uci-defaults/*) \
	$(wildcard package/luci-theme-halo/root/etc/uci-defaults/*)

.PHONY: test verify dist sh-check simulate ci rrb-compat deps-update deps-check deps-deploy release-archive shell image ensure-image

test: $(ENSURE)
	$(RUN) 'OPENUF_REQUIRE_GCM=1 lua tests/run_tests.lua'

# dist.sh's own exit status is the verdict: never pipe it (CLAUDE.md, "Shell code").
verify: $(ENSURE)
	$(RUN) 'sh tools/dist.sh --verify'

dist: $(ENSURE)
	$(RUN) 'sh tools/dist.sh'

sh-check: $(ENSURE)
	$(RUN) 'set -e; for f in $(SH_SCRIPTS); do bash -n "$$f"; dash -n "$$f"; done; \
		echo "shell syntax OK: $(words $(SH_SCRIPTS)) scripts, bash and dash"'

simulate: $(ENSURE)
	$(RUN) 'sh tools/simulate.sh --adopt && sh tools/simulate.sh'

ci: sh-check test simulate verify

# Needs the network: fetches d-malinowski's latest rrb-unifi release.
rrb-compat: $(ENSURE)
	$(RUN) 'sh tools/rrb-unifi-compat.sh $(ARGS)'

# The latest rrb-unifi that is known to work: the compat check, and the pin moved
# (setup.sh, the test fixture) only when it passes. Review and commit the result.
deps-update: $(ENSURE)
	$(RUN) 'sh tools/rrb-unifi-compat.sh --bump'

# On the host, not in the image: ssh needs this machine's keys (deploy.sh does the same).
deps-check:
	@test -n "$(HOST)" || { echo 'HOST="<ap-ip> [ap-ip...]" is required'; exit 1; }
	sh tools/deps.sh --check $(HOST)

deps-deploy:
	@test -n "$(HOST)" || { echo 'HOST="<ap-ip> [ap-ip...]" is required'; exit 1; }
	sh tools/deps.sh $(HOST)

# The release workflow's source archive: make release-archive VERSION=1.2.3
release-archive: $(ENSURE)
	@test -n "$(VERSION)" || { echo "VERSION=<x.y.z> is required"; exit 1; }
	$(RUN) 'sh tools/release-archive.sh $(VERSION)'

shell: $(ENSURE)
	$(RUN) 'exec bash'

image:
	@test -n "$(ENGINE)" || { echo "podman or docker is required (or LOCAL=1)"; exit 1; }
	$(ENGINE) build -t $(IMAGE) -f $(DOCKERFILE) tools/testenv

ensure-image:
	@test -n "$(ENGINE)" || { echo "podman or docker is required (or LOCAL=1)"; exit 1; }
	@$(ENGINE) image inspect $(IMAGE) >/dev/null 2>&1 || $(MAKE) --no-print-directory image
