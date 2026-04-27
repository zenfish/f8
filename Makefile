# f8 — install, test, and clean
#
# Default target is `help` so `make` with no args is harmless. Run any of:
#
#   make help              Show this help.
#   make install           Install Node deps in server/, create ~/.f8/config
#                          and ~/traces, symlink tools into $(LINK_DIR), and
#                          report SIP DTrace status.
#   make install-no-link   Same as install, but skip the symlink step. Use
#                          when /usr/local/bin isn't writable and you'd
#                          rather just add this directory to your PATH.
#   make test              Run the full pytest suite (no root needed).
#   make test-unit         Unit tests only.
#   make test-cov          Tests with coverage report.
#   make test-e2e          End-to-end tests (requires sudo).
#   make verify            Sanity-check syscall categories / colors.
#   make clean             Remove in-tree artifacts (pytest cache, coverage,
#                          server/node_modules). Run `make install` to put
#                          them back.
#   make uninstall         clean + remove the symlinks `make install` left
#                          in $(LINK_DIR) (only those still pointing into
#                          this tree). Does NOT touch ~/.f8 or ~/traces --
#                          those are user data.
#
# Variables you can override on the command line:
#
#   LINK_DIR=/usr/local/bin    Where to put / look for symlinks.
#   F8_HOME=$$HOME/.f8         Config directory created by `install`.
#   TRACES_DIR=$$HOME/traces   Default trace output directory.

.DEFAULT_GOAL := help
.PHONY: help install install-no-link deps config link sip-check \
        test test-unit test-cov test-e2e verify clean uninstall

LINK_DIR   ?= /usr/local/bin
F8_HOME    ?= $(HOME)/.f8
TRACES_DIR ?= $(HOME)/traces
TOOLS      := f8 f8_analyze f8_timeline f8_import f8_server f8_data f8_open f8_run_all.sh

help:
	@awk 'NR==1{next} /^#/{sub(/^# ?/,""); print; next} {exit}' Makefile

# ── install ────────────────────────────────────────────────────────
# Folds the old install.sh into make targets so there's a single
# install/uninstall surface. Each sub-target is independently runnable
# (`make deps`, `make config`, `make link`, `make sip-check`).

install: deps config link sip-check
	@echo ""
	@echo "=== Done ==="
	@echo ""
	@echo "Quick test:"
	@echo "  sudo f8 -o test.json -jp echo hello"
	@echo ""
	@echo "Then view in browser:"
	@echo "  f8_import test.json && f8_server"
	@echo "  -> http://localhost:3000"

install-no-link: deps config sip-check
	@echo ""
	@echo "Symlink step skipped. Add this directory to your PATH:"
	@echo "  export PATH=\"$$(pwd):\$$PATH\""

deps:
	@echo "1. Installing Node.js dependencies..."
	@if command -v node >/dev/null 2>&1; then \
	    ( cd server && npm install --omit=dev 2>&1 | tail -3 ); \
	    echo "   server/node_modules installed"; \
	else \
	    echo "   WARNING: Node.js not found -- server/import won't work until you install Node 20+"; \
	fi

config:
	@echo ""
	@echo "2. Setting up config..."
	@mkdir -p "$(F8_HOME)" "$(TRACES_DIR)"
	@if [ -f "$(F8_HOME)/config" ]; then \
	    echo "   $(F8_HOME)/config already exists (not overwriting)"; \
	else \
	    { \
	        echo '# f8 configuration'; \
	        echo '# See ENVIRONMENT.md for full syntax (supports ~, $$VAR expansion, comments)'; \
	        echo ''; \
	        echo 'F8_HOME=~/.f8'; \
	        echo 'F8_OUTPUT=~/traces'; \
	        echo 'F8_DB=$$F8_HOME/f8.db'; \
	    } > "$(F8_HOME)/config"; \
	    echo "   created $(F8_HOME)/config"; \
	fi
	@echo "   trace output directory: $(TRACES_DIR)"

link:
	@echo ""
	@echo "3. PATH setup..."
	@SCRIPT_DIR="$$(pwd)"; \
	if command -v f8 >/dev/null 2>&1; then \
	    EXISTING=$$(command -v f8); \
	    RESOLVED=$$(readlink -f "$$EXISTING" 2>/dev/null || echo "$$EXISTING"); \
	    if [ "$$RESOLVED" = "$$SCRIPT_DIR/f8" ]; then \
	        echo "   f8 already on PATH ($$EXISTING)"; \
	    else \
	        echo "   WARNING: f8 found at $$EXISTING (different location)"; \
	        echo "     To use this installation, add to your shell config:"; \
	        echo "     export PATH=\"$$SCRIPT_DIR:\$$PATH\""; \
	    fi; \
	elif [ -d "$(LINK_DIR)" ] && [ -w "$(LINK_DIR)" ]; then \
	    for tool in $(TOOLS); do \
	        if [ -x "$$SCRIPT_DIR/$$tool" ]; then \
	            ln -sf "$$SCRIPT_DIR/$$tool" "$(LINK_DIR)/$$tool"; \
	        fi; \
	    done; \
	    echo "   symlinked tools to $(LINK_DIR)"; \
	else \
	    echo "   $(LINK_DIR) not writable. Either:"; \
	    echo "     a) Add to PATH (in ~/.zshrc or ~/.bashrc):"; \
	    echo "          export PATH=\"$$SCRIPT_DIR:\$$PATH\""; \
	    echo "     b) Re-run with sudo:"; \
	    echo "          sudo make install"; \
	fi

sip-check:
	@echo ""
	@echo "4. Checking SIP status..."
	@if csrutil status 2>/dev/null | grep -qi "dtrace restrictions disabled"; then \
	    echo "   DTrace restrictions disabled -- full tracing available"; \
	elif csrutil status 2>/dev/null | grep -qi "disabled"; then \
	    echo "   SIP disabled -- full tracing available"; \
	else \
	    echo "   WARNING: SIP DTrace restrictions appear to be ENABLED"; \
	    echo "     f8 requires DTrace access. To disable just the DTrace"; \
	    echo "     restriction (not all of SIP):"; \
	    echo "       1. Reboot into Recovery Mode (hold power on Apple Silicon)"; \
	    echo "       2. Open Terminal from the Utilities menu"; \
	    echo "       3. csrutil enable --without dtrace"; \
	    echo "       4. Reboot"; \
	fi

# ── tests ──────────────────────────────────────────────────────────

test:
	python3 -m pytest tests/ -v

test-unit:
	python3 -m pytest tests/unit/ -v

test-cov:
	python3 -m pytest tests/ -v --cov=. --cov-report=term-missing \
		--cov-config=.coveragerc

test-e2e:
	@echo "E2E tests require sudo and will trace real programs."
	sudo python3 -m pytest tests/e2e/ -v

verify:
	python3 f8_categories.py --verify

# ── clean / uninstall ──────────────────────────────────────────────
# clean: in-tree only. Removes everything `make install` and the test
# suite produced inside this checkout. Does NOT touch ~/.f8, ~/traces,
# or symlinks in $(LINK_DIR) (those are user-owned / out-of-tree --
# use `make uninstall` for the symlinks).

clean:
	@echo "Removing in-tree artifacts..."
	rm -rf .pytest_cache tests/__pycache__ tests/unit/__pycache__ \
	       tests/integration/__pycache__ .coverage htmlcov/
	rm -rf server/node_modules
	@echo "Done. Run \`make install\` to reinstall."

# uninstall: clean + remove the symlinks `make install` dropped into
# LINK_DIR (only those that still point back into THIS source tree, so
# a different f8 checkout's symlinks aren't disturbed). User data in
# ~/.f8 and ~/traces is left alone -- delete those by hand if you
# really want a full wipe.

uninstall: clean
	@echo ""
	@echo "Removing symlinks from $(LINK_DIR) that point back into this tree..."
	@SCRIPT_DIR="$$(pwd)"; \
	removed=0; \
	for tool in $(TOOLS); do \
	    target="$(LINK_DIR)/$$tool"; \
	    if [ -L "$$target" ]; then \
	        link="$$(readlink "$$target")"; \
	        case "$$link" in \
	            "$$SCRIPT_DIR/"*) \
	                if rm -f "$$target" 2>/dev/null; then \
	                    echo "  removed $$target"; \
	                    removed=$$((removed+1)); \
	                else \
	                    echo "  ERROR: could not remove $$target (try: sudo make uninstall)"; \
	                fi ;; \
	            *) echo "  skipping $$target (points elsewhere: $$link)" ;; \
	        esac; \
	    fi; \
	done; \
	echo "  $$removed symlink(s) removed."
	@echo ""
	@echo "User data was NOT touched. To remove it manually:"
	@echo "    rm -rf ~/.f8 ~/traces"
