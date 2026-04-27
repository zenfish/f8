# f8 test suite
#
# Usage:
#   make test          Run all tests (unit + integration, no root needed)
#   make test-unit     Run unit tests only
#   make test-cov      Run with coverage report
#   make test-e2e      Run end-to-end tests (requires sudo)
#   make verify        Quick validation: categories, colors, no duplicates
#   make clean         Remove test/build artifacts (pytest cache, coverage)
#   make distclean     clean + remove in-tree install artifacts (node_modules).
#                      Run ./install.sh again afterward to reinstall.
#   make uninstall     distclean + remove symlinks from $(LINK_DIR) that point
#                      back into this tree. Does NOT touch ~/.f8 or ~/traces
#                      (user data). May need sudo if $(LINK_DIR) isn't writable.

.PHONY: test test-unit test-cov test-e2e verify clean distclean uninstall

LINK_DIR ?= /usr/local/bin
TOOLS := f8 f8_analyze f8_timeline f8_import f8_server f8_data f8_open f8_run_all.sh

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

clean:
	rm -rf .pytest_cache tests/__pycache__ tests/unit/__pycache__ \
		tests/integration/__pycache__ .coverage htmlcov/

# distclean: in-tree only. Removes everything install.sh produces inside the
# repo, so that ./install.sh starts from a fresh state. Does NOT touch
# ~/.f8, ~/traces, or symlinks in /usr/local/bin (those are user data /
# out-of-tree -- use `make uninstall` for the symlinks).
distclean: clean
	@echo "Removing in-tree install artifacts..."
	rm -rf server/node_modules
	@echo "Done. Run ./install.sh to reinstall."

# uninstall: distclean + remove the symlinks install.sh dropped into LINK_DIR
# (only those that still point back into THIS source tree, so a different f8
# checkout's symlinks aren't disturbed). User data in ~/.f8 and ~/traces is
# left alone -- delete those by hand if you really want a full wipe.
uninstall: distclean
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
