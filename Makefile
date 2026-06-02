# Trustabl Rulebook build.
#
# The PDF is generated from the rule pack + rationale docs, never authored by
# hand. `make book` verifies consistency, regenerates the index, assembles the
# chapters, and renders the PDF.
#
# Requirements: python3 + pyyaml, pandoc, and a LaTeX engine (xelatex by
# default; tectonic is the easiest to install for CI — override with
# `make book PDF_ENGINE=tectonic`).

RULES_REPO ?= ../trustabl-rules
PDF_ENGINE ?= xelatex
BUILD_DIR  := build
BOOK_MD    := $(BUILD_DIR)/trustabl-rulebook.md
BOOK_PDF   := $(BUILD_DIR)/trustabl-rulebook.pdf

.PHONY: book check index assemble pdf clean

# Full pipeline: gate -> index -> assemble -> render.
book: check index assemble pdf

# Fail if the rationale docs drift from the shipped pack.
check:
	python tools/check_rulebook.py --rules-repo $(RULES_REPO)

# Regenerate the POLICY_INDEX files (and fail if they were stale in CI: add --check).
index:
	python tools/gen_index.py --rules-repo $(RULES_REPO)

# Assemble all chapters + appendix into one markdown.
assemble:
	python tools/build_book.py --rules-repo $(RULES_REPO) --out $(BOOK_MD)

# Render the PDF (requires pandoc + a LaTeX engine).
pdf: $(BOOK_MD)
	pandoc --defaults=tools/book/pandoc.yaml --pdf-engine=$(PDF_ENGINE) \
	       -o $(BOOK_PDF) $(BOOK_MD)
	@echo "built $(BOOK_PDF)"

clean:
	rm -rf $(BUILD_DIR)
