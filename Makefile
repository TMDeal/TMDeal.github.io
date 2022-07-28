DATA_DIR := pandoc
IMAGE_DIR := images
OUTPUT_DIR := docs
META_DIR := meta
CSS_DIR := css

WIKI_FILES := $(shell find -type f -name "*.wiki" -printf "%P\n")

HTML_FILES := $(addprefix $(OUTPUT_DIR)/, $(WIKI_FILES:%.wiki=%.html))

IMAGE_FILES := $(shell find $(IMAGE_DIR) -type f -name "*.png")
IMAGE_FILES := $(addprefix $(OUTPUT_DIR)/, $(IMAGE_FILES))

CSS_FILES := $(shell find $(CSS_DIR) -type f -name "*.css")
CSS_FILES := $(addprefix $(OUTPUT_DIR)/, $(CSS_FILES))

META_FILES := $(addprefix $(META_DIR)/, $(WIKI_FILES:%.wiki=%.yml))

BUILD_SCRIPT := ./scripts/build
UPDATE_META_SCRIPT := ./scripts/update_meta

WEBROOT := https://TMDeal.github.io

.PHONY: all
all: build

.PHONY: build
build: build-dev

.PHONY: build-build
build-prod: WEBROOT := https://TMDeal.github.io
build-prod: html assets

.PHONY: build-dev
build-dev: WEBROOT := http://127.0.0.1:8888
build-dev: html assets

.PHONY: html
html: meta $(HTML_FILES)

.PHONY: assets
assets: $(IMAGE_FILES) $(CSS_FILES)

.PHONY: meta
meta: $(META_FILES)

$(OUTPUT_DIR)/%.html: %.wiki
	@echo "Building HTML files with WEBROOT=$(WEBROOT)"
	@mkdir -p $(shell dirname $@)
	@$(BUILD_SCRIPT) "$?" "$@" "$(DATA_DIR)" "$(addprefix $(META_DIR)/, $(?:%.wiki=%.yml))" $(WEBROOT)

$(OUTPUT_DIR)/$(IMAGE_DIR)/%.png: $(IMAGE_DIR)/%.png
	@echo "Copying $? to $@"
	@mkdir -p $(shell dirname $@)
	@cp $? $@

$(OUTPUT_DIR)/$(CSS_DIR)/%.css: $(CSS_DIR)/%.css
	@echo "Copying $? to $@"
	@mkdir -p $(shell dirname $@)
	@cp $? $@

$(META_DIR)/%.yml: %.wiki
	@echo "Updating metadata for $?"
	@./scripts/update_meta "$@" $(WEBROOT)

.PHONY: clean-meta
clean-meta:
	@echo "Meta deleted"
	@rm -rf $(META_DIR)

.PHONY: clean-docs
clean-docs:
	@echo "Docs deleted"
	@rm -rf $(OUTPUT_DIR)

.PHONY: clean
clean: clean-docs clean-meta
