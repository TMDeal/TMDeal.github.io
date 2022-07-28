DATA_DIR := pandoc
FILTERS_DIR := $(DATA_DIR)/filters
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

.PHONY: all
all: build

.PHONY: build
build: html assets

.PHONY: html
html: meta $(HTML_FILES)

.PHONY: assets
assets: $(IMAGE_FILES) $(CSS_FILES)

.PHONY: meta
meta: $(META_FILES)

.PHONY: serve
serve: build
	@five-server --no-browser $(OUTPUT_DIR)

$(OUTPUT_DIR)/%.html: %.wiki
	@echo "Building $?"
	@mkdir -p $(shell dirname $@)
	@pandoc -f vimwiki -t html "$?" \
		--output "$@" \
		--data-dir "$(DATA_DIR)" \
		--defaults "$(addprefix $(META_DIR)/, $(?:%.wiki=%.yml))" \
		--lua-filter "$(FILTERS_DIR)/fix_images.lua"

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
	@$(UPDATE_META_SCRIPT) "$@"

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
