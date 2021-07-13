LIBBPF_SRC := libbpf/src
export LIBBPF_OUTPUT := $(abspath .libbpf-output)
export LIBBPF_INCLUDE := -I$(LIBBPF_OUTPUT)
export LIBBPF_OBJ := $(abspath $(LIBBPF_OUTPUT)/libbpf.a)
export COMMON_OBJ := $(abspath common/libcommon.a)
export COMMON_INCLUDE := -I$(abspath common)
DIRS = src

.PHONY: all
all: $(DIRS)

.PHONY: $(DIRS)
$(DIRS): %: %/all

$(foreach dir,$(DIRS),$(dir)/%): $(LIBBPF_OBJ) $(COMMON_OBJ)
	$(Q)$(MAKE) -C $(@D) $*

.PHONY: clean
clean: $(foreach dir,$(DIRS) common,$(dir)/clean)
	$(call msg,CLEAN)
	$(Q)rm -rf $(LIBBPF_OUTPUT)

# Build libbpf
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) \
		| $(LIBBPF_OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1		      \
		    OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@)		      \
		    INCLUDEDIR= LIBDIR= UAPIDIR=			      \
		    install

$(LIBBPF_OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(COMMON_OBJ): $(LIBBPF_OBJ)
	$(Q)$(MAKE) -C $(@D) $(@F)

# delete failed targets
.DELETE_ON_ERROR:

# keep the libbpf intermediate target
.SECONDARY:

