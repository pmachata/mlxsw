LIBBPF_SRC := libbpf/src
export LIBBPF_OUTPUT := $(abspath .libbpf-output)
export LIBBPF_INCLUDE := -I$(LIBBPF_OUTPUT)
export LIBBPF_OBJ := $(abspath $(LIBBPF_OUTPUT)/libbpf.a)
DIRS = src

.PHONY: all
all: $(DIRS)

.PHONY: $(DIRS)
$(DIRS): %: %/all

$(foreach dir,$(DIRS),$(dir)/%): $(LIBBPF_OBJ)
	$(Q)$(MAKE) -C $(@D) $*

.PHONY: clean
clean: $(foreach dir,$(DIRS),$(dir)/clean)
	$(call msg,CLEAN)
	$(Q)rm -rf $(LIBBPF_OUTPUT) $(APPS)

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

# delete failed targets
.DELETE_ON_ERROR:

# keep the libbpf intermediate target
.SECONDARY:

