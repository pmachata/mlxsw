OUTPUT := .output
INCLUDES := $(LIBBPF_INCLUDE)
OBJECTS := \
	$(OUTPUT)/trace_helpers.o \
	$(OUTPUT)/map_helpers.o \
	#

all: libcommon.a

libcommon.a: $(OBJECTS)
	ar cru $@ $^

$(OUTPUT):
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

$(OUTPUT)/%.o: %.c $(wildcard %.h) | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -c $(filter %.c,$^) -o $@
