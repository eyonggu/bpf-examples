
LIBBPF_INSTALL_PATH=include/bpf/

libbpf_install:
	@mkdir -p include/bpf
	$(Q)cp libbpf/src/bpf.h $(LIBBPF_INSTALL_PATH)
	$(Q)cp libbpf/src/libbpf.h $(LIBBPF_INSTALL_PATH)
	$(Q)cp libbpf/src/bpf_helpers.h $(LIBBPF_INSTALL_PATH)
	$(Q)cp libbpf/src/libbpf_common.h $(LIBBPF_INSTALL_PATH)
	$(Q)cp libbpf/src/libbpf_version.h $(LIBBPF_INSTALL_PATH)
	$(Q)cp libbpf/src/libbpf_legacy.h $(LIBBPF_INSTALL_PATH)

