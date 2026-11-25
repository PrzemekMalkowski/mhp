# Builds the eBPF object embedded into mhp (internal/ebpf). Needs clang, bpftool, libbpf-dev.
OBJS := ../internal/ebpf/memtrace.bpf.o ../internal/ebpf/memtrace_legacy.bpf.o ../internal/ebpf/faults.bpf.o

all: $(OBJS)

../internal/ebpf/%.bpf.o: %.bpf.c vmlinux.h
	clang -O2 -g -Wall -Wno-missing-declarations -target bpf -D__TARGET_ARCH_x86 -I. -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true

# The heap tracer for kernels without session uprobes (Linux < 6.13): entry + return probes.
../internal/ebpf/memtrace_legacy.bpf.o: memtrace.bpf.c vmlinux.h
	clang -O2 -g -Wall -Wno-missing-declarations -target bpf -D__TARGET_ARCH_x86 -DNO_SESSION -I. -c $< -o $@
	llvm-strip -g $@ 2>/dev/null || true

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f $(OBJS) vmlinux.h
