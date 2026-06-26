obj-m += vpnhide_kmod.o

ifeq ($(KERNELRELEASE),)

# Check if KERNEL_SRC is defined (usually means we want to build for Android)
ifdef KERNEL_SRC
    ARCH           := arm64
    CROSS_COMPILE  := aarch64-linux-gnu-
    
    # If CLANG_DIR is set, use it, otherwise rely on system clang
    ifdef CLANG_DIR
        CC         := $(CLANG_DIR)/clang
        LD         := $(CLANG_DIR)/ld.lld
        AR         := $(CLANG_DIR)/llvm-ar
        NM         := $(CLANG_DIR)/llvm-nm
        OBJCOPY    := $(CLANG_DIR)/llvm-objcopy
        OBJDUMP    := $(CLANG_DIR)/llvm-objdump
        STRIP      := $(CLANG_DIR)/llvm-strip
    else
        CC         := clang
        LD         := ld.lld
        AR         := llvm-ar
        NM         := llvm-nm
        OBJCOPY    := llvm-objcopy
        OBJDUMP    := llvm-objdump
        STRIP      := llvm-strip
    endif

    MAKE_ARGS := -C $(KERNEL_SRC) M=$(CURDIR) \
        ARCH=$(ARCH) LLVM=1 LLVM_IAS=1 \
        CROSS_COMPILE=$(CROSS_COMPILE) \
        CC=$(CC) LD=$(LD) AR=$(AR) NM=$(NM) \
        OBJCOPY=$(OBJCOPY) OBJDUMP=$(OBJDUMP) STRIP=$(STRIP)
else
    # Native compilation fallback (for PC testing like Debian/Ubuntu)
    KDIR ?= /lib/modules/$(shell uname -r)/build
    MAKE_ARGS := -C $(KDIR) M=$(CURDIR)
    STRIP     := strip
endif

all:
	$(MAKE) $(MAKE_ARGS) modules

clean:
	$(MAKE) $(MAKE_ARGS) clean

strip: all
	$(STRIP) -d $(CURDIR)/vpnhide_kmod.ko

endif
