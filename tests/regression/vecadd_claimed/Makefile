ROOT_DIR := $(realpath ../../..)
include $(ROOT_DIR)/config.mk

PROJECT := vecadd_claimed

SRC_DIR := $(VORTEX_HOME)/tests/regression/$(PROJECT)

SRCS := $(SRC_DIR)/main.cpp

# vecadd's kernel, unmodified — the device-side binary is identical.
VX_SRCS := $(VORTEX_HOME)/tests/regression/vecadd/kernel.cpp

OPTS ?= -n64

KERNEL_LIB := vortex2

include ../common.mk
