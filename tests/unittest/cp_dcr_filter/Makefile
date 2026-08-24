ROOT_DIR := $(realpath ../../..)
include $(ROOT_DIR)/config.mk

PROJECT := cp_dcr_filter

SRC_DIR := $(VORTEX_HOME)/tests/unittest/$(PROJECT)

SRCS := $(SRC_DIR)/main.cpp $(SIM_COMMON_DIR)/cmd_processor.cpp

CXXFLAGS += -I$(SIM_COMMON_DIR)
CXXFLAGS += -DVX_CFG_XLEN=$(XLEN) -DVX_CFG_XLEN_$(XLEN)

include ../common.mk
