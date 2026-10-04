ROOT_DIR := $(realpath ../../..)
include $(ROOT_DIR)/config.mk

PROJECT := mem_checker

# Two cores so there are two distinct owners to authorize between. With the
# default single core CHK_OWNER_W floors at 1 bit but every principal resolves
# to eid 0, so the cross-tenant, grant and scoped-revocation cases would all be
# vacuously true. Same reason hw/syn/xilinx/dut/catalog.mk gives the vm DUT
# NUM_CORES=2.
CONFIGS += -DVX_CFG_NUM_CORES=2

RTL_DIR := $(VORTEX_HOME)/hw/rtl
DPI_DIR := $(VORTEX_HOME)/hw/dpi

SRC_DIR := $(VORTEX_HOME)/hw/unittest/$(PROJECT)

CXXFLAGS := -I$(SRC_DIR) -I$(VORTEX_HOME)/hw/unittest/common -I$(SW_COMMON_DIR)
CXXFLAGS += -I$(ROOT_DIR)/sw -I$(ROOT_DIR)/hw

SRCS += $(SRC_DIR)/main.cpp

RTL_PKGS := $(RTL_DIR)/VX_gpu_pkg.sv $(RTL_DIR)/sec/VX_sec_pkg.sv

RTL_INCLUDE := -I$(ROOT_DIR)/sw -I$(ROOT_DIR)/hw -I$(RTL_DIR) -I$(DPI_DIR) -I$(RTL_DIR)/libs
RTL_INCLUDE += -I$(RTL_DIR)/interfaces -I$(RTL_DIR)/mem -I$(RTL_DIR)/vm -I$(RTL_DIR)/cache
RTL_INCLUDE += -I$(RTL_DIR)/sec -I$(SRC_DIR)

TOP := VX_mem_checker_top

include ../common.mk
