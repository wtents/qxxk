#
# Copyright (c) 2013 Qualcomm Atheros, Inc..
#
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#

include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=art2
PKG_VERSION:=LinuxART2CS10.2v4.9.230
PKG_RELEASE:=1

PKG_BRANCH:=$(basename $(PKG_VERSION))
PKG_SOURCE:=$(PKG_VERSION).tar.bz2
PKG_SOURCE_URL:=http://tritium.qca.qualcomm.com/software/ART2/$(PKG_BRANCH)/$(PKG_VERSION)

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_VERSION)

include $(INCLUDE_DIR)/package-version-override.mk
include $(INCLUDE_DIR)/package.mk

#########################################################
############ ART DRIVER BUILD CONFIGURATION ############
#########################################################

ART2_COMMON_OPTS+= \
	$(TARGET_CONFIGURE_OPTS) \
	ART_ROOT=$(PKG_BUILD_DIR) \
	WORKAREA=$(PKG_BUILD_DIR) \
	TOOL_PREFIX=$(TARGET_CROSS)

ART2_DRV_OPTS+= \
	$(ART2_COMMON_OPTS) \
	KERNELARCH=$(ARCH) \
	KERNELRELEASE=$(LINUX_VERSION) \
	KERNELPATH=$(LINUX_DIR) \
	EXTRA_CFLAGS=-I$(PKG_BUILD_DIR)/driver/linux/modules/include \
	USE_PLATFORM_FRAMEWORK=1

ART2_APP_OPTS+= \
	$(ART2_COMMON_OPTS)

ifneq ($(CONFIG_DEBUG),)
ART2_APP_OPTS+= \
	GDB=1
endif

ifeq ($(BOARD),ipq806x)
ART2_APP_OPTS+=AKRONITE=1
ART_BUILD_TARGET=akronite
ART2_DRV_OPTS+= \
	EXTRA_CFLAGS+=-DAKRONITE_ART
endif

define KernelPackage/art2
    SECTION:=QCA
    CATEGORY:=QCA Proprietary software
    URL:=http://www.qca.qualcomm.com
    MAINTAINER:=Qualcomm Atheros
    TITLE:=$(1) - QCA ART Driver & tools
    DEPENDS:=+libpthread +libc +librt kmod-qca-wifi
    FILES:=$(PKG_BUILD_DIR)/driver/linux/modules/art.$(LINUX_KMOD_SUFFIX)
endef

define KernelPackage/art2/Description
    This package contains a driver for ART and the tools to use it:
      - art.ko
      - nart.out
      - NART related libs
    It has been build specifically for $(1)
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR)/driver/linux $(strip $(ART2_DRV_OPTS)) \
		-f makefile.artmod $(ART_BUILD_TARGET)
	$(MAKE) -C $(PKG_BUILD_DIR) $(strip $(ART2_APP_OPTS)) \
		-f makefile.nart all
endef

define KernelPackage/art2/install
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_DIR) $(1)/usr/lib
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nartbuild/*.out $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nartbuild/*.so $(1)/usr/lib
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/BoardData/*.bin $(1)/usr/sbin
	$(INSTALL_BIN) ./files/art.init $(1)/etc/init.d/art
endef

$(eval $(call KernelPackage,art2))
