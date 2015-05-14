#
# Copyright (c) 2013 Qualcomm Atheros, Inc.
#
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#


include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk

PKG_NAME:=qca-romboot
PKG_VERSION:=10.1.389
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)-$(BUILD_VARIANT)/$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE:=$(PKG_NAME)_$(PKG_VERSION).tar.bz2
PKG_BRANCH:=$(basename $(PKG_VERSION))
PKG_SOURCE_URL:=http://tritium.qca.qualcomm.com/software/$(PKG_BRANCH)/AP$(PKG_VERSION:999.999.0%=QCAMain%)/src/components

PKG_MD5SUM:=bb737c1ed9659db83617257c0fe998a5

PKG_BUILD_DEPENDS:=qca-legacy-uboot

include $(INCLUDE_DIR)/host-build.mk
include $(INCLUDE_DIR)/package-version-override.mk
include $(INCLUDE_DIR)/package.mk

define Package/qca-romboot/Default
  TITLE:=Rom boot code for
  SECTION:=boot
  CATEGORY:=Boot Loaders
  DEPENDS:=@TARGET_ar71xx +qca-legacy-uboot-$(1)
  URL:=http://www.qca.qualcomm.com
  VARIANT:=$(1)
endef

define Package/qca-romboot/Description
  This package contains the assembly code requied to init the chip and
  perform specific initialization prior to the bootloader. It's mainly
  executed before the bootloader for NAND boot.
  This package generates code for the $(1) board.
endef

define Package/qca-romboot-cus227
  $(call Package/qca-romboot/Default,cus227)
  TITLE+= CUS227
endef

define Package/qca-romboot-cus227/description
  $(call Package/qca-romboot/Description,CUS227)
endef

MAKEOPTS_QCA_ROMBOOT:= \
	CROSS_COMPILE=$(TARGET_CROSS) \
	UTILPATH=$(PKG_BUILD_DIR)

define Build/Compile
	$(HOSTCC) $(HOST_CFLAGS) -o $(PKG_BUILD_DIR)/bin2hex src/bin2hex.c
	$(HOSTCC) $(HOST_CFLAGS) -o $(PKG_BUILD_DIR)/checksum src/checksum.c
	($(foreach var,$(strip $(shell cat configs/$(BUILD_VARIANT).config)), export ${var};) \
	 make -C $(PKG_BUILD_DIR)/rom-boot-drv clean all $(MAKEOPTS_QCA_ROMBOOT) \
		TOPDIR=$(PKG_BUILD_DIR)/rom-boot-drv/ \
	)
endef

define Package/qca-romboot-cus227/install
	( cd $(PKG_BUILD_DIR)/rom-boot-drv; \
	$(MAKEOPTS_QCA_ROMBOOT) \
	./mk2stage -2 $(BIN_DIR)/openwrt-$(BOARD)-$(BUILD_VARIANT)-qca-legacy-uboot.bin; \
	$(CP) ./2fw.bin $(BIN_DIR)/openwrt-$(BOARD)-$(BUILD_VARIANT)-qca-romboot-2fw.bin )
endef

$(eval $(call BuildPackage,qca-romboot-cus227))
