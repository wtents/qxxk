# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=iwf-test
PKG_VERSION:=0.01
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/iwf-test

include $(INCLUDE_DIR)/package.mk

define Package/iwf-test
  SECTION:=utils
  CATEGORY:=Utilities
  TITLE:=IWF Series Product  Testing Utility
endef

define Package/iwf-test/description
  IWF Series Product  Testing Utility
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Package/iwf-test/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/com $(1)/usr/bin/
	$(INSTALL_DIR) $(1)/iwf_test
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/uart-test $(1)/iwf_test/
	$(INSTALL_BIN) ./iwf_test/button_reset $(1)/iwf_test/
	$(INSTALL_BIN) ./iwf_test/button_wps $(1)/iwf_test/
	$(INSTALL_BIN) ./iwf_test/button_test $(1)/iwf_test/
	$(INSTALL_BIN) ./iwf_test/chwifi_sta.sh $(1)/iwf_test/
	$(INSTALL_BIN) ./iwf_test/chwifi_ac_sta.sh $(1)/iwf_test/
	$(INSTALL_BIN) ./iwf_test/seteth.sh $(1)/iwf_test/
	$(INSTALL_BIN) ./iwf_test/leds_loopback.sh $(1)/iwf_test/
	$(INSTALL_BIN) ./IWF_TestServer.tcl $(1)/usr/bin/
endef

$(eval $(call BuildPackage,iwf-test))
