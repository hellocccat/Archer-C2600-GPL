#
# Copyright (c) 2014 Shenzhen TP-LINK Technologies Co.Ltd.
#

BUILD_DIR:=.
SDK_DIR:=../openwrt
SUBMAKE:=$(MAKE) $(FLAGS)

all: bootstrap build

config:
	cp ipf.config $(SDK_DIR)/.config;
	cp linux-3.4.config $(SDK_DIR)/target/linux/ipq806x/config-3.4;
	cp feeds.conf $(SDK_DIR)/feeds.conf;

bootstrap: config
	$(SUBMAKE) -C $(SDK_DIR) bootstrap

build:
	$(SUBMAKE) -C $(SDK_DIR)
