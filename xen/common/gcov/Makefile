obj-y += gcov_base.o gcov.o
obj-$(CONFIG_GCOV_FORMAT_3_4) += gcc_3_4.o
obj-$(CONFIG_GCOV_FORMAT_4_7) += gcc_4_7.o
obj-$(CONFIG_GCOV_FORMAT_AUTODETECT) += $(call cc-ifversion, -ge, 0x040700, \
						gcc_4_7.o, gcc_3_4.o)
