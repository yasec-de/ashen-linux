# SPDX-License-Identifier: GPL-2.0

obj-$(CONFIG_ASHEN_TAMPER) := ashen-tamper.o

ashen-tamper-y :=	cobs.o		\
			noise.o		\
			framing.o	\
			ashen.o

# The test links the protocol objects (no ashen.o/serdev) into its own module,
# so it builds under KUnit's UML target and needs no EXPORT_SYMBOLs.
obj-$(CONFIG_ASHEN_TAMPER_KUNIT_TEST) += ashen-protocol-test.o
ashen-protocol-test-y :=	protocol_kunit.o	\
				cobs.o			\
				noise.o			\
				framing.o
