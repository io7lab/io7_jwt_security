MOSQUITTO_DIR=/work/build

include $(MOSQUITTO_DIR)/config.mk

.PHONY : all binary check clean reallyclean test install uninstall check_vars

PLUGIN_NAME=io7_jwt_security

PLUGIN_CPPFLAGS=-I$(MOSQUITTO_DIR)/ -I$(MOSQUITTO_DIR)/include -I$(MOSQUITTO_DIR)/deps
PLUGIN_CFLAGS=-Wall -ggdb -O2 -Wconversion -Wextra -fPIC

all : binary

binary : ${PLUGIN_NAME}.so

${PLUGIN_NAME}.so : ${PLUGIN_NAME}.c io7_jwt_util.h
	$(CROSS_COMPILE)$(CC) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS)  -fPIC -shared $< -o $@

check_vars:
	@echo CROSS_COMPILE     : $(CROSS_COMPILE)
	@echo CC                : $(CC) 
	@echo PLUGIN_CPPFLAGS   : $(PLUGIN_CPPFLAGS) 
	@echo PLUGIN_CFLAGS     : $(PLUGIN_CFLAGS) 
	@echo PLUGIN_LDFLAGS    : $(PLUGIN_LDFLAGS)
	@echo $(CROSS_COMPILE)$(CC) $(PLUGIN_CPPFLAGS) $(PLUGIN_CFLAGS) $(PLUGIN_LDFLAGS)  -fPIC -shared $< -o $@

reallyclean : clean
clean:
	-rm -f *.o ${PLUGIN_NAME}.so *.gcda *.gcno

check: test
test:

install: ${PLUGIN_NAME}.so
	# Don't install, these are examples only.
	#$(INSTALL) -d "${DESTDIR}$(libdir)"
	#$(INSTALL) ${STRIP_OPTS} ${PLUGIN_NAME}.so "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"

uninstall :
	-rm -f "${DESTDIR}${libdir}/${PLUGIN_NAME}.so"
