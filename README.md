# io7_jwt_security

This is a specific purpose built plugin for the mosquitto that serves the io7 IOT platform

Build Instruction

For ARM Architecture
- apk add make g++ openssl-dev cjson-dev docbook-xsl
- git clone https://github.com/eclipse/mosquitto.git
- cd to mosquitto and build by running `make`
- git clone https://github.com/io7lab/mosquitto_jwt_plugin.git
- cd to mosquitto_jwt_plugin
- modify the Makefile to point to the mosquitto build tree
- run `make`
