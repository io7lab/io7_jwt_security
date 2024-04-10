# io7_jwt_security

This is a specific purpose built plugin for the mosquitto that serves the io7 IOT platform


The official eclipse-mosquitto docker container uses Alpine Linux, so this plugin needs to be built on the Alpine.

### Build Instruction

For Alpine Linux
- apk add make g++ openssl-dev cjson-dev docbook-xsl git
- git clone https://github.com/eclipse/mosquitto.git
- cd to mosquitto and build by running `make`
- cd plugins
- git clone https://github.com/io7lab/mosquitto_jwt_plugin.git
- cd io7_jwt_security
- modify the Makefile to point to the mosquitto build tree
- run `make`
