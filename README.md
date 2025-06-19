# io7_jwt_security

This is a mosquitto plugin. It may not be a well architected for the robustness and the future expandability.
Rather it is built for the specific purpose to support the io7 IOT platform which is an educational IOT platform.
So, it could be a good and easy resource to understand how to build the custom mosquitto plugin, though.

The requirements is like this.
<img width="1624" alt="Screenshot 2024-04-11 at 10 53 21 AM" src="https://github.com/io7lab/io7_jwt_security/assets/13171662/9d2901a0-35e1-4cee-a9de-4f63cbd7e3a4">

So this plugin is built to use the JWT as the MQTT login credential and it just allows subscription to `io7/+/evt/#` & `io7/+/mgmt/device/meta` and no publish authority.

It is built to support this particular requirement only. So it's quite simple, hence it could help anyone understand the mosquitto plugin architecture and develop his/her own.
### configuration file
The default configuration by the io7-platform-cloud installation script is working fine. But for any reason, for example deploying the containers on to different servers or the like, there is a way to configure the JWT Authentication Server.

In the mosquitto.conf, you need to add `plugin_opt_config_file /mosquitto/config/your-jwt-security.json` and create the json file in this form.

```json
{
  "url" : "http://io7api:2009/users/validateToken"
}
```


### Build Instruction
The official eclipse-mosquitto docker container uses Alpine Linux, so this plugin needs to be built on the Alpine.

Build Steps
- docker run -it --name jwt_build -v ~/data/mosquitto:/mosquitto -v ./work:/work alpine
- apk add make g++ openssl-dev cjson-dev docbook-xsl git
- cd /work
- git clone https://github.com/eclipse/mosquitto.git
- cd to mosquitto and build by running `make`
- cd plugins
- git clone https://github.com/io7lab/mosquitto_jwt_plugin.git
- cd mosquitto_jwt_plugin
- modify the Makefile to point to the mosquitto build tree
  - `MOSQUITTO_DIR=/work`
- run `make`
