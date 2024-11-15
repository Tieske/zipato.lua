#!/usr/bin/env copas

-- add ./src to package.path
package.path = "./src/?.lua;./src/?/init.lua;" .. package.path

local zipato = require "zipato"
zipato.https = require "copas.http"

local pwd = assert(os.getenv("ZIPATO_PWD"), "ZIPATO_PWD not set")
local zsession = zipato.new("thijs@thijsschreijer.nl", pwd)

print("MQTT config:",require("pl.pretty").write(zsession:get_mqtt_config()))

local devices = zsession:get_devices()
print("Devices:",require("pl.pretty").write(devices))

for _, device in ipairs(devices) do
  device.details = zsession:get_device_details(device.uuid)
end

print("Device details:",require("pl.pretty").write(devices))
