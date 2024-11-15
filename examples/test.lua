local zipato = require("src.zipato.init")

local pwd = assert(os.getenv("ZIPATO_PWD"), "ZIPATO_PWD not set")
local z = zipato.new("thijs@thijsschreijer.nl", pwd)
--local attribute_id = "3629ea14-bdc3-4bc7-9042-7d34deab8ec4"

--local val, properties = z:get_attribute_value(attribute_id)

--zipato.log:info("Value: %s", val)
--zipato.log:info(properties)


local device_name = "Netatmo CO2"
local device = assert(z:find_device(device_name))
local attributes = assert(z:get_device_attributes(device.uuid))

local attribute
for _, attr in ipairs(attributes) do
  print(device.name.." - "..attr.name)
  if attr.name == "Ellen CO2" then
    attribute = attr
  end
end

print(require("pl.pretty").write(attribute))

z:logout()
