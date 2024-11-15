--- Zipato API library for Zipabox/Zipatile home controllers for the V2 api which
-- has been deprecated.
--
-- The V2 devices are no longer available through the zipato cloud, only the local
-- API remians.
--
-- This library implements the session management and makes it easy to access
-- individual endpoints of the API.
--
-- @author Thijs Schreijer, http://www.thijsschreijer.nl
-- @license zipato.lua is free software under the MIT/X11 license.
-- @copyright 2019-2020 Thijs Schreijer
-- @release Version x.x, Library to acces the Zipato API

local url = require "socket.url"
local ltn12 = require "ltn12"
local json = require "cjson.safe"
local sha1 = require "sha1"
local socket = require "socket"
local now = socket.gettime

local zipato = {}
local zipato_mt = { __index = zipato }

-- http method is set on the module table, such that it can be overridden
-- by another implementation (eg. Copas)
zipato.https = require("socket.http") -- plain http for local API

-- Logger is set on the module table, to be able to override it
-- supports: debug, info, warn, error, fatal
-- log:debug([message]|[table]|[format, ...]|[function, ...])
zipato.log = require("logging.console")()



-------------------------------------------------------------------------------
-- Generic functions.
-- Functions for session management and instantiation
-- @section Generic




-- Performs a HTTP request on the Zipato API.
-- @param path (string) the relative path within the API base path, eg. "/v2/..."
-- @param method (string) HTTP method to use
-- @param headers (table) optional header table
-- @param query (table) optional query parameters (will be escaped)
-- @param body (table/string) optional body. If set the "Content-Length" will be
-- added to the headers. If a table, it will be send as JSON, and the
-- "Content-Type" header will be set to "application/json".
-- @return ok, response_body, response_code, response_headers, response_status_line
local function zipa_request(path, method, headers, query, body)
  local response_body = {}
  headers = headers or {}

  query = query or {} do
    local r = {}
    local i = 0
    for k, v in pairs(query) do
      r[i] = "&"
      r[i+1] = url.escape(k)
      r[i+2] = "="
      r[i+3] = url.escape(v)
      i = i + 4
    end
    query = "?" .. table.concat(r)
    if query == "?" then
      query = ""
    end
  end

  if type(body) == "table" then
    body = json.encode(body)
    headers["Content-Type"] =  "application/json"
  end
  headers["Content-Length"] = #(body or "")

  local r = {
    method = assert(method, "2nd parameter 'method' missing"):upper(),
    url = assert(path, "1st parameter 'relative-path' missing") .. query,
    headers = headers,
    source = ltn12.source.string(body or ""),
    sink = ltn12.sink.table(response_body),
  }
  zipato.log:debug("[zipato] making api request to: %s %s", r.method, r.url)
  zipato.log:debug(r)  -- not logging because of credentials

  local ok, response_code, response_headers, response_status_line = zipato.https.request(r)
  if not ok then
    zipato.log:error("[zipato] api request failed with: %s", response_code)
    return ok, response_code, response_headers, response_status_line
  end

  if type(response_body) == "table" then
    response_body = table.concat(response_body)
  end

  for name, value in pairs(response_headers) do
    if name:lower() == "content-type" and value:find("application/json", 1, true) then
      -- json body, decode
      response_body = assert(json.decode(response_body))
      break
    end
  end
-- print("Response: "..require("pl.pretty").write({
--  body = response_body,
--  status = response_code,
--  headers = response_headers,
-- }))

  zipato.log:debug("[zipato] api request returned: %s", response_code)

  return ok, response_body, response_code, response_headers, response_status_line
end



local _request do
  -- these return codes will force a logout, login, and a retry
  local retry_codes = {
    [401] = true,
    [403] = true,
    [302] = true, -- somehow the Zipato API returns a redirect on invalid cookies, instead of a proper 40x
  }


  -- perform a request while injecting authentication/session data.
  -- This method will automatically log in, if not already done.
  -- if auto_renew is set it will also retry to login after a failure/expiry
  _request = function(self, auto_renew, path, method, headers, query, body)
    if not self.cookie then
      -- must login first
      local ok, err = self:login()
      if not ok then
        return ok, err
      end
    end

    headers = headers or {}
    headers.Cookie = self.cookie

    local ok, response_body, response_code, response_headers, response_status_line = zipa_request(path, method, headers, query, body)

    if retry_codes[response_code or -1] then
      if auto_renew then
        -- we seem to be logged out/expired
        zipato.log:error("[zipato] _request failed with: '%s', (retrying after logout)", response_code)
        self:logout() -- force logout, drop current cookie value
        return _request(self, false, path, method, headers, query, body)
      else
        zipato.log:error("[zipato] retrying _request failed with:  %s", response_code)
      end
    end

    -- if we get a new JSESSIONID cookie, then store it
    local cookie = (response_headers or {})["set-cookie"] or ""
    if cookie:find("JSESSIONID=", 1, true) then
      zipato.log:debug("[zipato] request returned new JSESSIONID", response_code)
      self.cookie = cookie
    end

    return ok, response_body, response_code, response_headers, response_status_line
  end

end



--- Creates a new Zipato session instance.
-- @param username (string) required, the username to use for login
-- @param password (string) required, the password to use for login
-- @param opts (table, optional) additional options
-- @tparam string opts.base_url (string) the base url of the API, defaults to "http://192.168.2.6:8080".
-- @return zipato session object
-- @usage
-- local zipato = require "zipato"
-- local zsession = zipato.new("myself@nothere.com", "secret_password", {
--   attribute_update_config = {
--     update_interval = 1,   -- max age in seconds before refreshing
--     callback = function(session, uuid, value)
--       -- callback called for each attribute value update
--     end,
--   }
-- })
-- local ok, err = zsession:login()
-- if not ok then
--   print("failed to login: ", err)
-- end
function zipato.new(username, password, opts)
  opts = opts or {}
  opts.attribute_update_config = opts.attribute_update_config or {}

  local self = {
    -- local base_url="https://my.zipato.com/zipato-web"  -- web-based version; dead these days
    base_url = opts.base_url or "http://192.168.2.6:8080",   -- local version
    username = assert(username, "1st parameter, 'username' is missing"),
    password = sha1(assert(password, "2nd parameter, 'password' is missing")),
    _attribute_values = {},
    _attribute_update_config = {
      update_interval = opts.attribute_update_config.update_interval or 1,
      callback = opts.attribute_update_config.callback,
      expires = 0,
      handle = nil,
    },
  }
  zipato.log:debug("[zipato] created new instance for %s", self.username)

  return setmetatable(self, zipato_mt)
end



--- Performs a HTTP request on the Zipato API.
-- It will automatically inject authentication/session data. Or if not logged
-- in yet, it will log in. If the session has expired it will be renewed.
--
-- NOTE: if the response_body is json, then it will be decoded and returned as
-- a Lua table.
-- @param path (string) the relative path within the API base path, eg. "/v2/..."
-- @param method (string) HTTP method to use
-- @param headers (table) optional header table
-- @param query (table) optional query parameters (will be escaped)
-- @param body (table/string) optional body. If set the "Content-Length" will be
-- added to the headers. If a table, it will be send as JSON, and the
-- "Content-Type" header will be set to "application/json".
-- @return ok, response_body, response_code, response_headers, response_status_line
-- @usage
-- local zipato = require "zipato"
-- local zsession = zipato.new("myself@nothere.com", "secret_password")
--
-- local headers = { ["My-Header"] = "myvalue" }
-- local query = { ["param1"] = "value1" }
--
-- -- the following line will automatically log in
-- local ok, response_body, status, headers, statusline = zsession:request("/v2/attributes", "GET", headers, query, nil)
function zipato:request(path, method, headers, query, body)
  return _request(self, true, self.base_url .. path, method, headers, query, body)
end



--- Rewrite errors to Lua format (nil+error).
-- Takes the output of the `request` function and validates it for errors;
--
-- - nil+err
-- - body with "success = false" (some API calls return a 200 with success=false for example)
-- - mismatch in expected status code (a 200 expected, but a 404 received)
--
-- This reduces the error handling to standard Lua errors, instead of having to
-- validate each of the situations above individually.
-- @param expected (number) optional expected status code, if nil, it will be ignored
-- @param ... same parameters as the `request` method
-- @return nil+err or the input arguments
-- @usage
-- local zipato = require "zipato"
-- local zsession = zipato.new("myself@nothere.com", "secret_password")
--
-- -- Make a request where we expect a 200 result
-- local ok, response_body, status, headers, statusline = zsession:rewrite_error(200, zsession:request("/v2/attributes", "GET"))
-- if not ok then
--   return nil, response_body -- a 404 will also follow this path now, since we only want 200's
-- end
function zipato:rewrite_error(expected, ok, body, status, headers, ...)
  if not ok then
    return ok, body
  end

  if type(body) == "table" and body.success == false then
    return nil, tostring(status)..": "..json.encode(body)
  end

  if expected ~= nil and expected ~= status then
    if type(body) == "table" then
      body = json.encode({body = body, headers = headers})
    end
    return nil, "bad return code, expected " .. expected .. ", got "..status..". Response: "..body
  end

  return ok, body, status, headers, ...
end



--- Logs out of the current session.
-- @return `true` or nil+err
-- @usage
-- local zipato = require "zipato"
-- local zsession = zipato.new("myself@nothere.com", "secret_password")
-- local ok, err = zsession:login()
-- if not ok then
--   print("failed to login: ", err)
-- else
--   zsession:logout()
-- end
function zipato:logout()
  zipato.log:debug("[zipato] logout for %s", self.username)
  if self.cookie then
    local ok, response_body = self:rewrite_error(200, _request(self, false, self.base_url .. "/v2/user/logout", "GET"))
    self.cookie = nil
    if not ok then
      zipato.log:error("[zipato] logout for %s failed: %s", self.username, response_body)
      return nil, "failed to log out: " .. response_body
    end
  end

  return true
end



--- Logs in the current session.
-- This will automatically be called by the `request` method, if not logged in
-- already.
-- @return `true` or `nil+err`
-- @usage
-- local zipato = require "zipato"
-- local zsession = zipato.new("myself@nothere.com", "secret_password")
-- local ok, err = zsession:login()
-- if not ok then
--   print("failed to login: ", err)
-- end
function zipato:login()
  zipato.log:debug("[zipato] initiating login for %s", self.username)

  local ok, response_body, _, headers = self:rewrite_error(200, zipa_request(self.base_url .. "/v2/user/init", "GET"))
  if not ok then
    zipato.log:error("[zipato] failed to get nonce: %s", response_body)
    return nil, "failed to get nonce: "..response_body
  end

  local query = {
    username = self.username,
    token = sha1(response_body.nonce .. self.password),
  }

  self.cookie = headers["set-cookie"]
  ok, response_body = self:rewrite_error(200, _request(self, false, self.base_url .. "/v2/user/login", "GET", nil, query))
  if not ok then
    self.cookie = nil
    zipato.log:error("[zipato] failed to login: %s", response_body)
    return nil, "failed to login: "..response_body
  end

  return true
end



-------------------------------------------------------------------------------
-- API specific functions.
-- This section contains functions that directly interact with the Zipato API.
-- @section API



-- Gets an attribute value; "/attributes/{uuid}/value GET".
-- @param attribute_uuid (string) the uuid of the attribute to get the value of.
-- @return value + response_body, or nil+err
-- @usage
-- local zipato = require "zipato"
-- local zsession = zipato.new("myself@nothere.com", "secret_password")
-- local value, body = zsession:get_attribute_value("some_attribute_uuid_here")
-- local last_change = body.timestamp
--function zipato:get_attribute_value(attribute_uuid)

--  local ok, response_body = self:rewrite_error(200, self:request("/v2/attributes/"..attribute_uuid.."/value", "GET"))
--  if not ok then
--    return nil, "failed to get value: "..response_body
--  end

--  return response_body.value, response_body
--end



--- Sets an attribute value; "/attributes/{uuid}/value PUT".
-- @param attribute_uuid (string) the uuid of the attribute to set the value of.
-- @param value (optional) the value to set
-- @param timestamp (Date, optional) timestamp for the value to set
-- @param pendingValue (optional) pendingValue to set
-- @param pendingTimestamp (Date, optional) timestamp for the pendingValue to set
-- @return true, or nil+err
function zipato:set_attribute_value(attribute_uuid, value, timestamp, pendingValue, pendingTimestamp)
  local body = {
    value = tostring(value),
    timestamp = timestamp,
    pendingValue = tostring(pendingValue),
    pendingTimestamp = pendingTimestamp,
  }

  local ok, response_body = self:rewrite_error(202, self:request("/v2/attributes/"..attribute_uuid.."/value", "PUT", nil, nil, body))
  if not ok then
    return nil, "failed to set attribute value to: "..response_body
  end

  return response_body.value, response_body
end



--- Returns list of all devices; "/devices GET".
-- @return list, or nil+err
function zipato:get_devices()

  local ok, response_body = self:rewrite_error(200, self:request("/v2/devices", "GET"))
  if not ok then
    return nil, "failed to get devices: "..response_body
  end

  return response_body
end



--- Returns a device by name or uuid.
-- Retreives the list through `get_devices` but only returns the requested one.
-- @return device, or nil+err
function zipato:find_device(uuid_or_name)

  local device_list, err = self:get_devices()
  if not device_list then
    return nil, err
  end

  for _, device in ipairs(device_list) do
    if device.name == uuid_or_name or
       device.uuid == uuid_or_name then
      return device
    end
  end
  return nil, "device not found"
end



--- Returns device details by device_uuid; "/devices/{uuid} GET".
-- @param device_uuid (string) uuid of device to get
-- @param query (table, optional) query parameters, default: `{ full=true }`
-- @return device, or nil+err
function zipato:get_device_details(device_uuid, query)

  local ok, device_details = self:rewrite_error(200, self:request("/v2/devices/" .. device_uuid, "GET", nil, query or { full = "true" }))
  if not ok then
    return nil, "failed to get device details: "..device_details
  end

  return device_details
end



--- Returns device attributes by device.
-- Gets all attributes from the device endpoints; "/endpoints/{uuid}", and
-- combines them into a single attribute table.
-- @param device_uuid (string) uuid of device to get
-- @return attribute array, or nil+err
function zipato:get_device_attributes(device_uuid)

  local details, err = self:get_device_details(device_uuid)
  if not details then
    return nil, err
  end

  local endpoints = details.endpoints or {}
  local attributes = {}

  for _, endpoint in ipairs(endpoints) do
    local ok, response_body = self:rewrite_error(200, self:request("/v2/endpoints/"..endpoint.uuid, "GET", nil, { attributes = "true" }))
    if not ok then
      return nil, "failed to get endpoint details: "..response_body
    end

    for _, attrib in ipairs(response_body.attributes or {}) do
      attributes[#attributes + 1] = attrib
    end
  end

  return attributes
end



--- Returns all attribute values; "/attributes/values" GET.
-- @param handle (string, optional) handle of last call for updates
-- @param update (boolean, optional) request only updated values or all, defaults to true if handle is given, or false if not
-- @param raw (boolean, optional) if true, raw results, otherwise a table keyed by uuid, with the value as value
-- @return raw values array + handle, or nil+err
function zipato:get_attribute_values(handle, update, raw)

  if update == nil then
    update = not not handle
  end

  local headers = { ["If-None-Match"] = handle }
  local query = { update = update }

  local ok, response_body, _, response_headers = self:rewrite_error(200, self:request("/v2/attributes/all", "GET", headers, query))
  if not ok then
    return nil, "failed to get attribute values: "..response_body
  end

  if raw then
    return response_body, assert(response_headers["Etag"])
  end

  local values = {}
  for _, value_update in ipairs(response_body or {}) do
    values[value_update.uuid] = value_update.value.value
  end

  return values, assert(response_headers["Etag"])
end



--- Returns the mqtt configuration of the box if available.
-- @return table with broker_ip, broker_port and box_topic, or nil+err
function zipato:get_mqtt_config()
  -- fetch list of networks
  local ok, response_body = self:rewrite_error(200, self:request("/v2/networks", "GET"))
  if not ok then
    return nil, "failed to get network list: " .. response_body
  end

  -- do a quick search for mqtt related networks and put them in front
  for i = 1, #response_body do
    local network = response_body[i]
    if network.name:lower() == "mqtt" then
      -- seems mqtt related, add to start of array
      response_body[i] = nil  -- in case i == #response_body
      response_body[i] = response_body[#response_body]
      table.insert(response_body, 1, network)
    end
  end

  local mqtt_network
  for _, network in ipairs(response_body) do
    -- fetch this network
    local ok, response_body = self:rewrite_error(200, self:request("/v2/networks/"..network.uuid, "GET", nil, {config = "true"}))
    if not ok then
      return nil, "failed to retrieve network " .. network.uuid .. ": " .. response_body
    end

    -- check whether it is the mqtt class
    local cfg = (response_body or {}).config
    if cfg.broker and cfg.topicBase then -- looks like MQTT!
      mqtt_network = response_body
      break
    end
  end
  if not mqtt_network then
    return nil, "no mqtt network found in retrieved network list"
  end

  -- replace NULL by nil
  for k,v in pairs(mqtt_network) do
    if type(v) == "userdata" then -- javascript NULL
      mqtt_network[k] = nil
    end
  end
  for k,v in pairs(mqtt_network.config or {}) do
    if type(v) == "userdata" then -- javascript NULL
      mqtt_network.config[k] = nil
    end
  end

  -- print("MQTT stuff:",require("pl.pretty").write(mqtt_network))

  local broker, err = url.parse(mqtt_network.config.broker)
  if not broker then
    return nil, "failed to parse broker url "..mqtt_network.config.broker..": "..err
  end

  return {
    broker_ip = broker.host,
    broker_port = broker.port or 1883,
    box_topic = (mqtt_network.config.topicBase or "/") ..
                (mqtt_network.config.topicPrefix or
                (mqtt_network.config.clientId .. "/")),
  }
end



-------------------------------------------------------------------------------
-- Session tracked attributes.
-- A session can track the status of attributes, to prevent to have to do too
-- many API calls. It fetches the list once, and keeps track of updates.
--
-- Behaviour can be configured using `opts.attribute_update_config` settings
-- (see `new`).
--
-- The `update_interval` property determines when a value expires. Getting a value
-- while the values have expired, will cause an update of the values first.
--
-- The `callback` property will be called for each updated value.
-- @section Attributes



--- Fetches attribute values tracked by the session.
-- This will force an update, even if the values haven't expired yet. This
-- could for example be called on a recurring timer. With a configured `callback`
-- to handle the updates.
-- @return true, or nil+err
function zipato:fetch_attribute_values()
  local config = self._attribute_update_config
  local list = self._attribute_values

  -- we need an update
  local newlist, newhandle = self:get_attribute_values(config.handle)
  if not newlist then
    config.handle = nil   -- just in case; get all values from scratch next time
    return nil, newhandle
  end

  local callback = config.callback
  local callbacks = {}

  for uuid, value in pairs(newlist) do
    list[uuid] = value
    if callback then
      -- we do not execute callbacks, because the callback might recurse into
      -- this update function, and we need to have all values updated before
      -- that can happen.
      callbacks[uuid] = value
    end
  end

  config.handle = newhandle
  config.expires = now() + config.update_interval

  -- all values are up-to-date now, only now execute callbacks
  if callback then
    for uuid, value in pairs(callbacks or {}) do
      local ok, err = pcall(callback, self, uuid, value)
      if not ok then
        zipato.log:error("[zipato] attribute update callback for %s failed: %s", self.username, err)
      end
    end
  end

  return true
end



--- Gets a single attribute value, as tracked by the session.
-- If the current values are to old, it will update them in the process
-- by calling `fetch_attribute_values` first.
-- @param uuid (string) the uuid of the attribute to return the value of
-- @return value, or nil+err
-- @see fetch_attribute_values
function zipato:get_attribute_value(uuid)
  if self._attribute_update_config.expires <= now() then
    self:fetch_attribute_values()
  end

  local value = self._attribute_values[uuid]
  if value == nil then
    return nil, "attribute not found"
  end

  return value
end



return zipato
