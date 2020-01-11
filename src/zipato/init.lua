--- Zipato API library for Zipabox/Zipatile home controllers.
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
local sha1 = require("sha1")

local zipato = {}
local zipato_mt = { __index = zipato }

-- https method is set on the module table, such that it can be overridden
-- by another implementation (eg. Copas)
zipato.https = require "ssl.https"
-- Logger is set on the module table, to be able to override it
-- supports: debug, info, warn, error, fatal
-- log:debug([message]|[table]|[format, ...]|[function, ...])
zipato.log = require("logging.console")()



-------------------------------------------------------------------------------
-- Generic functions.
-- Functions for session management and instantiation
-- @section Generic


local base_url="https://my.zipato.com:443/zipato-web/v2"




-- Performs a HTTP request on the Zipato API.
-- @param path (string) the relative path within the API base path
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
    url = base_url .. assert(path, "1st parameter 'relative-path' missing") .. query,
    headers = headers,
    source = ltn12.source.string(body or ""),
    sink = ltn12.sink.table(response_body),
  }
  zipato.log:debug("[zipato] making api request to: %s %s", r.method, r.url)
  --zipato.log:debug(r)  -- not logging because of credentials

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
--print("Response: "..require("pl.pretty").write({
--  body = response_body,
--  status = response_code,
--  headers = response_headers,
--}))

  zipato.log:debug("[zipato] api request returned: %s", response_code)

  return ok, response_body, response_code, response_headers, response_status_line
end



--- Creates a new Zipato session instance.
-- @param username (string) required, the username to use for login
-- @param password (string) required, the password to use for login
-- @return zipato session object
-- @usage
-- local zipato = require "zipato"
-- local zsession = zipato.new("myself@nothere.com", "secret_password")
-- local ok, err = zsession:login()
-- if not ok then
--   print("failed to login: ", err)
-- end
function zipato.new(username, password)
  local self = {
    username = assert(username, "1st parameter, 'username' is missing"),
    password = sha1(assert(password, "2nd parameter, 'password' is missing")),
  }
  zipato.log:debug("[zipato] created new instance for %s", self.username)

  return setmetatable(self, zipato_mt)
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

--- Performs a HTTP request on the Zipato API.
-- It will automatically inject authentication/session data. Or if not logged
-- logged in yet, it will log in. If the session has expired it will be renewed.
--
-- NOTE: if the response_body is json, then it will be decoded and returned as
-- a Lua table.
-- @param path (string) the relative path within the API base path
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
-- local ok, response_body, status, headers, statusline = zsession:request("/attributes", "GET", headers, query, nil)
function zipato:request(path, method, headers, query, body)
  return _request(self, true, path, method, headers, query, body)
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
-- local ok, response_body, status, headers, statusline = zsession:rewrite_error(200, zsession:request("/attributes", "GET"))
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
    local ok, response_body = self:rewrite_error(200, _request(self, false, "/user/logout", "GET"))
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

  local ok, response_body, _, headers = self:rewrite_error(200, zipa_request("/user/init", "GET"))
  if not ok then
    zipato.log:error("[zipato] failed to get nonce: %s", response_body)
    return nil, "failed to get nonce: "..response_body
  end

  local query = {
    username = self.username,
    token = sha1(response_body.nonce .. self.password),
  }

  self.cookie = headers["set-cookie"]
  ok, response_body = self:rewrite_error(200, _request(self, false, "/user/login", "GET", nil, query))
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



--- Gets an attribute value.
-- @param attribute_uuid (string) the uuid of the attribute to get the value of.
-- @return value + response_body, or nil+err
-- @usage
-- @usage
-- local zipato = require "zipato"
-- local zsession = zipato.new("myself@nothere.com", "secret_password")
-- local value, body = zsession:get_attribute_value("some_attribute_uuid_here")
-- local last_change = body.timestamp
function zipato:get_attribute_value(attribute_uuid)

  local ok, response_body = self:rewrite_error(200, self:request("/attributes/"..attribute_uuid.."/value", "GET"))
  if not ok then
    return nil, "failed to get value: "..response_body
  end

  return response_body.value, response_body
end


return zipato
