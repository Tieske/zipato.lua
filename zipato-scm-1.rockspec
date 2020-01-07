package = "zipato"
version = "scm-1"

source = {
  url = "git://github.com/Tieske/zipato.lua",
  --tag = "0.1.0",
  branch = "master",
}

description = {
  summary = "Zipato API access for your Zipabox",
  detailed = [[
    Library to access the Zipato REST API.
  ]],
  homepage = "https://github.com/Tieske/zipato.lua",
  license = "MIT"
}

dependencies = {
  "lua >= 5.1, < 5.4",
  "luasec",
  "cjson",
  "sha1",
}

build = {
  type = "builtin",
  modules = {
    ["zipato.init"] = "src/zipato/init.lua",
  },
}
