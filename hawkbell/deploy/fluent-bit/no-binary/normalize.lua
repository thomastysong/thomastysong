-- Normalize agent-native OpenTelemetry log records (Claude Code, Codex,
-- Gemini CLI) into hawkbell-shaped activity records, and apply a few text
-- rules. Fluent Bit's opentelemetry input puts log attributes in
-- metadata.otlp.attributes and resource attributes in the group record.
--
-- These rules match text, not a parsed command line. They are easy to
-- evade and exist only for hosts that cannot run the hawkbell binary.

local function lower(s)
  if type(s) ~= "string" then return "" end
  return string.lower(s)
end

local function command_of(a)
  local tp = a["tool_parameters"]
  if type(tp) == "table" then
    return tp["full_command"] or tp["bash_command"]
  end
  if type(tp) == "string" then
    local cmd = tp:match('"full_command"%s*:%s*"(.-)"[,}]') or tp:match('"bash_command"%s*:%s*"(.-)"[,}]')
    if cmd then
      cmd = cmd:gsub('\\"', '"'):gsub("\\\\", "\\")
    end
    return cmd
  end
  -- Gemini CLI: function_args carries the shell command.
  local fa = a["function_args"]
  if type(fa) == "string" then
    return fa:match('"command"%s*:%s*"(.-)"[,}]')
  end
  return nil
end

local secret_paths = { "/%.ssh/id_", "%.aws/credentials", "/%.env$", "/%.env ", "%.kube/config", "%.netrc", "%.npmrc", "gcloud/credentials", "%.git%-credentials" }
local security_tools = { "osqueryd", "orbit", "fluent%-bit", "falcon", "sentinel", "mdatp", "santa", "auditd", "hawkbell" }

local function lite_rules(cmd, a)
  local c = lower(cmd)
  local hits = {}
  if c ~= "" then
    if (c:find("curl") or c:find("wget") or c:find("iwr") or c:find("invoke%-webrequest")) and
       (c:find("|%s*[%w/]*sh") or c:find("|%s*[%w/]*bash") or c:find("|%s*python") or c:find("|%s*iex")) then
      hits[#hits + 1] = { id = "HB-LITE-001", title = "Download piped into an interpreter", severity = "high" }
    end
    for _, p in ipairs(secret_paths) do
      if c:find(p) then
        hits[#hits + 1] = { id = "HB-LITE-002", title = "Credential file referenced by a tool command", severity = "medium" }
        break
      end
    end
    if c:find("systemctl%s+stop") or c:find("pkill") or c:find("killall") or c:find("launchctl%s+unload") or c:find("stop%-service") then
      for _, t in ipairs(security_tools) do
        if c:find(t) then
          hits[#hits + 1] = { id = "HB-LITE-003", title = "Agent stopped a security sensor", severity = "critical" }
          break
        end
      end
    end
  end
  local to = lower(a["to_mode"])
  if to == "bypasspermissions" then
    hits[#hits + 1] = { id = "HB-LITE-004", title = "Agent switched to bypass-permissions mode", severity = "medium" }
  end
  return hits
end

function hawkbell_otel(tag, ts, group, metadata, record)
  local otlp = (metadata or {})["otlp"] or {}
  local a = otlp["attributes"] or {}
  local res = (((group or {})["resource"] or {})["attributes"]) or {}
  local name = a["event.name"] or record["log"] or ""
  local cmd = command_of(a)
  local out = {
    v = 1,
    kind = "activity",
    type = "otel." .. tostring(name),
    source = "otel",
    integrity = "user",
    agent = { id = res["service.name"], version = res["service.version"] },
    session = { id = a["session.id"] or a["conversation.id"] },
    tool = { name = a["tool_name"] or a["function_name"], use_id = a["tool_use_id"] or a["call_id"] },
    outcome = { status = a["success"] == "true" and "ok" or a["success"] == "false" and "error" or nil, decision = a["decision"] },
    labels = { otel_event = name },
  }
  if cmd then
    out.target = { command = cmd }
  end
  local hits = lite_rules(cmd, a)
  if #hits > 0 then
    local h = hits[1]
    out.kind = "detection"
    out.type = "detection.finding"
    out.detection = { rule_id = h.id, title = h.title, severity = h.severity, class = "finding", maturity = "experimental" }
  end
  return 1, ts, metadata, out
end
