-- dns_monitor.lua
-- Detects suspicious DNS resolutions in real-time

local plugin_info = {
    version = "1.0",
    author = "utracks",
    description = "Passive DNS Resolver Monitor"
}

-- Configuration
local config = {
    whitelist = {
        "google.com",
        "microsoft.com",
        -- Add trusted domains
    },
    suspicious_tlds = {
        "xyz", "top", "gq", "cf", "tk", "ml", "ga", "cc", "ru", "cn"
    },
    threshold = {
        new_domains = 5, -- alerts after X new domains
        query_freq = 60 -- queries/minute threshold
    },
    update_whitelist = true -- auto-update from seen traffic
}

-- State tracking
local dns_state = {
    known_domains = {},
    domain_counters = {},
    last_alert = 0
}

-- DNS Analysis
local dns_monitor = Proto("dnsmon", "DNS Resolver Monitor")

local f_dns_qry_name = Field.new("dns.qry.name")
local f_dns_qry_type = Field.new("dns.qry.type")
local f_dns_flags = Field.new("dns.flags")

function dns_monitor.dissector(tvb, pinfo, tree)
    if pinfo.port ~= 53 and pinfo.dst_port ~= 53 then return end
    
    local qry_name = f_dns_qry_name()
    local qry_type = f_dns_qry_type()
    
    if not qry_name then return end
    
    local domain = tostring(qry_name):lower()
    local tld = domain:match("[^.]+$")
    
    -- Check against whitelist
    local is_whitelisted = false
    for _, wl_domain in ipairs(config.whitelist) do
        if string.find(domain, wl_domain, 1, true) then
            is_whitelisted = true
            break
        end
    end
    
    -- Domain tracking
    if not dns_state.known_domains[domain] then
        dns_state.known_domains[domain] = true
        if config.update_whitelist then
            table.insert(config.whitelist, domain)
        end
    end
    
    -- Suspicious checks
    local is_suspicious = false
    local reason = ""
    
    if not is_whitelisted then
        -- New domain check
        if not dns_state.domain_counters[domain] then
            dns_state.domain_counters[domain] = 0
            reason = "New domain"
            is_suspicious = true
        end
        
        -- TLD check
        for _, suspicious_tld in ipairs(config.suspicious_tlds) do
            if tld == suspicious_tld then
                reason = reason .. (reason ~= "" and ", " or "") .. "Suspicious TLD"
                is_suspicious = true
                break
            end
        end
        
        -- Query frequency
        dns_state.domain_counters[domain] = (dns_state.domain_counters[domain] or 0) + 1
        if dns_state.domain_counters[domain] > config.threshold.query_freq then
            reason = reason .. (reason ~= "" and ", " or "") .. "High frequency"
            is_suspicious = true
        end
    end
    
    -- Alerting
    if is_suspicious and os.time() - dns_state.last_alert > 60 then
        local alert = string.format(
            "Suspicious DNS: %s (%s)",
            domain,
            reason
        )
        register_alert("SUSPICIOUS_DNS", alert, 85)
        dns_state.last_alert = os.time()
    end
end

-- Initialize
function dns_monitor.init()
    -- Load persisted state if available
    local state_file = io.open("dns_monitor.state", "r")
    if state_file then
        local content = state_file:read("*a")
        state_file:close()
        dns_state = loadstring(content)() or dns_state
    end
end

function dns_monitor.cleanup()
    -- Save state on shutdown
    local state_file = io.open("dns_monitor.state", "w")
    if state_file then
        state_file:write("return " .. table.tostring(dns_state))
        state_file:close()
    end
end

register_postdissector(dns_monitor)