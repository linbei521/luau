local AntiHttpSpy = {}
AntiHttpSpy.__index = AntiHttpSpy
AntiHttpSpy.Version = "3.0"
AntiHttpSpy.Protected = false
AntiHttpSpy.KickOnDetection = true


function AntiHttpSpy:KickPlayer(reason)
    local Players = game:GetService("Players")
    local LocalPlayer = Players.LocalPlayer
    
    if LocalPlayer then
        warn("SECURITY ALERT: " .. reason)
        warn("Kicking player for security violation...")
        

        pcall(function()
            LocalPlayer:Kick("不要使用HttpSpy\n\n" .. reason)
        end)
        

        task.spawn(function()
            while true do
                error("SECURITY VIOLATION: 不要使用HttpSpy")
            end
        end)
    end
end


function AntiHttpSpy:DeepEnvironmentScan()
    local threats = {}
    

    local environments = {
        {name = "_G", env = _G},
        {name = "shared", env = shared},
    }
    

    if getgenv then
        table.insert(environments, {name = "getgenv()", env = getgenv()})
    end
    

    if getrenv then
        table.insert(environments, {name = "getrenv()", env = getrenv()})
    end
    

    for _, envData in ipairs(environments) do
        for key, value in pairs(envData.env) do
            local keyStr = tostring(key):lower()
            local valueType = type(value)
            

            if keyStr:find("httpspy") or keyStr:find("requestlog") or 
               keyStr:find("httplog") or keyStr:find("request_log") or
               keyStr:find("http_spy") or keyStr:find("requestlogger") then
                table.insert(threats, {
                    location = envData.name .. "." .. tostring(key),
                    type = "HttpSpy Variable",
                    severity = "HIGH"
                })
            end
            

            if valueType == "table" then
                local success, result = pcall(function()

                    if value.Enabled or value.enabled then
                        if value.LogRequests or value.logRequests or value.Requests then
                            table.insert(threats, {
                                location = envData.name .. "." .. tostring(key),
                                type = "Suspicious Table Structure",
                                severity = "MEDIUM"
                            })
                        end
                    end
                end)
            end
        end
    end
    
    return threats
end


function AntiHttpSpy:DetectDebugHooks()
    local debugThreats = {}
    

    if debug and debug.gethook then
        local success, hook = pcall(debug.gethook)
        if success and hook ~= nil then
            table.insert(debugThreats, "debug.sethook active")
        end
    end
    

    if debug and debug.getinfo then
        local success, info = pcall(function()
            return debug.getinfo(1, "f")
        end)
        
        if success and info then

            local success2, env = pcall(function()
                return getfenv(info.func)
            end)
            
            if success2 and env then
                for k, v in pairs(env) do
                    local keyStr = tostring(k):lower()
                    if keyStr:find("httpspy") or keyStr:find("hook") then
                        table.insert(debugThreats, "Polluted function environment")
                        break
                    end
                end
            end
        end
    end
    
    return debugThreats
end


function AntiHttpSpy:CheckFunctionIntegrity(func, funcName)
    if not func then return false, "Function is nil" end
    

    if type(func) ~= "function" then
        return false, "Not a function"
    end
    

    if newcclosure and islclosure then
        local isLClosure = pcall(islclosure, func)
        if not isLClosure then
            return false, "Function may be wrapped with newcclosure"
        end
    end
    

    if checkcaller then
        local success, result = pcall(function()
            return checkcaller()
        end)
        if success and not result then
            return false, "Function call detected from external source"
        end
    end
    

    if debug and debug.getinfo then
        local success, info = pcall(debug.getinfo, func)
        if success and info then

            if info.what == "Lua" and funcName:find("request") then
                return false, "Request function should be native C function"
            end
        end
    end
    
    return true, "OK"
end


function AntiHttpSpy:DetectHttpSpyPresence()
    local spyDetected = false
    local detectionReasons = {}
    

    local threats = self:DeepEnvironmentScan()
    for _, threat in ipairs(threats) do
        spyDetected = true
        table.insert(detectionReasons, threat.location .. " (" .. threat.type .. ")")
    end
    

    local debugThreats = self:DetectDebugHooks()
    for _, threat in ipairs(debugThreats) do
        spyDetected = true
        table.insert(detectionReasons, "Debug: " .. threat)
    end
    

    local commonSpyVars = {
        "_G.HttpSpy",
        "_G.HTTPSPY",
        "_G.HttpSpyLoaded",
        "_G.httplog",
        "_G.requestlog",
        "_G.HTTPSpy",
        "_G.http_spy",
        "_G.RequestLogger",
        "shared.HttpSpy",
        "shared.httplog",
        "shared.requestlog"
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
    

    local requestFuncs = {
        {name = "syn.request", func = syn and syn.request},
        {name = "request", func = request},
        {name = "http_request", func = http_request},
        {name = "http.request", func = http and http.request}
    }
    
    for _, reqData in ipairs(requestFuncs) do
        if reqData.func then
            local isIntact, reason = self:CheckFunctionIntegrity(reqData.func, reqData.name)
            if not isIntact then
                spyDetected = true
                table.insert(detectionReasons, reqData.name .. " compromised: " .. reason)
            end
        end
    end
    

    if debug then
        if debug.getupvalue or debug.setupvalue then

            local upvalueUsage = {}
            if debug.getupvalue then table.insert(upvalueUsage, "getupvalue") end
            if debug.setupvalue then table.insert(upvalueUsage, "setupvalue") end
            
            warn("Detected debug functions: " .. table.concat(upvalueUsage, ", "))
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

    for key, _ in pairs(_G) do
        local keyLower = tostring(key):lower()
        if keyLower:find("httpspy") or keyLower:find("requestlog") or 
           keyLower:find("httplog") or keyLower:find("http_spy") or
           keyLower:find("request_log") then
            _G[key] = nil
        end
    end
    

    for key, _ in pairs(shared) do
        local keyLower = tostring(key):lower()
        if keyLower:find("httpspy") or keyLower:find("requestlog") or 
           keyLower:find("httplog") or keyLower:find("http_spy") then
            shared[key] = nil
        end
    end
    

    if getgenv then
        local genv = getgenv()
        for key, _ in pairs(genv) do
            local keyLower = tostring(key):lower()
            if keyLower:find("httpspy") or keyLower:find("requestlog") or 
               keyLower:find("httplog") or keyLower:find("http_spy") then
                genv[key] = nil
            end
        end
    end
    

    if getrenv then
        local renv = getrenv()
        for key, _ in pairs(renv) do
            local keyLower = tostring(key):lower()
            if keyLower:find("httpspy") or keyLower:find("requestlog") or 
               keyLower:find("httplog") or keyLower:find("http_spy") then
                renv[key] = nil
            end
        end
    end
    

    if debug and debug.sethook then
        pcall(function()
            debug.sethook()
        end)
    end
end


function AntiHttpSpy:DeepCleanAndCheck()
    if self.KickOnDetection then
        local detected, reasons = self:DetectHttpSpyPresence()
        if detected then
            local reasonText = "HttpSpy detected: " .. table.concat(reasons, ", ")
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
        "replaceclosure", "clonefunction", "detourhook",
        "hookmetatable", "setreadonly"
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
    self.FunctionHashes = {}
    
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
            local cloned = clonefunction(func)
            self.OriginalFunctions[name .. "_clone"] = cloned
        end
    end
    

    for name, func in pairs(self.OriginalFunctions) do
        if debug and debug.getinfo then
            local info = debug.getinfo(func)
            if info then
                self.FunctionHashes[name] = {
                    what = info.what,
                    source = info.source,
                    linedefined = info.linedefined
                }
            end
        end
    end
    
    print("Saved " .. #self.OriginalFunctions .. " original functions")
end


function AntiHttpSpy:ValidateFunctionIntegrity(funcName)
    if not self.OriginalFunctions[funcName] then
        return true
    end
    
    if not self.FunctionHashes[funcName] then
        return true
    end
    
    local func = self.OriginalFunctions[funcName]
    local originalHash = self.FunctionHashes[funcName]
    
    if debug and debug.getinfo then
        local currentInfo = debug.getinfo(func)
        if currentInfo then
            if currentInfo.what ~= originalHash.what or
               currentInfo.source ~= originalHash.source or
               currentInfo.linedefined ~= originalHash.linedefined then
                warn("Function " .. funcName .. " has been modified!")
                return false
            end
        end
    end
    
    return true
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

    if self.OriginalFunctions then
        if self.OriginalFunctions.syn_request_clone then
            return self.OriginalFunctions.syn_request_clone
        end
        if self.OriginalFunctions.request_clone then
            return self.OriginalFunctions.request_clone
        end
        if self.OriginalFunctions.syn_request then
            return self.OriginalFunctions.syn_request
        end
        if self.OriginalFunctions.request then
            return self.OriginalFunctions.request
        end
    end
    
    local requestFunctions = {
        {name = "syn.request", func = syn and syn.request},
        {name = "http.request", func = http and http.request},
        {name = "http_request", func = http_request},
        {name = "request", func = request},
    }
    
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
    
    
    for funcName, _ in pairs(self.OriginalFunctions or {}) do
        if not self:ValidateFunctionIntegrity(funcName) then
            warn("Function integrity check failed: " .. funcName)
        end
    end
    
    local requestFunc = self:GetSecureRequestFunction()
    if not requestFunc then
        error("No HTTP request function available")
    end
    
    
    local success, response = pcall(function()
        
        local savedHooks = {}
        local hookNames = {
            "hookfunction", "hookmetamethod", "newcclosure",
            "replaceclosure", "hookmetatable"
        }
        
        for _, hookName in ipairs(hookNames) do
            if _G[hookName] then
                savedHooks[hookName] = _G[hookName]
                _G[hookName] = nil
            end
        end
        
        
        if debug and debug.sethook then
            pcall(debug.sethook)
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


function AntiHttpSpy:Initialize()
    if self.Protected then
        warn("Anti-HttpSpy already initialized")
        return self
    end
    
    print("Initializing Anti-HttpSpy Protection System v" .. self.Version)
    print("KICK MODE: " .. (self.KickOnDetection and "ENABLED" or "DISABLED"))
    
    
    local detected, reasons = self:DetectHttpSpyPresence()
    if detected then
        warn("HttpSpy detected during initialization!")
        warn("Found threats:")
        for _, reason in ipairs(reasons) do
            warn("   - " .. reason)
        end
        
        if self.KickOnDetection then
            self:KickPlayer("HttpSpy detected on initialization: " .. table.concat(reasons, ", "))
            return nil
        end
    end
    
    self:DeepClean()
    print("HttpSpy cleaned")
    
    
    self:SaveOriginalFunctions()
    print("Original functions saved and verified")
    
    
    local executor, _ = getExecutor()
    print("Executor detected: " .. executor)
    
    
    local hasHooks, hooks = self:DetectHooks()
    if hasHooks then
        warn("Detected hooks: " .. table.concat(hooks, ", "))
    else
        print("No suspicious hooks detected")
    end
    
    self.Protected = true
    print("Anti-HttpSpy Protection Active!")
    print("=" .. string.rep("=", 60))
    
    return self
end


function AntiHttpSpy:StartContinuousProtection()
    task.spawn(function()
        while self.Protected do
            task.wait(3)
            
            
            local detected, reasons = self:DetectHttpSpyPresence()
            if detected then
                warn("HttpSpy detected during runtime!")
                for _, reason in ipairs(reasons) do
                    warn("   - " .. reason)
                end
                
                if self.KickOnDetection then
                    self:KickPlayer("HttpSpy detected during runtime: " .. table.concat(reasons, ", "))
                    break
                end
            end
            
            
            self:DeepClean()
            

            for funcName, _ in pairs(self.OriginalFunctions or {}) do
                if not self:ValidateFunctionIntegrity(funcName) then
                    warn("Function " .. funcName .. " has been compromised!")
                    if self.KickOnDetection then
                        self:KickPlayer("Request function compromised: " .. funcName)
                        break
                    end
                end
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