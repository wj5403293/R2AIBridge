package com.r2aibridge.mcp

import android.util.Log
import kotlinx.coroutines.runBlocking
import com.r2aibridge.R2Core
import com.r2aibridge.ShellUtils
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.serialization.json.*
import org.json.JSONObject
import java.io.File
import java.text.SimpleDateFormat
import java.util.*

// 定义一个简单的 Prompt 结构
data class R2Prompt (
    val name: String,
    val description: String,
    val promptText: String
)

// 预设的"黄金工作流"列表
val availablePrompts = listOf(
    R2Prompt(
        name = "analyze_full",
        description = "🚀 全自动分析 (Auto Analysis)",
        promptText = """
            请对当前文件执行完整的自动化分析流程：
            1. 运行 `aaa` 进行深度分析。
            2. 运行 `i` 获取二进制文件基本信息（架构、大小、类型）。
            3. 运行 `afl` 列出所有识别到的函数。
            4. 运行 `iz` 列出部分字符串（前10个）。
            执行完上述命令后，请为我总结这个文件的主要功能和特征。
        """.trimIndent()
    ),
    R2Prompt(
        name = "check_security",
        description = "🛡️ 检查安全保护 (Check Security)",
        promptText = """
            请检查当前二进制文件的安全加固措施：
            1. 运行 `i` 查看 permissions 和 canary/nx/pic 等标志位。
            2. 分析是否开启了 PIE (Position Independent Executable)。
            3. 检查是否有符号表残留。
            请以此判断该 App/Library 的逆向难度。
        """.trimIndent()
    ),
    R2Prompt(
        name = "find_vulnerability",
        description = "🐛 寻找潜在漏洞 (Find Vulns)",
        promptText = """
            请尝试寻找常见的漏洞模式：
            1. 使用 `/ strcpy` 或 `/ system` 等命令搜索危险函数调用。
            2. 检查是否有硬编码的敏感字符串 (使用 `iz`)。
            3. 重点关注 JNI 接口函数 (Java_...)。
        """.trimIndent()
    ),
    R2Prompt(
        name = "prepare_patch",
        description = "🔧 准备 Patch 环境 (Setup Patching)",
        promptText = """
            我已经准备好修改代码，请帮我做好准备工作：
            1. 运行 `e io.cache=true` 开启缓存模式（安全防呆）。
            2. 运行 `oo+` 尝试以读写模式重载文件。
            3. 检查当前架构 `e asm.arch` 和位宽 `e asm.bits` 是否正确。
            请确认上述步骤完成后，告诉我“准备就绪，请下达 Patch 指令”。
        """.trimIndent()
    ),
    R2Prompt(
        name = "smart_rename",
        description = "🏷️ 智能重命名 (Smart Rename)",
        promptText = """
            请对当前函数进行语义分析并重命名：
            1. 运行 `pdf` 获取当前函数的汇编代码。
            2. 仔细阅读汇编逻辑，推断该函数的功能（例如：是网络请求？是MD5计算？还是UI点击事件？）。
            3. 如果你能确定其功能，请立即调用 `rename_function` 将其重命名为更有意义的名字（如 `calc_md5`, `check_license`）。
            4. 如果无法确定，请保留原名并告诉我分析到了什么。
        """.trimIndent()
    ),
    R2Prompt(
        name = "emulate_code",
        description = "🧪 模拟执行 (Emulate)",
        promptText = """
            请帮我模拟执行当前函数片段，以分析其计算逻辑：
            1. 目标：计算当输入参数 x0=1 时，函数的返回值。
            2. 操作：调用 `simulate_execution`。
            3. 参数建议：
               - session_id: 当前会话 ID
               - address: 当前 seek 地址
               - steps: 50 (足够跑完一个小逻辑)
               - init_regs: "x0=1"
            4. 分析输出的寄存器状态，告诉我最终 x0 是多少。
        """.trimIndent()
    ),
    R2Prompt(
        name = "decrypt_strings_auto",
        description = "🔐 自动化解密混淆字符串 (Auto Decrypt Strings)",
        promptText = """
            请协助我针对当前目标函数执行批量字符串解密。这是一个针对 OLLVM 混淆或自定义加密函数的自动化流程。

            请严格按照以下步骤操作：
            1. **环境侦察**：
               - 运行 `i` 检查当前架构 (ARM64/ARM32/x86)。
               - 运行 `pdf` 阅读目标函数的汇编代码。
            
            2. **参数推断 (至关重要)**：
               - **指令宽度 (`instr_size`)**：ARM64填4；ARM32填4(Thumb填2)；x86请填平均值(如3)或精确计算。
               - **结果寄存器 (`result_reg`)**：解密后的字符串指针放在哪里？(ARM通常是 `x0`/`r0`，x86通常是 `eax`/`rax`)。
               - **传参方式**：
                 - 如果是寄存器传参 (ARM)，直接进行下一步。
                 - 如果是栈传参 (x86 `push`)，请构造 `custom_init` 指令来模拟栈数据 (例如 `wv 0x1000 @ esp+4`)。
            
            3. **执行模拟**：
               - 调用 `batch_decrypt_strings` 工具。
               - 填入你分析出的 `result_reg`, `instr_size` 和 `custom_init`。
               - 如果函数引用了 `.rodata` 大表，请适当增大 `map_size` (如 `0x100000`)。

            执行完成后，请为我列出解密成功的字符串清单。
        """.trimIndent()
    )

)

/**
 * R2AI 全局配置管理
 * 使用 SharedPreferences 存储用户配置的输出限制参数
 */
object R2AIConfig {
    private const val PREFS_NAME = "r2ai_config"
    private const val KEY_MAX_LINES = "max_lines"
    private const val KEY_MAX_CHARS = "max_chars"

    // 编译期默认值（仅作为后备，实际值从 SharedPreferences 读取）
    private const val DEFAULT_MAX_LINES = 800
    private const val DEFAULT_MAX_CHARS = 32000

    private lateinit var prefs: android.content.SharedPreferences

    fun init(context: android.content.Context) {
        prefs = context.getSharedPreferences(PREFS_NAME, android.content.Context.MODE_PRIVATE)
    }

    fun getMaxLines(): Int {
        return try {
            prefs.getInt(KEY_MAX_LINES, DEFAULT_MAX_LINES)
        } catch (e: Exception) {
            DEFAULT_MAX_LINES
        }
    }

    fun getMaxChars(): Int {
        return try {
            prefs.getInt(KEY_MAX_CHARS, DEFAULT_MAX_CHARS)
        } catch (e: Exception) {
            DEFAULT_MAX_CHARS
        }
    }

    fun setMaxLines(lines: Int) {
        prefs.edit().putInt(KEY_MAX_LINES, lines.coerceIn(200, 50000)).apply()
    }

    fun setMaxChars(chars: Int) {
        prefs.edit().putInt(KEY_MAX_CHARS, chars.coerceIn(12000, 500000)).apply()
    }
}

object MCPServer {
        // --- [新增] Termux 常量与辅助函数 ---
        // AI 脚本沙盒路径
        private const val TERMUX_AI_DIR = "/data/data/com.termux/files/home/AI"

        /**
         * 获取 Termux 的用户 ID (UID)
         * 因为 Termux 不是以 Root 运行的，我们需要知道它的 UID 才能用 su 切换过去
         */
        private fun getTermuxUser(): String {
            // 通过查看 Termux 数据目录的所有者来判断 UID
            val result = ShellUtils.execCommand("ls -ldn /data/data/com.termux", isRoot = true)
            if (result.isSuccess) {
                // 输出类似: drwx------ 18 10157 10157 ...
                val parts = result.successMsg.trim().split("\\s+".toRegex())
                if (parts.size > 2) {
                    return parts[2] // 这就是 UID (例如 10157)
                }
            }
            return "10421" // 如果检测失败，使用默认常见的 Termux UID
        }

        /**
         * 构造 Termux 环境变量
         * ⚠️ 关键：如果没有这个，Python/Node 等命令会因为找不到库而报错
         */
        private fun getTermuxEnvSetup(): String {
        val termuxPrefix = "/data/data/com.termux/files/usr"
        val termuxHome = "/data/data/com.termux/files/home"
        return "export PATH=${termuxPrefix}/bin:$" + "PATH && " +
            "export LD_LIBRARY_PATH=${termuxPrefix}/lib && " +
            "export HOME=${termuxHome} && " +
            "export TMPDIR=/data/local/tmp && " +
            "mkdir -p $TERMUX_AI_DIR && " +
            "cd $TERMUX_AI_DIR && "
        }

        /**
         * 简单的安全检查，防止 AI 删库
         */
        private fun isDangerousCommand(command: String): Boolean {
            val dangerousCommands = listOf(
                "rm -rf /", "rm -rf /*", "mkfs", "dd if=", 
                "reboot", "shutdown", ":(){ :|:& };:"
            )
            val lower = command.lowercase()
            return dangerousCommands.any { lower.contains(it) }
        }
    
    private const val TAG = "R2AI"
    
    private val dateFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.getDefault())
    
    private val json = Json { 
        ignoreUnknownKeys = true
        isLenient = true
        prettyPrint = true
        coerceInputValues = true
    }
    
    // 当前打开的文件路径，用于记忆宫殿功能
    private var currentFilePath: String = ""

    private fun logInfo(msg: String) {
        val timestamp = dateFormat.format(Date())
        val logMsg = "[$timestamp] $msg"
        Log.i(TAG, logMsg)
        println(logMsg)
    }

    private fun logError(msg: String, error: String? = null) {
        val timestamp = dateFormat.format(Date())
        val logMsg = "[$timestamp] ⚠️ $msg" + (error?.let { ": $it" } ?: "")
        Log.e(TAG, logMsg)
        println(logMsg)
    }

    /**
     * 清洗和截断 Radare2 的输出，防止 AI 崩溃
     */
    private fun sanitizeOutput(
        raw: String,
        maxLines: Int,
        maxChars: Int,
        filterGarbage: Boolean = false
    ): String {
        if (raw.isBlank()) return "(Empty Output)"

        var output = raw

        // 1. 过滤垃圾段 (如 .eh_frame, .text 中的乱码)
        if (filterGarbage) {
            output = output.lineSequence()
                .filter { line ->
                    !line.contains(".eh_frame") &&
                    !line.contains(".gcc_except_table") &&
                    !line.contains("libunwind")
                }
                .joinToString("\n")
        }

        // 2. 行数截断（先截断行，保留完整语义）
        val lines = output.lines()
        if (lines.size > maxLines) {
            logInfo("输出超过 $maxLines 行 (共 ${lines.size} 行)，已截断")
            output = lines.take(maxLines).joinToString("\n")
        }

        // 3. 字符数截断（后截断字符，作为兜底保护）
        if (output.length > maxChars) {
            logInfo("输出超过 $maxChars 字符，已截断")
            return output.take(maxChars) + "\n\n[⛔ SYSTEM: 输出超过 $maxChars 字符，已强制截断。请缩小分析范围。]"
        }

        return output
    }

    /**
     * 使用全局配置的 sanitizeOutput 重载
     */
    private fun sanitizeOutput(
        raw: String,
        filterGarbage: Boolean = false
    ): String {
        return sanitizeOutput(
            raw,
            maxLines = R2AIConfig.getMaxLines(),
            maxChars = R2AIConfig.getMaxChars(),
            filterGarbage = filterGarbage
        )
    }

    /**
     * 检查设备是否有 Root 权限
     */
    private fun hasRootPermission(): Boolean {
        return try {
            logInfo("检查 Root 权限...")
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "echo test"))
            val exitCode = process.waitFor()
            val hasPermission = exitCode == 0
            logInfo("Root 权限检查结果: $hasPermission (exitCode: $exitCode)")
            hasPermission
        } catch (e: Exception) {
            logError("Root 权限检查异常", e.message)
            false
        }
    }

    /**
     * Root 复制逻辑
     */
    private fun tryRootCopy(originalPath: String): String? {
        if (!hasRootPermission()) {
            logError("设备未获得 Root 权限，无法执行 Root 复制", "文件: $originalPath")
            return null
        }

        try {
            val originalFile = File(originalPath)
            if (!originalFile.exists()) {
                logError("原始文件不存在，无法复制", originalPath)
                return null
            }

            val cacheDir = File(System.getProperty("java.io.tmpdir"), "r2_root_cache")
            if (!cacheDir.exists()) {
                cacheDir.mkdirs()
            }

            val fileName = originalFile.name
            val copyPath = File(cacheDir, "${System.currentTimeMillis()}_${fileName}").absolutePath

            logInfo("尝试 Root 复制文件: $originalPath -> $copyPath")

            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "cp '$originalPath' '$copyPath' && chmod 777 '$copyPath'"))
            val exitCode = process.waitFor()

            if (exitCode == 0) {
                val copyFile = File(copyPath)
                if (copyFile.exists() && copyFile.canRead()) {
                    logInfo("Root 复制成功: $copyPath")
                    return copyPath
                } else {
                    logError("Root 复制后文件不存在或不可读", copyPath)
                }
            } else {
                val error = process.errorStream.bufferedReader().readText()
                logError("Root 复制失败", "exitCode=$exitCode, error=$error")
            }
        } catch (e: Exception) {
            logError("Root 复制异常", e.message)
        }

        return null
    }

    fun cleanupRootCopies() {
        try {
            val cacheDir = File(System.getProperty("java.io.tmpdir"), "r2_root_cache")
            if (cacheDir.exists() && cacheDir.isDirectory) {
                val files = cacheDir.listFiles()
                if (files != null) {
                    var deletedCount = 0
                    for (file in files) {
                        if (file.isFile && file.delete()) {
                            deletedCount++
                        }
                    }
                    logInfo("已清理 $deletedCount 个 Root 复制副本文件")
                }
            }
        } catch (e: Exception) {
            logError("清理 Root 复制副本失败", e.message)
        }
    }

    fun configure(app: Application, onLogEvent: (String) -> Unit) {
        app.install(ContentNegotiation) {
            json(json)
        }

        app.intercept(ApplicationCallPipeline.Plugins) {
            call.response.header("Access-Control-Allow-Origin", "*")
            call.response.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            call.response.header("Access-Control-Allow-Headers", "*")
            
            if (call.request.httpMethod == HttpMethod.Options) {
                call.respond(HttpStatusCode.OK)
                finish()
            }
        }

        app.routing {
            get("/") {
                val info = buildJsonObject {
                    put("name", "Radare2 MCP Server")
                    put("version", "1.0")
                    put("status", "running")
                    put("endpoints", JsonArray(listOf(
                        JsonPrimitive("/mcp - Standard MCP endpoint"),
                        JsonPrimitive("/health - Health check")
                    )))
                }
                
                call.respondText(
                    text = json.encodeToString(JsonObject.serializer(), info),
                    contentType = ContentType.Application.Json,
                    status = HttpStatusCode.OK
                )
            }

            post("/mcp") {
                var requestId: JsonElement? = null
                var method = "unknown"

                try {
                    val requestBody = call.receiveText()

                    if (requestBody.isBlank()) {
                        val errorObj = buildJsonObject {
                            put("code", -32700)
                            put("message", "Empty request body")
                        }
                        val errorResp = buildJsonObject {
                            put("jsonrpc", "2.0")
                            put("id", JsonNull)
                            put("error", errorObj)
                        }.toString()

                        call.respondText(
                            text = errorResp,
                            contentType = ContentType.Application.Json,
                            status = HttpStatusCode.BadRequest
                        )
                        return@post
                    }

                    val request = json.decodeFromString<MCPRequest>(requestBody)
                    requestId = request.id
                    method = request.method

                    val idStr = when (val id = request.id) {
                        is JsonPrimitive -> id.content.take(8)
                        else -> "null"
                    }

                    val clientIp = call.request.local.remoteHost
                    val logMsg = "📥 ${request.method} | $clientIp | ID:$idStr"
                    logInfo("[App -> R2] ${request.method} (ID: $idStr)")
                    onLogEvent(logMsg)

                    if (method == "notifications/initialized") {
                        logInfo("客户端已初始化")
                        call.respond(HttpStatusCode.NoContent)
                        return@post
                    }

                    val result = when (request.method) {
                        "initialize" -> handleInitialize(request.params)
                        "ping" -> handlePing()
                        "tools/list" -> handleToolsList()
                        "tools/call" -> {
                            val toolName = request.params?.get("name")?.jsonPrimitive?.content ?: "unknown"
                            val toolLogMsg = "🔧 工具调用: $toolName | $clientIp"
                            onLogEvent(toolLogMsg)
                            handleToolCall(request.params, onLogEvent)
                        }
                        "prompts/list" -> {
                            val promptsJson = JsonArray(availablePrompts.map { prompt ->
                                buildJsonObject {
                                    put("name", prompt.name)
                                    put("description", prompt.description)
                                    
                                    // 🛠️【修改点】添加一个"占位参数"，把 UI 激活！
                                    put("arguments", JsonArray(listOf(
                                        buildJsonObject {
                                            put("name", "note") // 参数名
                                            put("description", "备注 (可选)") // 显示给用户看
                                            put("required", false) // 设为 false，用户不填也能提交
                                        }
                                    )))
                                }
                            })

                            val result = buildJsonObject {
                                put("prompts", promptsJson)
                            }
                            result
                        }
                        "prompts/get" -> {
                            try {
                                // 1. 获取参数
                                val params = request.params
                                val promptName = params?.get("name")?.jsonPrimitive?.content
                                
                                Log.e("R2AI", "收到 prompts/get 请求: $promptName") // <--- 关键日志 1

                                if (promptName == null) {
                                    val errorObj = buildJsonObject {
                                        put("code", -32602)
                                        put("message", "Missing 'name' parameter")
                                    }
                                    val errorResp = buildJsonObject {
                                        put("jsonrpc", "2.0")
                                        put("id", request.id ?: JsonNull)
                                        put("error", errorObj)
                                    }
                                    call.respondText(
                                        text = errorResp.toString(),
                                        contentType = ContentType.Application.Json,
                                        status = HttpStatusCode.OK
                                    )
                                    return@post
                                }

                                // 2. 查找对应的 Prompt
                                val targetPrompt = availablePrompts.find { it.name == promptName }

                                if (targetPrompt != null) {
                                    Log.e("R2AI", "找到 Prompt，准备发送: ${targetPrompt.description}") // <--- 关键日志 2

                                    // 3. 构建响应
                                    val result = buildJsonObject {
                                        put("description", targetPrompt.description)
                                        put("messages", JsonArray(listOf(
                                            buildJsonObject {
                                                put("role", "user")
                                                put("content", buildJsonObject {
                                                    put("type", "text")
                                                    put("text", targetPrompt.promptText)
                                                })
                                            }
                                        )))
                                    }
                                    
                                    // 发送
                                    Log.e("R2AI", "发送成功") // <--- 关键日志 3
                                    result

                                } else {
                                    Log.e("R2AI", "未找到 Prompt: $promptName")
                                    val errorObj = buildJsonObject {
                                        put("code", -32602)
                                        put("message", "Prompt not found: $promptName")
                                    }
                                    val errorResp = buildJsonObject {
                                        put("jsonrpc", "2.0")
                                        put("id", request.id ?: JsonNull)
                                        put("error", errorObj)
                                    }
                                    call.respondText(
                                        text = errorResp.toString(),
                                        contentType = ContentType.Application.Json,
                                        status = HttpStatusCode.OK
                                    )
                                    return@post
                                }

                            } catch (e: Exception) {
                                Log.e("R2AI", "prompts/get 发生崩溃", e) // <--- 关键日志 4 (捕获崩溃)
                                val errorObj = buildJsonObject {
                                    put("code", -32603)
                                    put("message", "Internal error: ${e.message}")
                                }
                                val errorResp = buildJsonObject {
                                    put("jsonrpc", "2.0")
                                    put("id", request.id ?: JsonNull)
                                    put("error", errorObj)
                                }
                                call.respondText(
                                    text = errorResp.toString(),
                                    contentType = ContentType.Application.Json,
                                    status = HttpStatusCode.OK
                                )
                                return@post
                            }
                        }
                        "resources/list" -> {
                            val resources = JsonArray(listOf(
                                // 1. 文件基础信息
                                buildJsonObject {
                                    put("uri", "r2://target-info")
                                    put("name", "ℹ️ 目标文件情报 (Binary Info)")
                                    put("description", "二进制文件的基本信息：架构(Arch)、位宽(Bits)、文件类型、编译器信息等。基于 r2 'i' 命令。")
                                    put("mimeType", "text/plain")
                                },
                                // 2. 导入表 (关键依赖)
                                buildJsonObject {
                                    put("uri", "r2://imports")
                                    put("name", "📦 导入函数列表 (Imports)")
                                    put("description", "目标文件调用的外部函数列表 (libc, JNI, OpenSSL 等)。用于快速判断程序功能。")
                                    put("mimeType", "text/plain")
                                },
                                // 3. 设备环境信息
                                buildJsonObject {
                                    put("uri", "r2://device-env")
                                    put("name", "🖥️ 设备环境信息 (Device Environment)")
                                    put("description", "当前设备的系统版本、架构、Root 状态等环境信息。不依赖 R2 会话，可随时读取。")
                                    put("mimeType", "text/plain")
                                }
                            ))
                            
                            buildJsonObject { put("resources", resources) }
                        }
                        
                        "resources/templates/list" -> {
                             buildJsonObject { put("resourceTemplates", JsonArray(emptyList())) }
                        }
                        
                        "resources/read" -> {
                            val uri = request.params?.get("uri")?.jsonPrimitive?.content ?: ""
                            Log.i(TAG, "📖 读取资源: $uri")

                            // 尝试获取会话，但如果为 null 也不要立即报错
                            val session = R2SessionManager.getAllSessions().values.lastOrNull()

                            val content = when (uri) {
                                // case 1: 设备环境 (完全不依赖 session)
                                "r2://device-env" -> {
                                    val prop = ShellUtils.execCommand("getprop ro.build.version.release", false).successMsg
                                    val arch = System.getProperty("os.arch") ?: "unknown"
                                    val isRoot = ShellUtils.execCommand("id", true).successMsg.contains("uid=0")
                                    """
                                    OS: Android $prop
                                    Arch: $arch
                                    Rooted: $isRoot
                                    Termux Dir: $TERMUX_AI_DIR
                                    """.trimIndent()
                                }

                                // case 3: 目标信息 (强依赖 session)
                                "r2://target-info" -> {
                                    if (session != null) {
                                        val basicInfo = R2Core.executeCommand(session.corePtr, "i")
                                        val sections = R2Core.executeCommand(session.corePtr, "iSq")
                                        "=== Basic Info ===\n$basicInfo\n=== Sections ===\n$sections"
                                    } else {
                                        "❌ 错误: 无活动 R2 会话。无法执行 'i' 命令。"
                                    }
                                }

                                // case 4: 导入表 (强依赖 session)
                                "r2://imports" -> {
                                    if (session != null) {
                                        val rawImports = R2Core.executeCommand(session.corePtr, "ii")
                                        sanitizeOutput(rawImports, maxLines = 100, maxChars = 8000)
                                    } else {
                                        "❌ 错误: 无活动 R2 会话。无法执行 'ii' 命令。"
                                    }
                                }

                                else -> "❌ 未知资源 URI: $uri"
                            }

                            // 构造响应
                            buildJsonObject {
                                put("contents", JsonArray(listOf(
                                    buildJsonObject {
                                        put("uri", uri)
                                        put("mimeType", "text/plain")
                                        put("text", content)
                                    }
                                )))
                            }
                        }
                        else -> {
                            logError("未知方法", method)
                            val errorObj = buildJsonObject {
                                put("code", -32601)
                                put("message", "Method not found: ${request.method}")
                            }
                            val errorResp = buildJsonObject {
                                put("jsonrpc", "2.0")
                                put("id", request.id ?: JsonNull)
                                put("error", errorObj)
                            }.toString()

                            call.respondText(
                                text = errorResp,
                                contentType = ContentType.Application.Json,
                                status = HttpStatusCode.OK
                            )
                            return@post
                        }
                    }

                    val responseJson = buildJsonObject {
                        put("jsonrpc", "2.0")
                        put("id", request.id ?: JsonNull)
                        put("result", result)
                    }.toString()

                    if (responseJson.length < 500) {
                        logInfo("[R2 -> App] ${responseJson.take(200)}")
                    } else {
                        logInfo("[R2 -> App] ${responseJson.length} bytes")
                    }

                    call.response.header(HttpHeaders.CacheControl, "no-cache")

                    call.respondText(
                        text = responseJson,
                        contentType = ContentType.Application.Json,
                        status = HttpStatusCode.OK
                    )
                } catch (e: Exception) {
                    logError("处理请求失败", e.message)
                    onLogEvent("⚠️ 错误: ${e.message}")

                    val errorObj = buildJsonObject {
                        put("code", -32603)
                        put("message", "Internal error: ${e.message}")
                    }
                    val errorResp = buildJsonObject {
                        put("jsonrpc", "2.0")
                        put("id", requestId ?: JsonNull)
                        put("error", errorObj)
                    }.toString()

                    call.respondText(
                        text = errorResp,
                        contentType = ContentType.Application.Json,
                        status = HttpStatusCode.OK
                    )
                }
            }

            options("/*") {
                call.response.header(HttpHeaders.AccessControlAllowOrigin, "*")
                call.response.header(HttpHeaders.AccessControlAllowMethods, "GET, POST, OPTIONS")
                call.response.header(HttpHeaders.AccessControlAllowHeaders, "Content-Type, Cache-Control")
                call.respondText("", ContentType.Text.Plain, HttpStatusCode.OK)
            }

            get("/health") {
                logInfo("健康检查")
                val stats = R2SessionManager.getStats()
                call.respondText(
                    "R2 MCP Server Running\n" +
                    "Active Sessions: ${R2SessionManager.getSessionCount()}\n" +
                    "Session Stats: $stats",
                    ContentType.Text.Plain
                )
            }
        }
        
        logInfo("🚀 MCP 服务器已启动")
    }

    private fun handlePing(): JsonElement {
        logInfo("收到 ping 请求")
        
        return buildJsonObject {
            put("message", "pong")
            put("timestamp", System.currentTimeMillis())
        }
    }

    private fun handleInitialize(params: JsonObject?): JsonElement {
        val clientProtocolVersion = params?.get("protocolVersion")?.jsonPrimitive?.content
        val negotiatedVersion = clientProtocolVersion ?: "2024-11-05"
        
        logInfo("协议协商: 客户端=$clientProtocolVersion -> 最终使用=$negotiatedVersion")
        
        return buildJsonObject {
            put("protocolVersion", negotiatedVersion)
            put("capabilities", buildJsonObject {
                put("tools", buildJsonObject {
                    put("listChanged", false)
                })
            })
            put("serverInfo", buildJsonObject {
                put("name", "Radare2 MCP Server")
                put("version", "1.0")
            })
        }
    }

    private fun handleToolsList(): JsonElement {
        val tools = listOf(
            createToolSchema(
                "r2_open_file",
                "🚪 [会话管理] 打开二进制文件。默认执行基础分析 (a) 以快速识别函数。注意：对于大型文件 (>10MB)，强烈建议将 auto_analyze 设为 false 以免超时。如需深度分析，可后续调用 r2_analyze_file 或使用 r2_run_command 执行 'aa'。",
                mapOf(
                    "file_path" to mapOf("type" to "string", "description" to "二进制文件的完整路径"),
                    "session_id" to mapOf("type" to "string", "description" to "可选:使用现有会话 ID,如果不提供则自动创建"),
                    "auto_analyze" to mapOf("type" to "boolean", "description" to "是否自动执行基础分析 (aa 命令)。默认为 true。对于大文件 (>10MB) 请设为 false。", "default" to true)
                ),
                listOf("file_path")
            ),
            createToolSchema(
                "r2_analyze_file",
                "⚡ [深度分析] 一次性执行深度分析 (aaa) 并自动释放资源。支持复用现有 session_id 或根据文件路径查找会话。",
                mapOf(
                    "file_path" to mapOf("type" to "string", "description" to "二进制文件的完整路径"),
                    "session_id" to mapOf("type" to "string", "description" to "可选：现有会话 ID")
                ),
                listOf("file_path")
            ),
            createToolSchema(
                "r2_run_command",
                "⚙️ [通用命令] 在指定会话中执行任意 Radare2 命令。支持所有 r2 命令。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID"),
                    "command" to mapOf("type" to "string", "description" to "Radare2 命令"),
                    "max_lines" to mapOf("type" to "integer", "description" to "最大输出行数（默认 1000）", "default" to 1000),
                    "max_chars" to mapOf("type" to "integer", "description" to "最大输出字符数（默认 20000）", "default" to 20000)
                ),
                listOf("session_id", "command")
            ),
            createToolSchema(
                "r2_list_functions",
                "📋 [函数分析] 列出二进制文件中的已识别函数。使用 'afl' 命令。可通过 filter 过滤函数名，防止输出过多。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID"),
                    "filter" to mapOf("type" to "string", "description" to "可选:函数名过滤器（如 'sym.Java' 只显示 Java 相关函数）", "default" to ""),
                    "max_lines" to mapOf("type" to "integer", "description" to "最大输出行数（默认 500）", "default" to 500),
                    "max_chars" to mapOf("type" to "integer", "description" to "最大输出字符数（默认 16000）", "default" to 16000)
                ),
                listOf("session_id")
            ),
            createToolSchema(
                "r2_list_strings",
                "📝 [逆向第一步] 列出二进制文件中的字符串。通过配置 bin.str.min 进行底层过滤，提高大文件分析性能。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID"),
                    "mode" to mapOf("type" to "string", "description" to "搜索模式: 'data' (iz) 或 'all' (izz)", "default" to "data"),
                    "min_length" to mapOf("type" to "integer", "description" to "最小字符串长度（默认 5，在 R2 核心层过滤）", "default" to 5),
                    "max_lines" to mapOf("type" to "integer", "description" to "最大输出行数（默认 500）", "default" to 500),
                    "max_chars" to mapOf("type" to "integer", "description" to "最大输出字符数（默认 16000）", "default" to 16000)
                ),
                listOf("session_id")
            ),
            createToolSchema(
                "r2_get_xrefs",
                "🔗 [逻辑追踪必备] 获取指定地址/函数的交叉引用。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID"),
                    "address" to mapOf("type" to "string", "description" to "目标地址或函数名"),
                    "direction" to mapOf("type" to "string", "description" to "方向: 'to' (默认) 或 'from'", "default" to "to"),
                    "max_lines" to mapOf("type" to "integer", "description" to "最大输出行数（默认 50）", "default" to 50),
                    "max_chars" to mapOf("type" to "integer", "description" to "最大输出字符数（默认 8000）", "default" to 8000)
                ),
                listOf("session_id", "address")
            ),
            createToolSchema(
                "r2_get_info",
                "ℹ️ [环境感知] 获取二进制文件的详细信息。包括架构（32/64位）、平台（ARM/x86）、文件类型（ELF/DEX）等。帮助 AI 决定分析策略。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID"),
                    "detailed" to mapOf("type" to "boolean", "description" to "详细模式", "default" to false)
                ),
                listOf("session_id")
            ),
            createToolSchema(
                "r2_decompile_function",
                "🔍 [代码分析] 反编译指定地址的函数为伪代码。使用 'pdc' 命令，将汇编代码转换为类 C 语言的可读代码。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID"),
                    "address" to mapOf("type" to "string", "description" to "函数地址（十六进制格式，如：0x401000 或 main）"),
                    "max_lines" to mapOf("type" to "integer", "description" to "最大输出行数", "default" to 500),
                    "max_chars" to mapOf("type" to "integer", "description" to "最大输出字符数", "default" to 15000)
                ),
                listOf("session_id", "address")
            ),
            createToolSchema(
                "r2_disassemble",
                "📜 [汇编分析] 反汇编指定地址的代码。使用 'pd' 命令显示汇编指令。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID"),
                    "address" to mapOf("type" to "string", "description" to "起始地址（十六进制格式，如：0x401000）"),
                    "lines" to mapOf("type" to "integer", "description" to "反汇编行数（默认10行）", "default" to 10)
                ),
                listOf("session_id", "address")
            ),
            createToolSchema(
                "r2_close_session",
                "🔒 [会话管理] 关闭指定的 Radare2 会话。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID")
                ),
                listOf("session_id")
            ),
            createToolSchema(
                "r2_analyze_target",
                "🎯 [智能分析] 执行特定的 Radare2 递归分析策略。请根据分析需求选择最轻量级的策略，避免盲目使用全量分析。\n" +
                "策略说明：\n" +
                "- 'basic' (aa): 基础分析，识别符号和入口点。\n" +
                "- 'blocks' (aab): 仅分析当前函数或地址的基本块结构（修复函数截断问题）。\n" +
                "- 'calls' (aac): 递归分析函数调用目标（发现未识别的子函数）。\n" +
                "- 'refs' (aar): 分析数据引用（识别字符串引用、全局变量）。\n" +
                "- 'pointers' (aad): 分析数据段指针（用于 C++ 虚表、跳转表恢复）。\n" +
                "- 'full' (aaa): 全量深度分析（耗时极长，仅在小文件或必要时使用）。",
                mapOf(
                    "strategy" to mapOf("type" to "string", "enum" to listOf("basic", "blocks", "calls", "refs", "pointers", "full"), "description" to "分析策略模式"),
                    "address" to mapOf("type" to "string", "description" to "可选：指定分析的起始地址或符号（例如 '0x00401000' 或 'sym.main'）。如果不填，默认分析全局或当前位置。"),
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID")
                ),
                listOf("strategy", "session_id")
            ),
            createToolSchema(
                "r2_manage_xrefs",
                "🔗 [交叉引用管理] 管理代码和数据的交叉引用(Xrefs)。用于查询'谁调用了函数'、'字符串在哪里被使用'，或手动修复缺失的引用关系。\n" +
                "操作类型说明：\n" +
                "- 'list_to' (axt): 查询引用了目标地址的位置（例如：谁调用了这个函数？）。\n" +
                "- 'list_from' (axf): 查询目标地址引用了哪些位置（例如：这个函数里调用了谁？）。\n" +
                "- 'add_code' (axc): 手动添加一个代码引用（修复未识别的跳转）。\n" +
                "- 'add_call' (axC): 手动添加一个函数调用引用。\n" +
                "- 'add_data' (axd): 手动添加一个数据引用（如指针指向）。\n" +
                "- 'add_string' (axs): 手动添加一个字符串引用。\n" +
                "- 'remove_all' (ax-): 删除指定地址的所有引用（修复错误的分析）。",
                mapOf(
                    "action" to mapOf("type" to "string", "enum" to listOf("list_to", "list_from", "add_code", "add_call", "add_data", "add_string", "remove_all"), "description" to "要执行的操作类型"),
                    "target_address" to mapOf("type" to "string", "description" to "目标地址或符号（例如 '0x00401000', 'sym.main', 'entry0'）。对于添加操作，这是引用指向的目标。"),
                    "source_address" to mapOf("type" to "string", "description" to "源地址（可选）。对于添加操作(add_*)，这是发出引用的位置。如果不填，默认为当前光标位置。"),
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID")
                ),
                listOf("action", "target_address", "session_id")
            ),
             createToolSchema(
                "r2_config_manager",
                "⚙️ [配置管理] 管理 Radare2 的分析与显示配置 (eval variables)。\n" +
                "当分析结果不理想、函数截断或需要深度分析时使用。\n" +
                "关键配置参考：\n" +
                "- 流量控制: 'anal.hasnext' (继续分析后续代码), 'anal.jmp.after' (无条件跳转后继续)\n" +
                "- 混淆/大块: 'anal.bb.maxsize' (调整基本块大小限制)\n" +
                "- 引用/字符串: 'anal.strings' (开启字符串引用,默认关闭), 'anal.datarefs' (代码引用数据)\n" +
                "- 边界范围 (anal.in): 'io.maps' (分析所有映射), 'dbg.stack' (分析栈), 'bin.section' (当前段)\n" +
                "- 跳转表: 'anal.jmp.tbl' (开启实验性跳转表分析)",
                mapOf(
                    "action" to mapOf("type" to "string", "enum" to listOf("get", "set", "list"), "description" to "操作类型：get(读取当前值), set(修改值), list(搜索配置项)"),
                    "key" to mapOf("type" to "string", "description" to "配置键名，例如 'anal.strings' 或 'anal.in'"),
                    "value" to mapOf("type" to "string", "description" to "要设置的新值 (仅 set 模式需要)。例如 'true', 'false', 'io.maps'"),
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID")
                ),
                listOf("action", "key", "session_id")
            ),
            createToolSchema(
                "r2_analysis_hints",
                "🔧 [分析提示] 管理分析提示 (Analysis Hints)。用于手动修正 R2 的分析错误，或优化反汇编显示。\n" +
                "当反汇编结果看起来不对（如代码被当成数据）、立即数格式难以理解（如需要看 IP 地址/十进制）、或控制流中断时使用。\n" +
                "操作说明：\n" +
                "- 'list' (ah): 列出当前地址的提示。\n" +
                "- 'set_base' (ahi): 修改立即数显示进制 (value='10'十进制, '16'十六进制, 's'字符串, 'i'IP地址)。\n" +
                "- 'set_arch' (aha): 强制指定后续代码的架构 (value='arm', 'x86')。\n" +
                "- 'set_bits' (ahb): 强制指定位数 (value='16', '32', '64')。\n" +
                "- 'override_jump' (ahc): 强制指定 Call/Jmp 的跳转目标地址 (修复间接跳转)。\n" +
                "- 'override_opcode' (ahd): 直接用自定义字符串替换当前指令显示的文本。\n" +
                "- 'remove' (ah-): 清除当前地址的所有提示。",
                mapOf(
                    "action" to mapOf("type" to "string", "enum" to listOf("list", "set_base", "set_arch", "set_bits", "override_jump", "override_opcode", "remove"), "description" to "提示操作类型"),
                    "address" to mapOf("type" to "string", "description" to "可选：目标地址（默认为当前光标位置）。"),
                    "value" to mapOf("type" to "string", "description" to "参数值。例如进制类型('10', 's')、架构名、跳转目标地址或替换的指令字符串。"),
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID")
                ),
                listOf("action", "session_id")
            ),
            createToolSchema(
            "os_list_dir",
            "📁 [文件目录] 列出目录内容。能力：自动识别并使用 Root 权限。\n" +
            "技巧：如果不确定 Native 库位置，请先列出 '/data/app/' 目录，找到对应的包名目录（通常包含随机字符），进入后再找 'lib' 目录。",
             mapOf(
             "path" to mapOf("type" to "string", "description" to "目录路径")
             ),
              listOf("path")
          ),
            createToolSchema(
            "os_read_file",
            "📄 [文本读取] 读取文件的文本内容 (基于 cat)。\n" +
            "⛔ 警告：严禁读取二进制文件 (如 .so, .db, .apk, .dex, .png)，会导致输出乱码甚至服务崩溃！二进制文件请务必使用 r2_open_file 进行分析。\n" +
            "特性：自动 Root 提权，自动截断超大文件 (>50KB)，适合读取 xml/json/yaml/conf 等配置文件。",
                mapOf(
              "path" to mapOf("type" to "string", "description" to "目标文件的绝对路径")
               ),
              listOf("path")
             ),
            createToolSchema(
                "termux_command", 
                "💻 [Shell] 在 Termux 环境中执行系统命令 (Python, Node, Curl, SQLCipher 等)。\n" +
                "环境：已自动注入 PATH 和 LD_LIBRARY_PATH，可直接运行 'python script.py'。\n" +
                "权限：\n" +
                "- use_root=false (默认): 以 Termux 普通用户运行，更安全。\n" +
                "- use_root=true: 仅在需要读取系统数据库时开启。",
                mapOf(
                    "command" to mapOf("type" to "string", "description" to "Shell 命令"),
                    "use_root" to mapOf("type" to "boolean", "description" to "是否提权", "default" to false),
                    "max_lines" to mapOf("type" to "integer", "description" to "最大输出行数（默认 1000）", "default" to 1000),
                    "max_chars" to mapOf("type" to "integer", "description" to "最大输出字符数（默认 16000）", "default" to 16000)
                ), 
                listOf("command")
            ),
            createToolSchema(
                "termux_save_script", 
                "💾 [编程] 将代码保存到 AI 专属沙盒目录 ($TERMUX_AI_DIR)。\n" +
                "特性：自动创建目录、自动赋予执行权限 (+x)、自动修正文件所有者。\n" +
                "用法：保存后，立即使用 termux_command('python filename.py') 运行。",
                mapOf(
                    "filename" to mapOf("type" to "string", "description" to "纯文件名 (例如 'scan.py')"),
                    "content" to mapOf("type" to "string", "description" to "代码内容")
                ), 
                listOf("filename", "content")
            ),
            createToolSchema(
                "sqlite_query",
                "🗄️ [数据库] 使用系统内置 sqlite3 工具执行 SQL 查询。支持 Root 权限，可直接读取 /data/data 下的私有数据库。请务必使用 LIMIT 限制返回行数，防止输出过大。",
                mapOf(
                    "db_path" to mapOf("type" to "string", "description" to "数据库文件的绝对路径 (如 /data/data/com.xxx/databases/msg.db)"),
                    "query" to mapOf("type" to "string", "description" to "要执行的 SQL 语句 (如 'SELECT * FROM user LIMIT 10;')"),
                    "max_lines" to mapOf("type" to "integer", "description" to "最大输出行数（默认 1000）", "default" to 1000),
                    "max_chars" to mapOf("type" to "integer", "description" to "最大输出字符数（默认 32000）", "default" to 32000)
                ),
                listOf("db_path", "query")
            ),
             createToolSchema(
                "r2_test",
                "🧪 [诊断工具] 测试 Radare2 库是否正常工作。",
                mapOf(),
                listOf()
            ),
            createToolSchema(
                "read_logcat",
                "📝[Logcat]读取Android系统日志。用于分析崩溃堆栈、调试 Patch 结果或监控应用行为。",
                mapOf(
                    "lines" to mapOf("type" to "integer", "description" to "读取日志的行数 (建议 100-500，默认 200)"),
                    "filter" to mapOf("type" to "string", "description" to "关键词过滤 (可选，例如 'com.example.app' 或 '致命信号')"),
                    "use_root" to mapOf("type" to "boolean", "description" to "是否使用 Root 权限读取 (读取其他 App 崩溃必须为 true)")
                ),
                listOf()
            ),
            createToolSchema(
                "rename_function",
                "🏷️[智能重命名函数]当你分析出某个函数的具体用途或函数功能时（例如：加密、登录验证、初始化），请务必调用此工具将其重命名，操作会自动持久化保存到本地知识库。以便在后续分析或重启会话后保留上下文。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID"),
                    "address" to mapOf("type" to "string", "description" to "目标函数地址 (例如 '0x00401000' 或 'sym.main')。留空则默认为当前 seek 的位置。"),
                    "name" to mapOf("type" to "string", "description" to "新的函数名 (只能包含字母、数字、下划线，例如 'AES_Encrypt')")
                ),
                listOf("session_id", "name")
            ),
            createToolSchema(
                "simulate_execution",
                "🧪[模拟执行]在 ESIL 沙箱中模拟执行代码。用于在不运行 App 的情况下计算函数返回值、解密字符串或分析寄存器变化。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID"),
                    "address" to mapOf("type" to "string", "description" to "开始模拟的地址 (例如 '0x1234')。留空默认当前位置。"),
                    "steps" to mapOf("type" to "integer", "description" to "执行的指令步数 (建议 10-100)，防止死循环。"),
                    "init_regs" to mapOf("type" to "string", "description" to "可选：初始化寄存器状态 (例如 'x0=0x1, x1=0x2000')")
                ),
                listOf("session_id", "steps")
            ),
            createToolSchema(
                "add_knowledge_note",
                "📝[添加笔记]向持久化知识库添加笔记。用于记录关键发现（如密钥、算法原理、重要结构体成员）。这些笔记会在下次打开文件时自动加载并展示给你，防止信息丢失。",
                mapOf(
                    "address" to mapOf("type" to "string", "description" to "相关地址 (例如 '0x1234')"),
                    "note" to mapOf("type" to "string", "description" to "笔记内容 (例如 'AES Key 生成函数，返回值是 Key')")
                ),
                listOf("address", "note")
            ),
            createToolSchema(
                "batch_decrypt_strings",
                "🔐 [批量解密] 批量解密字符串，批量模拟执行并提取结果。专为对抗混淆 (OLLVM) 和自定义算法设计。\n" +
                "核心能力：\n" +
                "1. 自动定位函数引用点，批量回溯模拟。\n" +
                "2. 支持所有架构：通过 `instr_size` 和 `result_reg` 适配 ARM64/ARM32/x86。\n" +
                "3. 解决栈传参：通过 `custom_init` 注入指令 (如 'wv 0x10 @ 0x178004') 手动修补堆栈。\n" +
                "4. 解决内存布局：通过 `map_size` 扩大内存映射范围。\n" +
                "注意：仅适用于纯算法函数，无法模拟 malloc/JNI 等外部系统调用。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID"),
                    "func_address" to mapOf("type" to "string", "description" to "目标解密函数的地址 (例如 '0x401000')"),
                    
                    // 👇 关键的新增参数
                    "result_reg" to mapOf("type" to "string", "description" to "存放结果字符串指针的寄存器。ARM64通常是'x0', ARM32是'r0', x86是'eax'。默认为 'x0'。", "default" to "x0"),
                    
                    "instr_size" to mapOf("type" to "integer", "description" to "指令平均字节数。用于计算回溯地址。ARM64=4, ARM32=4(或2), x86=变长(可填平均值3)。默认为 4。", "default" to 4),
                    
                    "pre_steps" to mapOf("type" to "integer", "description" to "向前回溯的指令条数，用于让 CPU 执行参数准备逻辑。默认为 30。", "default" to 30),
                    
                    "map_size" to mapOf("type" to "string", "description" to "模拟器内存映射大小。如果算法引用了远处的数据段，请调大此值。默认为 '0x40000' (256KB)。", "default" to "0x40000"),
                    
                    "custom_init" to mapOf("type" to "string", "description" to "【高级插槽】在模拟启动前执行的 R2 命令序列。用于手动初始化栈参数或全局变量。\n示例 (x86栈传参): 'wv 0x1234 @ esp+4; wv 0x5678 @ esp+8'\n示例 (填充全局变量): 'wx 0xff @ 0x80040'", "default" to "")
                ),
                listOf("session_id", "func_address")
            ),
            createToolSchema(
                "scan_crypto_signatures",
                "🔍 [侦察] 扫描二进制文件中的密码学常量（Magic Numbers）。\n" +
                "用于快速定位加密算法的位置。例如：自动发现 AES S-Box, RSA Keys, MD5/SHA 常量等。\n" +
                "建议在分析未知的加密函数前先运行此工具。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID")
                ),
                listOf("session_id")
            ),
            createToolSchema(
                "apply_hex_patch",
                "🔨 [修改指令] 对指定地址应用二进制 Patch (修改指令)。\n" +
                "用于绕过校验、修改返回值等。例如：将 '1a000034' (CBZ) 修改为 '1f2003d5' (NOP)。\n" +
                "⚠️ 警告：此操作会直接修改内存/文件。如果不确定，请先使用模拟执行测试。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID"),
                    "address" to mapOf("type" to "string", "description" to "Patch 的起始地址 (例如 '0x00401a00')"),
                    "hex_bytes" to mapOf("type" to "string", "description" to "要写入的十六进制机器码 (例如 '1f2003d5')。不需要空格。")
                ),
                listOf("session_id", "address", "hex_bytes")
            ),
            createToolSchema(
                "find_jni_methods",
                "🔗 [JNI] 列出所有的 JNI 接口函数。\n" +
                "这是 Android 逆向的入口点。它会搜索静态导出的 'Java_' 符号以及 'JNI_OnLoad' 函数。\n" +
                "找到这些函数后，你通常应该从这里开始分析。",
                mapOf(
                    "session_id" to mapOf("type" to "string", "description" to "会话 ID")
                ),
                listOf("session_id")
            )
        )
        
        return buildJsonObject {
            put("tools", JsonArray(tools.map { tool ->
                buildJsonObject {
                    put("name", tool.name)
                    put("description", tool.description)
                    put("inputSchema", tool.inputSchema)
                }
            }))
        }
    }

    private fun createToolSchema(
        name: String,
        description: String,
        properties: Map<String, Map<String, Any>>,
        required: List<String>
    ): ToolInfo {
        val schema = buildJsonObject {
            put("type", "object")
            put("properties", buildJsonObject {
                properties.forEach { (key, value) ->
                    put(key, buildJsonObject {
                        value.forEach { (k, v) ->
                            when (v) {
                                is String -> put(k, v)
                                is Int -> put(k, v)
                                is Boolean -> put(k, v)
                                is List<*> -> put(k, JsonArray(v.map { JsonPrimitive(it.toString()) }))
                                else -> put(k, v.toString())
                            }
                        }
                    })
                }
            })
            put("required", JsonArray(required.map { JsonPrimitive(it) }))
        }
        
        return ToolInfo(name, description, schema)
    }

    private suspend fun handleToolCall(params: JsonObject?, onLogEvent: (String) -> Unit): JsonElement {
        if (params == null) {
            return createToolResult(false, error = "Missing params")
        }

        val toolName = params["name"]?.jsonPrimitive?.content 
            ?: return createToolResult(false, error = "Missing tool name")
        
        val rawArgs = params["arguments"]
        val args: JsonObject = try {
    when (rawArgs) {
        is JsonObject -> rawArgs
        is JsonPrimitive -> {
            if (rawArgs.isString) {
                // AI 有时会把 JSON 对象发成字符串，这里尝试二次解析
                json.decodeFromString<JsonObject>(rawArgs.content)
            } else {
                JsonObject(emptyMap()) // 空参数
            }
        }
        else -> JsonObject(emptyMap())
    }
} catch (e: Exception) {
    // 如果解析失败，记录日志并返回空对象，避免 Crash
    logError("参数解析失败", e.message)
    JsonObject(emptyMap())
}

        logInfo("执行工具: $toolName")
        onLogEvent("执行: $toolName")

        return try {
            val result = when (toolName) {
                // --- [新增] 分发逻辑 ---
                "termux_command" -> runBlocking { executeTermuxCommand(args) }
                "termux_save_script" -> runBlocking { executeSaveScript(args) }
                "r2_open_file" -> executeOpenFile(args, onLogEvent)
                "r2_analyze_file" -> executeAnalyzeFile(args, onLogEvent)
                "r2_run_command" -> executeCommand(args)
                "r2_list_functions" -> executeListFunctions(args)
                "r2_list_strings" -> executeListStrings(args)
                "r2_get_xrefs" -> executeGetXrefs(args)
                "r2_get_info" -> executeGetInfo(args)
                "r2_decompile_function" -> executeDecompileFunction(args)
                "r2_disassemble" -> executeDisassemble(args)
                "r2_test" -> executeTestR2(args)
                "r2_close_session" -> executeCloseSession(args)
                "r2_analyze_target" -> executeAnalyzeTarget(args)
                "r2_manage_xrefs" -> executeManageXrefs(args)
                "r2_config_manager" -> executeConfigManager(args)
                "r2_analysis_hints" -> executeAnalysisHints(args)
                "sqlite_query" -> executeSqliteQuery(args)
                "os_list_dir" -> executeOsListDir(args)
                "os_read_file" -> executeOsReadFile(args)
                "read_logcat" -> {
                    try {
                        val lines = args["lines"]?.jsonPrimitive?.int ?: 200
                        val filter = args["filter"]?.jsonPrimitive?.content ?: ""
                        val useRoot = args["use_root"]?.jsonPrimitive?.boolean ?: false

                        // 1. 定义噪音关键词列表 (黑名单)
                        // 这些 tag 或关键词通常是无用的系统噪音或自身协议日志
                        val noiseKeywords = listOf(
                            "R2AI",             // 自身的 Tag
                            "R2Service",        // 后台服务 Tag
                            "System.out",       // 自身的 stdout
                            "MainActivity",     // 自身的 UI 逻辑
                            "jsonrpc",          // MCP 协议内容
                            "ViewRootImpl",     // Android UI 渲染噪音
                            "Oplus",            // 厂商(OPPO/OnePlus) 系统噪音
                            "InputMethod",      // 输入法噪音
                            "ImeTracker",       // 输入法追踪
                            "ResourcesManager"  // 资源加载噪音
                        )

                        // 2. 构建命令
                        val command = if (useRoot) {
                            if (filter.isNotEmpty()) {
                                "su -c logcat -d -v threadtime -t $lines | grep \"$filter\""
                            } else {
                                "su -c logcat -d -v threadtime -t $lines"
                            }
                        } else {
                            "logcat -d -v threadtime -t $lines"
                        }

                        logInfo("执行 Logcat: $command")

                        // 3. 执行命令
                        val process = Runtime.getRuntime().exec(arrayOf("sh", "-c", command))
                        val output = process.inputStream.bufferedReader().use { it.readText() }
                        process.waitFor()

                        // 4. 执行智能过滤
                        val filteredOutput = output.lineSequence()
                            .filter { line ->
                                // 规则 A: 如果用户指定了 filter，则只保留匹配行
                                if (!useRoot && filter.isNotEmpty() && !line.contains(filter, ignoreCase = true)) {
                                    return@filter false
                                }
                                
                                // 规则 B: 始终保留"崩溃"和"严重错误"信息
                                if (line.contains("FATAL") || 
                                    line.contains(" crash ") || 
                                    line.contains("F DEBUG") || // Native Crash 堆栈
                                    line.contains("E AndroidRuntime")) {
                                    return@filter true
                                }

                                // 规则 C: 过滤掉黑名单中的噪音
                                val isNoise = noiseKeywords.any { noise -> line.contains(noise) }
                                !isNoise
                            }
                            .joinToString("\n")

                        // 5. 结果截断与返回
                        val finalResult = if (filteredOutput.isBlank()) {
                            "日志为空 (已过滤噪音)。"
                        } else if (filteredOutput.length > 50000) {
                            "...(前略)...\n" + filteredOutput.takeLast(50000)
                        } else {
                            filteredOutput
                        }

                        createToolResult(true, output = finalResult)

                    } catch (e: Exception) {
                        logError("Logcat 失败", e.message)
                        createToolResult(false, error = "Logcat 执行失败: ${e.message}")
                    }
                }
                "rename_function" -> {
                    val rawName = args["name"]?.jsonPrimitive?.content ?: "func_renamed"
                    val address = args["address"]?.jsonPrimitive?.content ?: ""
                    val sessionId = args["session_id"]?.jsonPrimitive?.content

                    // 1. 名称清洗 (Sanitization)
                    val safeName = rawName.trim()
                        .replace(" ", "_")
                        .replace(Regex("[^a-zA-Z0-9_.]"), "")

                    if (safeName.isEmpty()) {
                        createToolResult(false, error = "Invalid function name provided.")
                    } else if (sessionId == null) {
                        createToolResult(false, error = "Session ID is required.")
                    } else {
                        val session = R2SessionManager.getSession(sessionId)
                        if (session == null) {
                            createToolResult(false, error = "No active Radare2 session found. Please open a file first.")
                        } else {
                            // 2. 获取当前 Seek 地址 (如果 address 为空)
                            val targetAddr = if (address.isNotBlank()) address else {
                                // 如果没传地址，先查一下当前在哪，为了存入 JSON 需要确切地址
                                val offset = R2Core.executeCommand(session.corePtr, "?v $$").trim() // $$ = current seek
                                offset
                            }

                            // 3. 执行 R2 命令
                            val command = "afn $safeName $targetAddr"
                            logInfo("执行重命名: $command")
                            val r2Result = R2Core.executeCommand(session.corePtr, command)

                            // --- 🧠 [新增] 记忆保存逻辑 ---
                            if (currentFilePath.isNotBlank()) {
                                saveKnowledge(currentFilePath, "renames", targetAddr, safeName)
                            }

                            // 4. 验证结果
                            createToolResult(true, output = "成功将函数重命名为: $safeName\n已存入持久化知识库。\nR2 Output: $r2Result")
                        }
                    }
                }
                "add_knowledge_note" -> {
                    val address = args["address"]?.jsonPrimitive?.content ?: ""
                    val note = args["note"]?.jsonPrimitive?.content ?: ""

                    if (currentFilePath.isNotBlank() && address.isNotBlank() && note.isNotBlank()) {
                        // 1. 保存到 JSON
                        saveKnowledge(currentFilePath, "notes", address, note)
                        
                        // 2. 可选：同时也作为注释写入 R2 (CC 命令)
                        // val r2Cmd = "CC $note @ $address"
                        // R2Core.executeCommand(session.corePtr, r2Cmd)

                        createToolResult(true, output = "笔记已保存到记忆宫殿: [$address] $note")
                    } else {
                        createToolResult(false, error = "需要已打开文件、地址和笔记内容。")
                    }
                }
                "simulate_execution" -> {
                    val address = args["address"]?.jsonPrimitive?.content ?: ""
                    val steps = args["steps"]?.jsonPrimitive?.int ?: 20
                    val initRegs = args["init_regs"]?.jsonPrimitive?.content ?: ""
                    val sessionId = args["session_id"]?.jsonPrimitive?.content

                    if (sessionId == null) {
                        createToolResult(false, error = "Session ID is required.")
                    } else {
                        val session = R2SessionManager.getSession(sessionId)
                        if (session == null) {
                            createToolResult(false, error = "No active Radare2 session found. Please open a file first.")
                        } else {
                            val sb = StringBuilder()

                            // 1. 初始化 ESIL VM
                            R2Core.executeCommand(session.corePtr, "aei; aeim")

                            // 2. 跳转到起始位置
                            if (address.isNotBlank()) {
                                R2Core.executeCommand(session.corePtr, "s $address")
                            }

                            // 3. 设置寄存器 (如果有)
                            if (initRegs.isNotBlank()) {
                                val regs = initRegs.split(",")
                                for (reg in regs) {
                                    val cleanReg = reg.trim()
                                    if (cleanReg.isNotEmpty()) {
                                        R2Core.executeCommand(session.corePtr, "aer $cleanReg")
                                        sb.append("Set $cleanReg\n")
                                    }
                                }
                            }

                            // 4. 开始模拟 (Step N times)
                            sb.append("Executing $steps steps...\n")
                            R2Core.executeCommand(session.corePtr, "aes $steps")

                            // 5. 获取结果
                            val regsOutput = R2Core.executeCommand(session.corePtr, "aer")
                            
                            // 🛠️【终极修复】
                            // sr pc = "Seek to Register PC"
                            // 这会强制把编辑器光标移动到 ESIL 虚拟机当前的 PC 地址
                            R2Core.executeCommand(session.corePtr, "sr pc")
                            
                            // 然后再反汇编，不需要 @ 了，因为光标已经过去了
                            val currentOp = R2Core.executeCommand(session.corePtr, "pd 1")

                            sb.append("\n--- Final Registers ---\n")
                            sb.append(regsOutput)
                            sb.append("\n--- Stopped At (PC) ---\n")
                            sb.append(currentOp)

                            createToolResult(true, output = sb.toString())
                        }
                    }
                }
                "batch_decrypt_strings" -> {
                    // --- 1. 参数提取与校验 ---
                    val sessionId = args["session_id"]?.jsonPrimitive?.content
                        ?: return createToolResult(false, error = "Missing session_id")
                    val funcAddr = args["func_address"]?.jsonPrimitive?.content
                        ?: return createToolResult(false, error = "Missing func_address")
                    
                    // 默认值配置
                    val resultReg = args["result_reg"]?.jsonPrimitive?.content ?: "x0"
                    val instrSize = args["instr_size"]?.jsonPrimitive?.int ?: 4
                    val maxSteps = 2000
                    val preSteps = args["pre_steps"]?.jsonPrimitive?.int ?: 30
                    val mapSize = args["map_size"]?.jsonPrimitive?.content ?: "0x40000"
                    val customInit = args["custom_init"]?.jsonPrimitive?.content ?: ""

                    val session = R2SessionManager.getSession(sessionId)
                        ?: return createToolResult(false, error = "Invalid session_id")

                    val sb = StringBuilder("🚀 启动全架构通用模拟: $funcAddr\n")

                    // --- 2. 查找交叉引用 (Xrefs) ---
                    val xrefsJson = R2Core.executeCommand(session.corePtr, "axtj $funcAddr")
                    val callSites = mutableListOf<Long>()
                    try {
                        val jsonArr = org.json.JSONArray(xrefsJson)
                        for (i in 0 until jsonArr.length()) {
                            val item = jsonArr.getJSONObject(i)
                            if (item.optString("type").lowercase().contains("call")) {
                                callSites.add(item.getLong("from"))
                            }
                        }
                    } catch (e: Exception) { }

                    if (callSites.isEmpty()) return createToolResult(true, output = "⚠️ 未发现调用点。请检查地址是否正确。")

                    sb.append("🔍 发现 ${callSites.size} 处调用，准备模拟...\n")
                    var successCount = 0

                    // --- 3. 批量模拟循环 ---
                    for (callSite in callSites) {
                        val callSiteHex = "0x%x".format(callSite)
                        // 计算回溯起点
                        val startPC = callSite - (preSteps * instrSize)

                        // A. 重置映射 & 动态分配内存
                        R2Core.executeCommand(session.corePtr, "om -") // 清空
                        R2Core.executeCommand(session.corePtr, "omf 0 $mapSize") // 动态大小映射
                        
                        // B. 计算安全的栈顶地址 (Stack Pointer)
                        // 逻辑：栈顶 = 映射大小 - 0x100 (保留一点 buffer 防止溢出)
                        val mapSizeBytes = try {
                            if (mapSize.startsWith("0x")) mapSize.substring(2).toLong(16)
                            else mapSize.toLong()
                        } catch (e: Exception) { 0x40000L }
                        
                        val safeStackAddr = mapSizeBytes - 0x100
                        val safeStackHex = "0x%x".format(safeStackAddr)

                        // C. 初始化 ESIL 虚拟机
                        R2Core.executeCommand(session.corePtr, "e esil.romem=true")
                        R2Core.executeCommand(session.corePtr, "aei; aeim")
                        
                        // D. 初始化通用寄存器 (覆盖 ARM64, ARM32, x86, x64)
                        // 将 SP/BP 都指向我们计算出的安全内存高位，防止 push/pop 崩溃
                        val initStackCmd = "aer x29=$safeStackHex; aer sp=$safeStackHex; " +
                                           "aer rbp=$safeStackHex; aer esp=$safeStackHex; " +
                                           "aer r7=$safeStackHex" // ARM32 Thumb Frame Pointer
                        R2Core.executeCommand(session.corePtr, initStackCmd)

                        // E. 【高阶】执行 AI 自定义的特殊初始化 (例如写栈参数)
                        if (customInit.isNotBlank()) {
                            R2Core.executeCommand(session.corePtr, customInit)
                        }

                        // F. 执行参数准备阶段 (Pre-run)
                        R2Core.executeCommand(session.corePtr, "aer pc=$startPC")
                        R2Core.executeCommand(session.corePtr, "aecu $callSite")
                        
                        // G. 跳过 Call 指令本身，模拟函数内部
                        // 设置 LR/Ret 地址为 0xffffff (陷阱)，模拟函数执行完返回
                        R2Core.executeCommand(session.corePtr, "aer lr=0xffffff; aer rax=0xffffff")
                        R2Core.executeCommand(session.corePtr, "aer pc=$funcAddr")
                        
                        // H. 正式模拟 (Run)
                        R2Core.executeCommand(session.corePtr, "aes $maxSteps")

                        // I. 提取结果 (通用寄存器)
                        val retValStr = R2Core.executeCommand(session.corePtr, "aer $resultReg").trim()
                        val resultString = R2Core.executeCommand(session.corePtr, "ps @ $retValStr").trim()

                        // J. 结果验证与保存
                        if (resultString.isNotBlank() && resultString.length > 1 && resultString.all { it.code in 32..126 }) {
                            sb.append("✅ $callSiteHex -> \"$resultString\"\n")
                            if (currentFilePath.isNotBlank()) {
                                saveKnowledge(currentFilePath, "notes", callSiteHex, "Decrypted: \"$resultString\"")
                                R2Core.executeCommand(session.corePtr, "CC Decrypted: \"$resultString\" @ $callSite")
                            }
                            successCount++
                        }
                    }
                    
                    sb.append("\n📊 统计: 成功 $successCount / ${callSites.size}\n")
                    createToolResult(true, output = sb.toString())
                }
                "scan_crypto_signatures" -> {
                    val sessionId = args["session_id"]?.jsonPrimitive?.content
                        ?: return createToolResult(false, error = "Missing session_id")
                    val session = R2SessionManager.getSession(sessionId)
                        ?: return createToolResult(false, error = "Invalid session_id")

                    logInfo("正在扫描密码学特征...")
                    
                    // /ca = Search for crypto constants (AES, RSA, SHA...) in all sections
                    // search.in=io.maps 确保扫描所有映射的内存
                    R2Core.executeCommand(session.corePtr, "e search.in=io.maps")
                    val rawOutput = R2Core.executeCommand(session.corePtr, "/ca")
                    
                    if (rawOutput.isBlank()) {
                        createToolResult(true, output = "未发现明显的密码学常量特征。")
                    } else {
                        // 简单的格式化，去掉太长的杂音
                        val formatted = rawOutput.lineSequence()
                            .take(50) // 只取前50个，防止太多
                            .joinToString("\n")
                        createToolResult(true, output = "🔍 发现以下密码学特征:\n$formatted\n\n💡 提示：请根据地址跳转分析引用 (axt)。")
                    }
                }
                "apply_hex_patch" -> {
                    val sessionId = args["session_id"]?.jsonPrimitive?.content ?: return createToolResult(false, error = "Missing session_id")
                    val address = args["address"]?.jsonPrimitive?.content ?: return createToolResult(false, error = "Missing address")
                    val hexBytes = args["hex_bytes"]?.jsonPrimitive?.content ?: return createToolResult(false, error = "Missing bytes")

                    val session = R2SessionManager.getSession(sessionId) ?: return createToolResult(false, error = "Invalid session_id")

                    // 1. 尝试开启写模式 (oo+)
                    R2Core.executeCommand(session.corePtr, "oo+")
                    
                    // 2. 备份原有字节 (为了显示给用户看)
                    val len = hexBytes.length / 2
                    val originalBytes = R2Core.executeCommand(session.corePtr, "p8 $len @ $address").trim()
                    
                    // 3. 写入新字节
                    // wx = Write heX
                    R2Core.executeCommand(session.corePtr, "wx $hexBytes @ $address")
                    
                    // 4. 验证是否写入成功
                    val newBytes = R2Core.executeCommand(session.corePtr, "p8 $len @ $address").trim()
                    
                    // 5. 刷新反汇编预览
                    val preview = R2Core.executeCommand(session.corePtr, "pd 1 @ $address")

                    if (newBytes.equals(hexBytes, ignoreCase = true)) {
                        createToolResult(true, output = "✅ Patch 成功！\n📍 地址: $address\n🔴 原字节: $originalBytes\n🟢 新字节: $newBytes\n\n🔍 当前指令预览:\n$preview")
                    } else {
                        createToolResult(false, error = "❌ Patch 失败。可能没有写权限，或者文件只读。\n当前字节仍为: $newBytes")
                    }
                }
                "find_jni_methods" -> {
                    val sessionId = args["session_id"]?.jsonPrimitive?.content ?: return createToolResult(false, error = "Missing session_id")
                    val session = R2SessionManager.getSession(sessionId) ?: return createToolResult(false, error = "Invalid session_id")

                    // is~Java_ : 列出符号(symbols)中包含 "Java_" 的 
                    // is~JNI_OnLoad : 列出 JNI_OnLoad 
                    val javaFuncs = R2Core.executeCommand(session.corePtr, "is~Java_").trim()
                    val onLoad = R2Core.executeCommand(session.corePtr, "is~JNI_OnLoad").trim()
                    
                    val sb = StringBuilder() 
                    if (onLoad.isNotBlank()) {
                        sb.append("⚡ 发现动态注册入口 (JNI_OnLoad):\n$onLoad\n\n")
                    } else {
                        sb.append("ℹ️ 未发现 JNI_OnLoad (可能是静态注册或被混淆)\n\n")
                    }
                    
                    if (javaFuncs.isNotBlank()) {
                        sb.append("☕ 发现静态 JNI 函数:\n$javaFuncs")
                    } else {
                        sb.append("⚠️ 未发现静态导出的 'Java_' 函数。请检查是否被 Strip 或使用了动态注册。")
                    }
                    
                    createToolResult(true, output = sb.toString())
                }
                else -> createToolResult(false, error = "Unknown tool: $toolName")
            }
            fixContentFormat(result)
        } catch (e: Exception) {
            logError("工具执行异常: $toolName", e.message)
            createToolResult(false, error = e.message ?: "Unknown error")
        }
    }

    private fun createToolResult(
        success: Boolean,
        output: String? = null,
        error: String? = null
    ): JsonElement {
        return buildJsonObject {
            put("content", JsonArray(listOf(
                buildJsonObject {
                    put("type", "text")
                    put("text", output ?: error ?: "")
                }
            )))
            put("isError", !success)
        }
    }

    private fun fixContentFormat(result: JsonElement): JsonElement {
        if (result !is JsonObject) return result
        
        val content = result["content"]?.jsonArray ?: return result
        
        val fixedContent = content.map { item ->
            when {
                item is JsonPrimitive && item.isString -> {
                    val text = item.content
                    if (text.length > 30) {
                        logInfo("[自动修复格式] ${text.take(30)}...")
                    }
                    buildJsonObject {
                        put("type", "text")
                        put("text", text)
                    }
                }
                else -> item
            }
        }
        
        return buildJsonObject {
            result.forEach { (key, value) ->
                if (key == "content") {
                    put("content", JsonArray(fixedContent))
                } else {
                    put(key, value)
                }
            }
        }
    }

    private suspend fun executeOpenFile(args: JsonObject, onLogEvent: (String) -> Unit): JsonElement {
        val filePath = args["file_path"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing file_path")
        
        val autoAnalyze = args["auto_analyze"]?.jsonPrimitive?.booleanOrNull ?: true
        
        val file = java.io.File(filePath)
        if (!file.exists()) {
            logInfo("文件不存在或无权限访问，尝试 Root 复制: $filePath")
            val copyPath = tryRootCopy(filePath)
            if (copyPath != null) {
                logInfo("Root 复制成功，使用副本继续: $copyPath")
                val copyFile = java.io.File(copyPath)
                if (!copyFile.exists()) {
                    logError("Root 复制后副本文件不存在", copyPath)
                    return createToolResult(false, error = "Failed to create accessible copy of file: $filePath")
                }
                return executeOpenFileWithFile(copyFile, copyPath, autoAnalyze, onLogEvent)
            } else {
                logError("文件不存在且 Root 复制失败", filePath)
                return createToolResult(false, error = "File does not exist or no permission to access: $filePath")
            }
        }
        
        var sessionId = args["session_id"]?.jsonPrimitive?.content
        var session = if (sessionId != null) R2SessionManager.getSession(sessionId) else null
        
        if (session == null) {
            // 创建新会话
            val corePtr = R2Core.initR2Core()
            if (corePtr == 0L) {
                logError("R2 Core 初始化失败")
                return createToolResult(false, error = "Failed to initialize R2 core")
            }
            
            val opened = R2Core.openFile(corePtr, filePath)
            if (!opened) {
                logInfo("文件打开失败，尝试 Root 复制: $filePath")
                val copyPath = tryRootCopy(filePath)
                if (copyPath != null) {
                    logInfo("使用 Root 复制的副本重试: $copyPath")
                    val copyOpened = R2Core.openFile(corePtr, copyPath)
                    if (copyOpened) {
                        logInfo("Root 复制副本打开成功")
                        sessionId = R2SessionManager.createSession(copyPath, corePtr)
                        session = R2SessionManager.getSession(sessionId)!!
                        logInfo("创建新会话 (使用副本): $sessionId")
                    } else {
                        R2Core.closeR2Core(corePtr)
                        logError("Root 复制副本也无法打开", copyPath)
                        return createToolResult(false, error = "Failed to open file (root copy failed): $copyPath")
                    }
                } else {
                    R2Core.closeR2Core(corePtr)
                    logError("打开文件失败且 Root 复制失败", filePath)
                    return createToolResult(false, error = "Failed to open file: $filePath")
                }
            } else {
                sessionId = R2SessionManager.createSession(filePath, corePtr)
                session = R2SessionManager.getSession(sessionId)!!
                logInfo("创建新会话: $sessionId")
            }
        } else {
            // [补全功能 1]：如果传入了有效的 session_id，则在现有会话中打开文件
            logInfo("复用现有会话: $sessionId，尝试打开文件: $filePath")
            val opened = R2Core.openFile(session.corePtr, filePath)
            if (!opened) {
                logInfo("文件打开失败，尝试 Root 复制并复用会话...")
                val copyPath = tryRootCopy(filePath)
                if (copyPath != null) {
                    val copyOpened = R2Core.openFile(session.corePtr, copyPath)
                    if (copyOpened) {
                        logInfo("复用会话打开 Root 副本成功: $copyPath")
                    } else {
                         return createToolResult(false, error = "Failed to open file in existing session: $filePath")
                    }
                } else {
                     return createToolResult(false, error = "Failed to open file in existing session: $filePath")
                }
            }
        }

        // --- 🧠 [新增] 记忆加载逻辑 ---
        val memory = loadKnowledge(filePath)
        
        // 执行恢复命令 (重命名)
        for (cmd in memory.r2Commands) {
            R2Core.executeCommand(session!!.corePtr, cmd)
        }
        
        val analysisResult = if (autoAnalyze) {
            logInfo("执行基础分析 (a)...")
            val startTime = System.currentTimeMillis()
            val output = R2Core.executeCommand(session!!.corePtr, "a")
            val duration = System.currentTimeMillis() - startTime
            logInfo("分析完成，耗时 ${duration}ms")
            "\n[基础分析已完成，耗时 ${duration}ms]\n$output"
        } else {
            "\n[跳过自动分析]"
        }

        val info = R2Core.executeCommand(session!!.corePtr, "i")
        
        // 记录当前文件路径，供保存时使用
        currentFilePath = filePath
        
        return createToolResult(true, output = "Session: $sessionId\n\nFile: ${file.absolutePath}$analysisResult\n\n${memory.summary}\n=== 文件信息 ===\n$info")
    }

    private suspend fun executeOpenFileWithFile(file: java.io.File, filePath: String, autoAnalyze: Boolean, onLogEvent: (String) -> Unit): JsonElement {
        var sessionId: String
        var session = R2SessionManager.getSessionByFilePath(filePath)
        
        if (session == null) {
            val corePtr = R2Core.initR2Core()
            if (corePtr == 0L) {
                logError("R2 Core 初始化失败")
                return createToolResult(false, error = "Failed to initialize R2 core")
            }
            
            val opened = R2Core.openFile(corePtr, filePath)
            if (!opened) {
                R2Core.closeR2Core(corePtr)
                logError("打开文件失败", filePath)
                return createToolResult(false, error = "Failed to open file: $filePath")
            }
            
            sessionId = R2SessionManager.createSession(filePath, corePtr)
            session = R2SessionManager.getSession(sessionId)!!
            logInfo("创建新会话: $sessionId")
        } else {
            sessionId = session.sessionId
            logInfo("使用现有会话: $sessionId")
        }

        // --- 🧠 [新增] 记忆加载逻辑 ---
        val memory = loadKnowledge(filePath)
        
        // 执行恢复命令 (重命名)
        for (cmd in memory.r2Commands) {
            R2Core.executeCommand(session!!.corePtr, cmd)
        }
        
        val analysisResult = if (autoAnalyze) {
            logInfo("执行基础分析 (a)...")
            val startTime = System.currentTimeMillis()
            val output = R2Core.executeCommand(session!!.corePtr, "a")
            val duration = System.currentTimeMillis() - startTime
            logInfo("分析完成，耗时 ${duration}ms")
            "\n[基础分析已完成，耗时 ${duration}ms]\n$output"
        } else {
            "\n[跳过自动分析]"
        }

        val info = R2Core.executeCommand(session!!.corePtr, "i")
        
        // 记录当前文件路径，供保存时使用
        currentFilePath = filePath
        
        return createToolResult(true, output = "Session: $sessionId\n\nFile: ${file.absolutePath}$analysisResult\n\n${memory.summary}\n=== 文件信息 ===\n$info")
    }

    private suspend fun executeAnalyzeFile(args: JsonObject, onLogEvent: (String) -> Unit): JsonElement {
        val filePath = args["file_path"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing file_path")
            
        // [补全功能 2]: 优先检查是否传入了 session_id
        val explicitSessionId = args["session_id"]?.jsonPrimitive?.content
        if (explicitSessionId != null) {
            val existingSession = R2SessionManager.getSession(explicitSessionId)
            if (existingSession != null) {
                logInfo("使用指定会话进行分析: $explicitSessionId")
                
                logInfo("执行深度分析 (aaa)...")
                val startTime = System.currentTimeMillis()
                R2Core.executeCommand(existingSession.corePtr, "aaa")
                val duration = System.currentTimeMillis() - startTime
                
                val info = R2Core.executeCommand(existingSession.corePtr, "i")
                val funcs = R2Core.executeCommand(existingSession.corePtr, "afl~?")
                
                return createToolResult(true, output = "Session: ${existingSession.sessionId}\n\n[指定会话深度分析]\nFile: $filePath\nFunctions: $funcs\n深度分析耗时: ${duration}ms\n\n$info")
            }
        }
        
        val file = java.io.File(filePath)
        if (!file.exists()) {
            logInfo("文件不存在或无权限访问，尝试 Root 复制: $filePath")
            val copyPath = tryRootCopy(filePath)
            if (copyPath != null) {
                logInfo("Root 复制成功，使用副本继续: $copyPath")
                val copyFile = java.io.File(copyPath)
                if (!copyFile.exists()) {
                    logError("Root 复制后副本文件不存在", copyPath)
                    return createToolResult(false, error = "Failed to create accessible copy of file: $filePath")
                }
                return executeAnalyzeFileWithFile(copyFile, copyPath, onLogEvent)
            } else {
                logError("文件不存在且 Root 复制失败", filePath)
                return createToolResult(false, error = "File does not exist or no permission to access: $filePath")
            }
        }
        
        logInfo("分析文件: ${file.absolutePath} (${file.length()} bytes)")

        val existingSession = R2SessionManager.getSessionByFilePath(file.absolutePath)
        if (existingSession != null) {
            logInfo("文件已被会话 ${existingSession.sessionId} 打开，执行深度分析")
            
            val startTime = System.currentTimeMillis()
            R2Core.executeCommand(existingSession.corePtr, "aaa")
            val duration = System.currentTimeMillis() - startTime
            
            val info = R2Core.executeCommand(existingSession.corePtr, "i")
            val funcs = R2Core.executeCommand(existingSession.corePtr, "afl~?")
            
            return createToolResult(true, output = "Session: ${existingSession.sessionId}\n\n[复用现有会话]\nFile: ${file.absolutePath}\nSize: ${file.length()} bytes\nFunctions: $funcs\n深度分析耗时: ${duration}ms\n\n$info")
        }

        val corePtr = R2Core.initR2Core()
        if (corePtr == 0L) {
            logError("R2 Core 初始化失败")
            return createToolResult(false, error = "Failed to initialize R2 core")
        }

        try {
            val opened = R2Core.openFile(corePtr, file.absolutePath)
            if (!opened) {
                val copyPath = tryRootCopy(file.absolutePath)
                if (copyPath != null) {
                    logInfo("使用 Root 复制的副本重试分析: $copyPath")
                    val copyOpened = R2Core.openFile(corePtr, copyPath)
                    if (copyOpened) {
                        logInfo("Root 复制副本打开成功，开始深度分析")
                        val copyFile = File(copyPath)
                        val sessionId = R2SessionManager.createSession(copyPath, corePtr)

                        logInfo("执行深度分析 (aaa)...")
                        val startTime = System.currentTimeMillis()
                        R2Core.executeCommand(corePtr, "aaa")
                        val duration = System.currentTimeMillis() - startTime
                        logInfo("深度分析完成，耗时 ${duration}ms")

                        val info = R2Core.executeCommand(corePtr, "i")
                        val funcs = R2Core.executeCommand(corePtr, "afl~?")

                        logInfo("分析完成，Session ID: $sessionId, 函数数量: $funcs")
                        return createToolResult(true, output = "Session: $sessionId\n\n[使用 Root 复制副本]\nOriginal: ${file.absolutePath}\nCopy: $copyPath\nSize: ${copyFile.length()} bytes\nFunctions: $funcs\n深度分析耗时: ${duration}ms\n\n$info")
                    } else {
                        logError("Root 复制副本也无法打开", copyPath)
                    }
                }

                logError("打开文件失败且 Root 复制失败", file.absolutePath)
                R2Core.closeR2Core(corePtr)
                return createToolResult(false, error = "Failed to open file: ${file.absolutePath}")
            }

            val sessionId = R2SessionManager.createSession(file.absolutePath, corePtr)

            logInfo("执行深度分析 (aaa)...")
            val startTime = System.currentTimeMillis()
            R2Core.executeCommand(corePtr, "aaa")
            val duration = System.currentTimeMillis() - startTime
            logInfo("深度分析完成，耗时 ${duration}ms")

            val info = R2Core.executeCommand(corePtr, "i")
            val funcs = R2Core.executeCommand(corePtr, "afl~?")

            logInfo("分析完成，Session ID: $sessionId, 函数数量: $funcs")
            return createToolResult(true, output = "Session: $sessionId\n\nFile: ${file.absolutePath}\nSize: ${file.length()} bytes\nFunctions: $funcs\n深度分析耗时: ${duration}ms\n\n$info")
        } catch (e: Exception) {
            logError("分析过程异常", e.message)
            R2Core.closeR2Core(corePtr)
            return createToolResult(false, error = "Exception during analysis: ${e.message}")
        }
    }

    private suspend fun executeAnalyzeFileWithFile(file: java.io.File, filePath: String, onLogEvent: (String) -> Unit): JsonElement {
        logInfo("分析文件: ${file.absolutePath} (${file.length()} bytes)")

        val existingSession = R2SessionManager.getSessionByFilePath(file.absolutePath)
        if (existingSession != null) {
            logInfo("文件已被会话 ${existingSession.sessionId} 打开，执行深度分析")
            
            val startTime = System.currentTimeMillis()
            R2Core.executeCommand(existingSession.corePtr, "aaa")
            val duration = System.currentTimeMillis() - startTime
            
            val info = R2Core.executeCommand(existingSession.corePtr, "i")
            val funcs = R2Core.executeCommand(existingSession.corePtr, "afl~?")
            
            return createToolResult(true, output = "Session: ${existingSession.sessionId}\n\n[复用现有会话]\nFile: ${file.absolutePath}\nSize: ${file.length()} bytes\nFunctions: $funcs\n深度分析耗时: ${duration}ms\n\n$info")
        }

        val corePtr = R2Core.initR2Core()
        if (corePtr == 0L) {
            logError("R2 Core 初始化失败")
            return createToolResult(false, error = "Failed to initialize R2 core")
        }

        try {
            val opened = R2Core.openFile(corePtr, filePath)
            if (!opened) {
                R2Core.closeR2Core(corePtr)
                logError("打开文件失败", filePath)
                return createToolResult(false, error = "Failed to open file: $filePath")
            }

            val sessionId = R2SessionManager.createSession(filePath, corePtr)

            logInfo("执行深度分析 (aaa)...")
            val startTime = System.currentTimeMillis()
            R2Core.executeCommand(corePtr, "aaa")
            val duration = System.currentTimeMillis() - startTime
            logInfo("深度分析完成，耗时 ${duration}ms")

            val info = R2Core.executeCommand(corePtr, "i")
            val funcs = R2Core.executeCommand(corePtr, "afl~?")

            logInfo("分析完成，Session ID: $sessionId, 函数数量: $funcs")
            return createToolResult(true, output = "Session: $sessionId\n\nFile: ${file.absolutePath}\nSize: ${file.length()} bytes\nFunctions: $funcs\n深度分析耗时: ${duration}ms\n\n$info")
        } catch (e: Exception) {
            logError("分析过程异常", e.message)
            R2Core.closeR2Core(corePtr)
            return createToolResult(false, error = "Exception during analysis: ${e.message}")
        }
    }

    private suspend fun executeCommand(args: JsonObject): JsonElement {
        val sessionId = args["session_id"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing session_id")
        val command = args["command"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing command")

        val maxLines = args["max_lines"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxLines()
        val maxChars = args["max_chars"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxChars()

        val session = R2SessionManager.getSession(sessionId)
            ?: return createToolResult(false, error = "Invalid session_id: $sessionId")

        logInfo("执行命令: $command (Session: ${sessionId.take(16)})")

        val rawResult = R2Core.executeCommand(session.corePtr, command)

        val result = sanitizeOutput(rawResult, maxLines = maxLines, maxChars = maxChars)

        if (result.length > 200) {
            logInfo("命令返回: ${result.length} bytes")
        }

        return createToolResult(true, output = result)
    }

    private suspend fun executeListFunctions(args: JsonObject): JsonElement {
        val sessionId = args["session_id"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing session_id")

        val filter = args["filter"]?.jsonPrimitive?.content ?: ""
        // 兼容旧 limit 参数，同时支持新的 max_lines 和 max_chars，优先使用全局配置
        val maxLines = args["max_lines"]?.jsonPrimitive?.intOrNull ?: args["limit"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxLines()
        val maxChars = args["max_chars"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxChars()

        val session = R2SessionManager.getSession(sessionId)
            ?: return createToolResult(false, error = "Invalid session_id: $sessionId")

        val command = if (filter.isBlank()) "afl" else "afl~$filter"

        logInfo("列出函数 (过滤: '$filter', 限制: $maxLines, Session: ${sessionId.take(16)})")

        val rawResult = R2Core.executeCommand(session.corePtr, command)

        val result = sanitizeOutput(rawResult, maxLines = maxLines, maxChars = maxChars)

        return createToolResult(true, output = result)
    }
    
    private suspend fun executeListStrings(args: JsonObject): JsonElement {
        val sessionId = args["session_id"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing session_id")

        val mode = args["mode"]?.jsonPrimitive?.content ?: "data"
        val minLength = args["min_length"]?.jsonPrimitive?.intOrNull ?: 5
        val maxLines = args["max_lines"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxLines()
        val maxChars = args["max_chars"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxChars()

        val session = R2SessionManager.getSession(sessionId)
            ?: return createToolResult(false, error = "Invalid session_id: $sessionId")

        val command = when (mode) {
            "all" -> "izz"
            else -> "iz"
        }

        logInfo("列出字符串 (模式: $mode, 最小长度: $minLength, Session: ${sessionId.take(16)})")

        // [补全功能 3]：使用 R2 原生配置进行过滤，防止内存爆炸
        R2Core.executeCommand(session.corePtr, "e bin.str.min=$minLength")

        val rawOutput = R2Core.executeCommand(session.corePtr, command)

        val cleanOutput = rawOutput.lineSequence()
            .filter { line ->
                !line.contains(".eh_frame") &&
                !line.contains(".gcc_except_table") &&
                !line.contains(".text") &&
                !line.contains("libunwind")
            }
            .filter { line ->
                line.trim().length > 20 ||
                line.split("ascii", "utf8", "utf16", "utf32").lastOrNull()?.trim()?.length ?: 0 >= minLength
            }
            .joinToString("\n")

        val finalOutput = if (cleanOutput.isBlank()) {
            "No meaningful strings found (filters active: min_len=$minLength, exclude=.text/.eh_frame)"
        } else {
            sanitizeOutput(cleanOutput, maxLines = maxLines, maxChars = maxChars)
        }

        return createToolResult(true, output = finalOutput)
    }

    private suspend fun executeDecompileFunction(args: JsonObject): JsonElement {
    val sessionId = args["session_id"]?.jsonPrimitive?.content
        ?: return createToolResult(false, error = "Missing session_id")
    val address = args["address"]?.jsonPrimitive?.content
        ?: return createToolResult(false, error = "Missing address")

    // 从参数或全局配置读取截断阈值
    val maxLines = args["max_lines"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxLines()
    val maxChars = args["max_chars"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxChars()

    val session = R2SessionManager.getSession(sessionId)
        ?: return createToolResult(false, error = "Invalid session_id: $sessionId")

    // 可选：记录函数大小（供调试用），但不再作为拒绝条件
    val info = R2Core.executeCommand(session.corePtr, "afi @ $address")
    val size = info.lines()
        .find { it.trim().startsWith("size:") }
        ?.substringAfter(":")
        ?.trim()
        ?.toLongOrNull() ?: 0
    logInfo("反编译函数: $address (size: $size bytes)")

    // 直接执行反编译，交由 sanitizeOutput 截断
    val rawCode = R2Core.executeCommand(session.corePtr, "pdc @ $address")
    val result = sanitizeOutput(rawCode, maxLines = maxLines, maxChars = maxChars)

    return createToolResult(true, output = result)
}

    private suspend fun executeDisassemble(args: JsonObject): JsonElement {
        val sessionId = args["session_id"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing session_id")
        val address = args["address"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing address")
        val lines = args["lines"]?.jsonPrimitive?.intOrNull ?: 10

        val session = R2SessionManager.getSession(sessionId)
            ?: return createToolResult(false, error = "Invalid session_id: $sessionId")

        logInfo("反汇编: $address ($lines 行)")
        
        val result = R2Core.executeCommand(session.corePtr, "pd $lines @ $address")
        
        return createToolResult(true, output = result)
    }

    private suspend fun executeCloseSession(args: JsonObject): JsonElement {
        val sessionId = args["session_id"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing session_id")

        val session = R2SessionManager.removeSession(sessionId)
            ?: return createToolResult(false, error = "Invalid session_id: $sessionId")

        logInfo("关闭会话: $sessionId (文件: ${session.filePath})")
        
        return createToolResult(true, output = "Session closed: $sessionId")
    }
    
    private suspend fun executeTestR2(args: JsonObject): JsonElement {
        logInfo("执行 R2 测试")
        
        return try {
            val testResult = R2Core.testR2()
            logInfo("R2 测试完成")
            createToolResult(true, output = testResult)
        } catch (e: Exception) {
            logError("R2 测试失败", e.message)
            createToolResult(false, error = "R2 test failed: ${e.message}\n${e.stackTraceToString()}")
        }
    }

    private suspend fun executeGetXrefs(args: JsonObject): JsonElement {
        val sessionId = args["session_id"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing session_id")

        val address = args["address"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing address")

        val direction = args["direction"]?.jsonPrimitive?.content ?: "to"
        // 兼容旧 limit 参数，同时支持新的 max_lines 和 max_chars，优先使用全局配置
        val maxLines = args["max_lines"]?.jsonPrimitive?.intOrNull ?: args["limit"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxLines()
        val maxChars = args["max_chars"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxChars()

        val session = R2SessionManager.getSession(sessionId)
            ?: return createToolResult(false, error = "Invalid session_id: $sessionId")

        val command = when (direction) {
            "from" -> "axf @ $address"
            else -> "axt @ $address"
        }

        logInfo("获取交叉引用 (地址: $address, 方向: $direction, 限制: $maxLines, Session: ${sessionId.take(16)})")

        val rawResult = R2Core.executeCommand(session.corePtr, command)

        val result = sanitizeOutput(rawResult, maxLines = maxLines, maxChars = maxChars)

        return createToolResult(true, output = result)
    }

    private suspend fun executeGetInfo(args: JsonObject): JsonElement {
        val sessionId = args["session_id"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing session_id")
        
        val detailed = args["detailed"]?.jsonPrimitive?.booleanOrNull ?: false

        val session = R2SessionManager.getSession(sessionId)
            ?: return createToolResult(false, error = "Invalid session_id: $sessionId")

        val command = if (detailed) "iI" else "i"
        
        logInfo("获取文件信息 (详细: $detailed, Session: ${sessionId.take(16)})")
        
        val result = R2Core.executeCommand(session.corePtr, command)
        
        return createToolResult(true, output = result)
    }

    private suspend fun executeOsListDir(args: JsonObject): JsonElement {
        val pathStr = args["path"]?.jsonPrimitive?.content ?: "/"
        val dir = java.io.File(pathStr)
        val resultLines = mutableListOf<String>()
        var usedRoot = false

        val files = dir.listFiles()
        if (files != null) {
            files.forEach { file ->
                val type = if (file.isDirectory) "[DIR] " else "[FILE]"
                val size = if (file.isFile) String.format("%-8s", "(${file.length()})") else "        "
                resultLines.add("$type $size ${file.name}")
            }
        } else {
            val cmd = "ls -p \"$pathStr\""
            val output = ShellUtils.execCommand(cmd, isRoot = true)

            if (output.isSuccess) {
                usedRoot = true
                output.successMsg.lines().forEach { line ->
                    if (line.isNotBlank()) {
                        val type = if (line.endsWith("/")) "[DIR] " else "[FILE]"
                        val name = line.removeSuffix("/")
                        resultLines.add("$type $name")
                    }
                }
            } else {
                return createToolResult(false, error = "❌ 无法访问目录: $pathStr\n错误信息: ${output.errorMsg}")
            }
        }

        val header = if (usedRoot) "=== 目录列表 (Root Access) ===\n" else "=== 目录列表 ===\n"
        val body = if (resultLines.isEmpty()) "(目录为空)" else resultLines.joinToString("\n")

        return createToolResult(true, output = header + body)
    }

    private suspend fun executeOsReadFile(args: JsonObject): JsonElement {
        val pathStr = args["path"]?.jsonPrimitive?.content
        if (pathStr.isNullOrEmpty()) {
            return createToolResult(false, error = "Path is required")
        }

        val file = java.io.File(pathStr)
        var content = ""
        var source = "Standard API"

        if (file.exists() && file.canRead()) {
            try {
                content = file.readText()
            } catch (e: Exception) {
            }
        }

        if (content.isEmpty()) {
            val output = ShellUtils.execCommand("cat \"$pathStr\"", isRoot = true)
            if (output.isSuccess) {
                content = output.successMsg
                source = "Root Access"
            } else {
                return createToolResult(false, error = "❌ 读取文件失败: $pathStr\nPermission denied & Root failed.")
            }
        }

        val limit = 50000 
        val truncatedNote = if (content.length > limit) {
            content = content.take(limit)
            "\n\n[⚠️ SYSTEM: 文件过大，已截断显示前 50KB 内容]"
        } else ""

        return createToolResult(true, output = "($source)\n$content$truncatedNote")
    }

    private suspend fun executeAnalyzeTarget(args: JsonObject): JsonElement {
        val strategy = args["strategy"]?.jsonPrimitive?.content ?: "basic"
        val address = args["address"]?.jsonPrimitive?.content

        val sessionId = args["session_id"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing session_id")

        val session = R2SessionManager.getSession(sessionId)
            ?: return createToolResult(false, error = "Invalid session_id: $sessionId")

        val addrSuffix = if (!address.isNullOrEmpty()) " @ $address" else ""

        val cmd = when (strategy) {
            "basic" -> "aa"
            "blocks" -> "aab$addrSuffix"
            "calls" -> "aac$addrSuffix"
            "refs" -> "aar$addrSuffix"
            "pointers" -> "aad$addrSuffix"
            "full" -> "aaa"
            else -> "aa"
        }

        logInfo("执行智能分析策略: $strategy (命令: $cmd, 会话: ${sessionId.take(16)})")

        val startTime = System.currentTimeMillis()
        val analysisOutput = R2Core.executeCommand(session.corePtr, cmd)
        val duration = System.currentTimeMillis() - startTime
        logInfo("分析完成，耗时 ${duration}ms")

        val funcCount = R2Core.executeCommand(session.corePtr, "afl~?").trim()
        val codeSize = R2Core.executeCommand(session.corePtr, "?v \$SS").trim()

        val resultMsg = StringBuilder()
        resultMsg.append("✅ 分析策略 '$strategy' 执行完毕 (Cmd: $cmd, 耗时: ${duration}ms)。\n")
        resultMsg.append("📊 当前状态：\n")
        resultMsg.append("- 已识别函数数: $funcCount\n")
        resultMsg.append("- 代码段大小: $codeSize bytes\n")

        when (strategy) {
            "calls" -> resultMsg.append("💡 提示：如果函数数量增加了，说明发现了新的子函数。")
            "pointers" -> resultMsg.append("💡 提示：请检查数据段是否识别出了新的 xref。")
            "blocks" -> resultMsg.append("💡 提示：函数基本块结构已优化，可能修复了截断问题。")
            "refs" -> resultMsg.append("💡 提示：数据引用已分析，可用于查找字符串和全局变量。")
            "full" -> resultMsg.append("⚠️ 注意：全量分析已完成，可能耗时较长。")
            else -> resultMsg.append("💡 提示：基础分析已完成，识别了符号和入口点。")
        }

        if (analysisOutput.isNotBlank()) {
            resultMsg.append("\n\n=== 分析输出 ===\n$analysisOutput")
        }

        return createToolResult(true, output = resultMsg.toString())
    }

    private suspend fun executeManageXrefs(args: JsonObject): JsonElement {
        val action = args["action"]?.jsonPrimitive?.content ?: "list_to"
        val target = args["target_address"]?.jsonPrimitive?.content ?: ""
        val source = args["source_address"]?.jsonPrimitive?.content

        val sessionId = args["session_id"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing session_id")

        val session = R2SessionManager.getSession(sessionId)
            ?: return createToolResult(false, error = "Invalid session_id: $sessionId")

        if (target.isEmpty()) {
            return createToolResult(false, error = "必须指定目标地址 (target_address)")
        }

        val atSuffix = if (!source.isNullOrEmpty()) " $source" else ""

        logInfo("执行交叉引用管理: $action (目标: $target, 源: ${source ?: "当前位置"}, 会话: ${sessionId.take(16)})")

        val resultText = when (action) {
            "list_to" -> {
                val json = R2Core.executeCommand(session.corePtr, "axtj $target")
                formatXrefs(json, "引用了 $target 的位置 (Xrefs TO)")
            }
            "list_from" -> {
                val json = R2Core.executeCommand(session.corePtr, "axfj $target")
                formatXrefs(json, "$target 引用了哪些位置 (Xrefs FROM)")
            }
            "add_code" -> runR2Action(session, "axc $target$atSuffix", "已添加代码引用")
            "add_call" -> runR2Action(session, "axC $target$atSuffix", "已添加函数调用引用")
            "add_data" -> runR2Action(session, "axd $target$atSuffix", "已添加数据引用")
            "add_string" -> runR2Action(session, "axs $target$atSuffix", "已添加字符串引用")
            "remove_all" -> runR2Action(session, "ax- $target", "已清除该地址的所有引用")
            else -> "❌ 未知操作: $action"
        }

        return createToolResult(true, output = resultText)
    }

    private suspend fun executeConfigManager(args: JsonObject): JsonElement {
        val action = args["action"]?.jsonPrimitive?.content ?: "get"
        val key = args["key"]?.jsonPrimitive?.content ?: ""
        val value = args["value"]?.jsonPrimitive?.content ?: ""

        if (key.isEmpty()) {
            return createToolResult(false, error = "必须指定配置键名 (key)")
        }

        val sessionId = args["session_id"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing session_id")

        val session = R2SessionManager.getSession(sessionId)
            ?: return createToolResult(false, error = "Invalid session_id: $sessionId")

        logInfo("执行配置管理: $action (键: $key, 值: $value, 会话: ${sessionId.take(16)})")

        val resultText = when (action) {
            "get" -> {
                val output = R2Core.executeCommand(session.corePtr, "e $key").trim()
                if (output.isEmpty()) {
                    "⚠️ 未找到配置项: $key"
                } else {
                    "$key = $output"
                }
            }
            "set" -> {
                if (value.isEmpty()) {
                    return createToolResult(false, error = "set 操作需要指定值 (value)")
                }
                R2Core.executeCommand(session.corePtr, "e $key=$value")

                val current = R2Core.executeCommand(session.corePtr, "e $key").trim()
                if (current == value || (value == "true" && current == "true") || (value == "false" && current == "false")) {
                    "✅ 配置已更新: $key = $current"
                } else {
                    "⚠️ 配置更新可能失败，当前值: $key = $current"
                }
            }
            "list" -> {
                val output = R2Core.executeCommand(session.corePtr, "e? $key")
                "🔎 搜索 '$key' 的结果:\n$output"
            }
            else -> "❌ 未知操作: $action"
        }

        return createToolResult(true, output = resultText)
    }

    private suspend fun executeAnalysisHints(args: JsonObject): JsonElement {
        val action = args["action"]?.jsonPrimitive?.content ?: "list"
        val address = args["address"]?.jsonPrimitive?.content ?: ""
        val value = args["value"]?.jsonPrimitive?.content ?: ""

        val sessionId = args["session_id"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing session_id")

        val session = R2SessionManager.getSession(sessionId)
            ?: return createToolResult(false, error = "Invalid session_id: $sessionId")

        val addrSuffix = if (address.isNotEmpty()) " @ $address" else ""
        val checkAddr = address

        logInfo("执行分析提示: $action (地址: ${address.ifEmpty { "当前位置" }}, 值: $value, 会话: ${sessionId.take(16)})")

        val resultText = when (action) {
            "list" -> {
                val output = R2Core.executeCommand(session.corePtr, "ah$addrSuffix").trim()
                if (output.isBlank()) {
                    "ℹ️ 该地址没有分析提示。"
                } else {
                    output
                }
            }
            "set_base" -> {
                if (value.isEmpty()) {
                    return createToolResult(false, error = "必须指定进制类型 (value)，如 10, 16, s, i")
                }
                R2Core.executeCommand(session.corePtr, "ahi $value$addrSuffix")
                "✅ 已修改数值显示格式为 '$value'"
            }
            "set_arch" -> {
                if (value.isEmpty()) {
                    return createToolResult(false, error = "必须指定架构 (value)，如 arm, x86")
                }
                R2Core.executeCommand(session.corePtr, "aha $value$addrSuffix")
                "✅ 已强制设置架构为 '$value'"
            }
            "set_bits" -> {
                if (value.isEmpty()) {
                    return createToolResult(false, error = "必须指定位数 (value)，如 32, 64")
                }
                R2Core.executeCommand(session.corePtr, "ahb $value$addrSuffix")
                "✅ 已强制设置位数为 '$value' bits"
            }
            "override_jump" -> {
                if (value.isEmpty()) {
                    return createToolResult(false, error = "必须指定跳转目标地址 (value)")
                }
                R2Core.executeCommand(session.corePtr, "ahc $value$addrSuffix")
                "✅ 已强制覆盖跳转目标为 $value"
            }
            "override_opcode" -> {
                if (value.isEmpty()) {
                    return createToolResult(false, error = "必须指定新的指令字符串 (value)")
                }
                R2Core.executeCommand(session.corePtr, "ahd $value$addrSuffix")
                "✅ 已将指令文本替换为: \"$value\""
            }
            "remove" -> {
                R2Core.executeCommand(session.corePtr, "ah-$addrSuffix")
                "✅ 已清除该地址的分析提示"
            }
            else -> "❌ 未知操作: $action"
        }

        val previewCmd = if (checkAddr.isNotEmpty()) "pd 1 @ $checkAddr" else "pd 1"
        val preview = R2Core.executeCommand(session.corePtr, previewCmd).trim()

        val finalOutput = "$resultText\n\n🔍 当前效果预览:\n$preview"
        return createToolResult(true, output = finalOutput)
    }

    private suspend fun executeSqliteQuery(args: JsonObject): JsonElement {
        val dbPath = args["db_path"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing db_path")
        val query = args["query"]?.jsonPrimitive?.content
            ?: return createToolResult(false, error = "Missing query")

        val maxLines = args["max_lines"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxLines()
        val maxChars = args["max_chars"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxChars()

        val safeQuery = query.replace("\"", "\\\"")

        val command = "sqlite3 -header -column \"$dbPath\" \"$safeQuery\""

        logInfo("执行 SQL: $command")

        val result = ShellUtils.execCommand(command, isRoot = true)

        return if (result.isSuccess) {
            val cleanOutput = sanitizeOutput(result.successMsg, maxLines = maxLines, maxChars = maxChars)
            createToolResult(true, output = cleanOutput)
        } else {
            createToolResult(false, error = "SQL Error:\n${result.errorMsg}\n(Exit Code: Fail)")
        }
    }

    private fun formatXrefs(jsonStr: String, title: String): String {
        if (jsonStr.trim().isEmpty() || jsonStr == "[]") {
            return "ℹ️ $title: 无数据"
        }

        try {
            val sb = StringBuilder("📊 $title:\n")
            val items = jsonStr.trim().removePrefix("[").removeSuffix("]").split("},")

            for ((index, item) in items.withIndex()) {
                val cleanItem = item.removePrefix("{").removeSuffix("}").trim()
                if (cleanItem.isEmpty()) continue

                val fields = cleanItem.split(",").associate {
                    val parts = it.split(":", limit = 2)
                    if (parts.size == 2) {
                        parts[0].trim().removeSurrounding("\"") to parts[1].trim().removeSurrounding("\"")
                    } else {
                        "" to ""
                    }
                }

                val type = fields["type"] ?: "UNK"
                val from = fields["from"]?.toLongOrNull() ?: 0
                val to = fields["to"]?.toLongOrNull() ?: 0

                val refAddr = if (title.contains("TO")) from else to
                val hexAddr = "0x%08x".format(refAddr)

                sb.append("- [$type] $hexAddr")

                fields["opcode"]?.let { opcode ->
                    sb.append(" : ${opcode.trim()}")
                }
                fields["fcn_name"]?.let { fcnName ->
                    sb.append(" (in $fcnName)")
                }

                sb.append("\n")
            }

            return sb.toString()
        } catch (e: Exception) {
            logError("Xref JSON 解析失败", e.message)
            return "⚠️ 解析数据失败，原始返回:\n$jsonStr"
        }
    }
    private fun runR2Action(session: R2SessionManager.R2Session, cmd: String, successMsg: String): String {
        R2Core.executeCommand(session.corePtr, cmd)
        return "✅ $successMsg (Cmd: $cmd)"
    }

    // --- [新增] Termux 工具具体实现 ---
    private suspend fun executeTermuxCommand(args: JsonObject): JsonElement {
        val cmd = args["command"]?.jsonPrimitive?.content ?: return createToolResult(false, error = "缺少命令参数")
        val useRoot = args["use_root"]?.jsonPrimitive?.booleanOrNull ?: false

        val maxLines = args["max_lines"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxLines()
        val maxChars = args["max_chars"]?.jsonPrimitive?.intOrNull ?: R2AIConfig.getMaxChars()

        if (isDangerousCommand(cmd)) return createToolResult(false, error = "❌ 安全拦截: 检测到危险命令")

        // 1. 准备环境 (PATH, LD_LIBRARY_PATH)
        val envSetup = getTermuxEnvSetup()
        val fullCmd = "$envSetup $cmd"

        // 2. 构造最终执行命令
        val finalCmd = if (useRoot) {
            // Root 模式：直接执行
            logInfo("⚡ [Root] Termux Exec: $cmd")
            fullCmd
        } else {
            // 普通模式：使用 su 切换到 Termux 用户 (比 Root 安全)
            val termuxUid = getTermuxUser()
            logInfo("🔒 [User $termuxUid] Termux Exec: $cmd")
            // 注意：需要转义双引号以防止 su -c 解析错误
            "su $termuxUid -c \"${fullCmd.replace("\"", "\\\"")}\""
        }

        // 3. 执行
        val result = ShellUtils.execCommand(finalCmd, isRoot = true)

        return if (result.isSuccess) {
            createToolResult(true, output = sanitizeOutput(result.successMsg, maxLines = maxLines, maxChars = maxChars))
        } else {
            createToolResult(false, error = "Termux Error:\n${result.errorMsg}")
        }
    }

    private suspend fun executeSaveScript(args: JsonObject): JsonElement {
        val filename = args["filename"]?.jsonPrimitive?.content ?: return createToolResult(false, error = "缺少文件名")
        val content = args["content"]?.jsonPrimitive?.content ?: return createToolResult(false, error = "缺少内容")

        if (filename.contains("/") || filename.contains("\\")) {
            return createToolResult(false, error = "❌ 文件名不能包含路径")
        }
        
        val scriptPath = "$TERMUX_AI_DIR/$filename"
        val termuxUid = getTermuxUser()

        // 使用 Base64 传输内容，防止特殊字符导致 Shell 写入失败
        val base64Content = android.util.Base64.encodeToString(
            content.toByteArray(Charsets.UTF_8), 
            android.util.Base64.NO_WRAP
        )

        // 原子操作：创建目录 -> 写入文件 -> 改权限 -> 改所有者
        val cmd = "mkdir -p '$TERMUX_AI_DIR' && " +
                  "echo '$base64Content' | base64 -d > '$scriptPath' && " +
                  "chmod 755 '$scriptPath' && " +
                  "chown $termuxUid:$termuxUid '$scriptPath'"

        val result = ShellUtils.execCommand(cmd, isRoot = true)

        return if (result.isSuccess) {
            createToolResult(true, output = "✅ 已保存: $scriptPath\n所有者: $termuxUid")
        } else {
            createToolResult(false, error = "保存失败:\n${result.errorMsg}")
        }
    }

    // --- 🧠 记忆宫殿辅助函数 (Internal Storage Ver.) ---

    // 使用 App 的私有目录。建议加一级子目录 'knowledge' 保持整洁
    // 如果您在 Service/Activity 中有 Context，也可以用 context.filesDir.absolutePath + "/knowledge"
    val KNOWLEDGE_BASE_DIR = "/data/data/com.r2aibridge/files/knowledge"

    // 获取知识库文件对象
    fun getKnowledgeFile(targetPath: String): File {
        // 使用目标文件的哈希或文件名作为 JSON 文件名
        // 为了防止路径中的 "/" 搞乱文件名，这里简单处理：把 "/" 替换为 "_"
        // 例如: /system/lib/libc.so -> _system_lib_libc.so.json
        val safeName = targetPath.replace("/", "_") + ".json"
        
        val dir = File(KNOWLEDGE_BASE_DIR)
        if (!dir.exists()) {
            // 创建目录 (不需要 root，因为是在自己的沙箱里)
            dir.mkdirs()
        }
        return File(dir, safeName)
    }

    // 保存知识 (保持不变)
    fun saveKnowledge(targetPath: String, type: String, address: String, content: String) {
        try {
            val file = getKnowledgeFile(targetPath)
            val json = if (file.exists()) JSONObject(file.readText()) else JSONObject()
            
            if (!json.has(type)) json.put(type, JSONObject())
            
            json.getJSONObject(type).put(address, content)
            
            file.writeText(json.toString(2))
            Log.i("R2AI", "Memory saved to internal storage: $type[$address]")
        } catch (e: Exception) {
            Log.e("R2AI", "Failed to save knowledge", e)
        }
    }

    // 加载知识 (保持不变)
    data class KnowledgeRestore(val r2Commands: List<String>, val summary: String)

    fun loadKnowledge(targetPath: String): KnowledgeRestore {
        val file = getKnowledgeFile(targetPath)
        if (!file.exists()) return KnowledgeRestore(emptyList(), "无历史知识库 (新文件)。")

        val commands = mutableListOf<String>()
        val summaryBuilder = StringBuilder("📚 已从知识库恢复：\n")
        
        try {
            val json = JSONObject(file.readText())
            
            if (json.has("renames")) {
                val renames = json.getJSONObject("renames")
                var count = 0
                renames.keys().forEach { addr ->
                    val name = renames.getString(addr)
                    commands.add("afn $name $addr")
                    count++
                }
                summaryBuilder.append("- $count 个函数重命名\n")
            }
            
            if (json.has("notes")) {
                val notes = json.getJSONObject("notes")
                var count = 0
                notes.keys().forEach { addr ->
                    val note = notes.getString(addr)
                    summaryBuilder.append("- 笔记 @ $addr: $note\n")
                    count++
                }
            }
            
        } catch (e: Exception) {
            return KnowledgeRestore(emptyList(), "读取知识库失败: ${e.message}")
        }
        
        return KnowledgeRestore(commands, summaryBuilder.toString())
    }
}