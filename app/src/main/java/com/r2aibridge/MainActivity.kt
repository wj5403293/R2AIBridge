package com.r2aibridge

import android.Manifest
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.wifi.WifiManager
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.provider.Settings
import android.util.Log
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsControllerCompat
import com.r2aibridge.mcp.MCPServer
import com.r2aibridge.mcp.R2AIConfig
import com.r2aibridge.service.R2ServiceForeground
import com.r2aibridge.ui.theme.R2AIBridgeTheme
import java.net.Inet4Address
import java.net.NetworkInterface
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CoroutineScope

class MainActivity : ComponentActivity() {

    private val logEventReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            Log.d("MainActivity", "BroadcastReceiver: 收到广播 操作=${intent?.action}")
            when (intent?.action) {
                R2ServiceForeground.ACTION_LOG_EVENT -> {
                    val message = intent.getStringExtra(R2ServiceForeground.EXTRA_LOG_MESSAGE)
                    Log.d("MainActivity", "BroadcastReceiver: 收到日志消息=$message")
                    message?.let { logMessage ->
                        Log.d("MainActivity", "BroadcastReceiver: 调用回调 回调=${logEventCallback != null}")
                        // 通过回调传递给Compose
                        logEventCallback?.invoke(logMessage)
                    }
                }
                R2ServiceForeground.ACTION_STOP -> {
                    Log.d("MainActivity", "BroadcastReceiver: 收到 ACTION_STOP，触发停止回调")
                    stopEventCallback?.invoke()
                }
            }
        }
    }
    
    private var logEventCallback: ((String) -> Unit)? = null
    private var stopEventCallback: (() -> Unit)? = null

    private val manageAllFilesLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (Environment.isExternalStorageManager()) {
                Toast.makeText(this, "✅ 已获得所有文件访问权限", Toast.LENGTH_SHORT).show()
                startR2Service()
            } else {
                Toast.makeText(this, "⚠️ 未授予所有文件访问权限，部分功能可能无法使用", Toast.LENGTH_LONG).show()
            }
        }
    }

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.values.all { it }
        if (allGranted) {
            // 普通权限已授予，检查所有文件访问权限
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                if (!Environment.isExternalStorageManager()) {
                    // 引导用户到设置页面授予所有文件访问权限
                    requestAllFilesAccess()
                } else {
                    startR2Service()
                }
            } else {
                startR2Service()
            }
        } else {
            Toast.makeText(this, "⚠️ 需要授予所有权限才能正常使用", Toast.LENGTH_LONG).show()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // 初始化全局配置
        R2AIConfig.init(this)

        // 🔥 智能加载 Radare2 库（热插拔支持）
        try {
            R2Core.loadLibraries(this)
            Log.i("MainActivity", "✅ 通过智能加载器加载 R2 库")
            
            // 🧹 清理所有 Root 复制的副本文件
            MCPServer.cleanupRootCopies()
        } catch (e: Exception) {
            Log.e("MainActivity", "❌ 加载 R2 库失败", e)
            Toast.makeText(this, "R2库加载失败：${e.message}", Toast.LENGTH_LONG).show()
        }
        
        // 启用边到边显示和透明状态栏
        WindowCompat.setDecorFitsSystemWindows(window, false)
        
        // 注册日志事件接收器，并同时监听服务停止动作，便于通知栏停止与主界面按钮行为一致
        val filter = IntentFilter().apply {
            addAction(R2ServiceForeground.ACTION_LOG_EVENT)
            addAction(R2ServiceForeground.ACTION_STOP)
        }
        ContextCompat.registerReceiver(this, logEventReceiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED)
        
        requestRequiredPermissions()
        
        setContent {
            R2AIBridgeTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen(
                        onStartService = { startR2Service() },
                        onStopService = { stopR2Service() },
                        getWifiIpAddress = { getWifiIpAddress() },
                        onLogEventCallbackSet = { callback -> logEventCallback = callback },
                        onStopEventCallbackSet = { callback -> stopEventCallback = callback }
                    )
                }
            }
        }
    }

    private fun requestRequiredPermissions() {
        // 先检查Android 11+的所有文件访问权限
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            if (Environment.isExternalStorageManager()) {
                Log.d("MainActivity", "已有所有文件访问权限")
                // 已有权限，直接请求其他权限
                requestOtherPermissions()
                return
            }
        }
        
        // 请求普通权限
        requestOtherPermissions()
    }
    
    private fun requestOtherPermissions() {
        val permissions = mutableListOf(
            Manifest.permission.INTERNET,
            Manifest.permission.ACCESS_WIFI_STATE
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            permissions.add(Manifest.permission.POST_NOTIFICATIONS)
        }
        
        // Android 10及以下才需要这些权限
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            permissions.add(Manifest.permission.READ_EXTERNAL_STORAGE)
            permissions.add(Manifest.permission.WRITE_EXTERNAL_STORAGE)
        }

        permissionLauncher.launch(permissions.toTypedArray())
    }
    
    private fun requestAllFilesAccess() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                val intent = Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION)
                intent.data = android.net.Uri.parse("package:$packageName")
                Toast.makeText(this, "请授予'允许访问所有文件'权限", Toast.LENGTH_LONG).show()
                manageAllFilesLauncher.launch(intent)
            } catch (e: Exception) {
                val intent = Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION)
                Toast.makeText(this, "请授予'允许访问所有文件'权限", Toast.LENGTH_LONG).show()
                manageAllFilesLauncher.launch(intent)
            }
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        try {
            unregisterReceiver(logEventReceiver)
        } catch (_: Exception) {}
    }

    private fun startR2Service() {
        val intent = Intent(this, R2ServiceForeground::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun stopR2Service() {
        val intent = Intent(this, R2ServiceForeground::class.java)
        stopService(intent)
    }

    private fun getWifiIpAddress(): String {
        try {
            val wifiManager = applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            if (!wifiManager.isWifiEnabled) {
                return "未连接WiFi"
            }
            
            @Suppress("DEPRECATION")
            val wifiInfo = wifiManager.connectionInfo
            @Suppress("DEPRECATION")
            val ipInt = wifiInfo.ipAddress
            
            if (ipInt != 0) {
                return String.format(
                    "%d.%d.%d.%d",
                    ipInt and 0xff,
                    ipInt shr 8 and 0xff,
                    ipInt shr 16 and 0xff,
                    ipInt shr 24 and 0xff
                )
            }
            
            // Fallback: 遍历网络接口查找 WiFi 地址
            val interfaces = NetworkInterface.getNetworkInterfaces()
            while (interfaces.hasMoreElements()) {
                val networkInterface = interfaces.nextElement()
                val name = networkInterface.name ?: continue
                // WiFi 接口通常叫 wlan0 或包含 wlan
                if (!name.contains("wlan", ignoreCase = true)) continue
                val addresses = networkInterface.inetAddresses
                while (addresses.hasMoreElements()) {
                    val address = addresses.nextElement()
                    if (address is Inet4Address && !address.isLoopbackAddress) {
                        return address.hostAddress ?: "未连接WiFi"
                    }
                }
            }
            
            return "未连接WiFi"
        } catch (e: Exception) {
            return "未连接WiFi"
        }
    }
}

@Composable
fun MainScreen(
    onStartService: () -> Unit,
    onStopService: () -> Unit,
    getWifiIpAddress: () -> String,
    onLogEventCallbackSet: ((String) -> Unit) -> Unit,
    onStopEventCallbackSet: (() -> Unit) -> Unit
) {
    var isServiceRunning by remember { mutableStateOf(true) } // 默认启动
    val commandHistory = remember { mutableStateListOf<String>() }
    val realLogcatHistory = remember { mutableStateListOf<String>() }
    val logListState = rememberLazyListState()
    val context = LocalContext.current
    val view = LocalView.current
    val focusManager = LocalFocusManager.current

    /**
     * 启动持续的 R2AI 日志监听
     */
    suspend fun startLogcatMonitoring() {
        try {
            val process = Runtime.getRuntime().exec(arrayOf("logcat", "-s", "R2AI"))
            val reader = java.io.BufferedReader(java.io.InputStreamReader(process.inputStream))
            
            var line: String?
            while (reader.readLine().also { line = it } != null && !process.waitFor(10, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                line?.let { logLine ->
                    if (logLine.isNotBlank()) {
                        // 在主线程上更新UI
                        withContext(Dispatchers.Main) {
                            realLogcatHistory.add(logLine)
                            // 限制历史记录数量
                            if (realLogcatHistory.size > 1000) {
                                realLogcatHistory.removeRange(0, realLogcatHistory.size - 1000)
                            }
                        }
                    }
                }
            }
            
            reader.close()
            process.destroy()
        } catch (e: Exception) {
            withContext(Dispatchers.Main) {
                realLogcatHistory.add("日志监听失败: ${e.message}")
            }
        }
    }

    /**
     * 生成 Android logcat 格式的日志消息
     */
    fun formatLogcatMessage(level: String, tag: String, message: String): String {
        val now = java.util.Date()
        val dateFormat = java.text.SimpleDateFormat("MM-dd HH:mm:ss.SSS", java.util.Locale.getDefault())
        val timestamp = dateFormat.format(now)
        val pid = android.os.Process.myPid()
        // 使用 System.nanoTime() 的哈希值作为线程ID的替代方案
        val tid = (System.nanoTime() % 100000).toInt()
        return String.format("%s %5d %5d %s %s    : %s", timestamp, pid, tid, level, tag, message)
    }
    
    // 设置日志事件回调
        LaunchedEffect(Unit) {
        Log.d("MainActivity", "LaunchedEffect: 设置日志回调")
        onLogEventCallbackSet { logMessage ->
            Log.d("MainActivity", "回调: 收到日志=$logMessage")
            commandHistory.add(0, formatLogcatMessage("I", "R2AI", logMessage))
        }
        // 注册停止事件回调，通知栏停止时通过此回调更新 UI
        onStopEventCallbackSet {
            isServiceRunning = false
            commandHistory.add(0, formatLogcatMessage("I", "R2AI", "⛔ 服务已停止"))
        }
        // 添加初始消息
        commandHistory.add(0, formatLogcatMessage("I", "R2AI", "📱 应用启动"))
        Log.d("MainActivity", "LaunchedEffect: 启动服务")
        // 启动服务
        onStartService()

        // 启动持续的 R2AI 日志监听
        launch(Dispatchers.IO) {
            startLogcatMonitoring()
        }
    }
    
    // 设置透明状态栏和图标颜色
    val darkTheme = isSystemInDarkTheme()
    
    SideEffect {
        val window = (view.context as ComponentActivity).window
        
        // 设置状态栏图标颜色：明亮模式用深色图标，深色模式用浅色图标
        WindowInsetsControllerCompat(window, view).apply {
            isAppearanceLightStatusBars = !darkTheme
            isAppearanceLightNavigationBars = !darkTheme
        }
    }
    
    val wifiIp = remember(isServiceRunning) { getWifiIpAddress() }
    val localhostUrl = "http://127.0.0.1:5050/mcp"
    val wifiUrl = if (wifiIp != "未连接WiFi") "http://$wifiIp:5050/mcp" else null

    val edbgLocalhostUrl = ShellUtils.EDBG.getLocalhostUrl()
    val edbgWifiUrl = if (wifiIp != "未连接WiFi") ShellUtils.EDBG.getWifiUrl(wifiIp) else null
    var isEdbgRunning by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    fun refreshEdbgStatus() {
        scope.launch(Dispatchers.IO) {
            val running = ShellUtils.EDBG.isRunning()
            withContext(Dispatchers.Main) {
                isEdbgRunning = running
            }
        }
    }

    LaunchedEffect(Unit) {
        refreshEdbgStatus()
        while (true) {
            delay(3000)
            refreshEdbgStatus()
        }
    }

    val scrollState = rememberScrollState()

    // 点击空白处清除焦点
    Column(
        modifier = Modifier
            .fillMaxSize()
            .statusBarsPadding()
            .navigationBarsPadding()
            .padding(12.dp)
            .verticalScroll(scrollState)
            .clickable(
                interactionSource = remember { MutableInteractionSource() },
                indication = null,
                onClick = { focusManager.clearFocus() }
            ),
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        // Title
        Text(
            text = "Radare2 AI Bridge",
            style = MaterialTheme.typography.titleLarge,
            modifier = Modifier.padding(bottom = 4.dp)
        )
        
        // Telegram Group Link
        Text(
            text = "Telegram群: t.me/MuortVIP",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.primary,
            modifier = Modifier
                .clickable {
                    val intent = Intent(Intent.ACTION_VIEW, android.net.Uri.parse("https://t.me/MuortVIP"))
                    context.startActivity(intent)
                }
                .padding(bottom = 8.dp)
        )

        // Service Status Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 3.dp),
            colors = CardDefaults.cardColors(
                containerColor = if (isServiceRunning) 
                    Color(0xFF4CAF50) 
                else 
                    Color(0xFFFF9800)
            )
        ) {
            Column(
                modifier = Modifier.padding(12.dp)
            ) {
                Text(
                    text = if (isServiceRunning) "R2 MCP: 运行中" else "R2 MCP: 已停止",
                    style = MaterialTheme.typography.titleSmall,
                    color = Color.White
                )
                
                if (isServiceRunning) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "端口: 5050",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color.White
                    )
                    
                    Spacer(modifier = Modifier.height(6.dp))
                    
                    // 本地地址
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "本地地址:",
                                style = MaterialTheme.typography.bodySmall,
                                fontSize = 11.sp,
                                color = Color.White.copy(alpha = 0.8f)
                            )
                            Text(
                                text = localhostUrl,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = Color.White
                            )
                        }
                        Button(
                            onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                val clip = ClipData.newPlainText("MCP URL", localhostUrl)
                                clipboard.setPrimaryClip(clip)
                                Toast.makeText(context, "已复制", Toast.LENGTH_SHORT).show()
                            },
                            modifier = Modifier.size(32.dp),
                            contentPadding = PaddingValues(0.dp)
                        ) {
                            Text("📋", style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                    
                    Spacer(modifier = Modifier.height(4.dp))
                    
                    // WiFi 地址
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "WiFi地址:",
                                style = MaterialTheme.typography.bodySmall,
                                fontSize = 11.sp,
                                color = Color.White.copy(alpha = 0.8f)
                            )
                            Text(
                                text = wifiUrl ?: wifiIp,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = Color.White
                            )
                        }
                        Button(
                            onClick = {
                                if (wifiUrl != null) {
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    val clip = ClipData.newPlainText("MCP URL", wifiUrl)
                                    clipboard.setPrimaryClip(clip)
                                    Toast.makeText(context, "已复制", Toast.LENGTH_SHORT).show()
                                } else {
                                    Toast.makeText(context, "WiFi未连接", Toast.LENGTH_SHORT).show()
                                }
                            },
                            modifier = Modifier.size(32.dp),
                            contentPadding = PaddingValues(0.dp)
                        ) {
                            Text("📋", style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                }
            }
        }

        // R2 Control Buttons
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 2.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Button(
                onClick = {
                    onStartService()
                    isServiceRunning = true
                },
                modifier = Modifier.weight(1f).height(36.dp),
                enabled = !isServiceRunning,
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)
            ) {
                Text("启动R2", style = MaterialTheme.typography.bodySmall)
            }

            Button(
                onClick = {
                    onStopService()
                    isServiceRunning = false
                    commandHistory.add(0, formatLogcatMessage("I", "R2AI", "⛔ 服务已停止"))
                },
                modifier = Modifier.weight(1f).height(36.dp),
                enabled = isServiceRunning,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error
                ),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)
            ) {
                Text("停止R2", style = MaterialTheme.typography.bodySmall)
            }
        }

        // eDBG Status Card
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 3.dp),
            colors = CardDefaults.cardColors(
                containerColor = if (isEdbgRunning)
                    Color(0xFF2196F3)
                else
                    Color(0xFF9E9E9E)
            )
        ) {
            Column(
                modifier = Modifier.padding(12.dp)
            ) {
                Text(
                    text = "eDBG MCP: ${if (isEdbgRunning) "运行中" else "已停止"}",
                    style = MaterialTheme.typography.titleSmall,
                    color = Color.White
                )

                if (isEdbgRunning) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "端口: ${ShellUtils.EDBG.getPort()}",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color.White
                    )

                    Spacer(modifier = Modifier.height(6.dp))

                    // 本地地址
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "本地地址:",
                                style = MaterialTheme.typography.bodySmall,
                                fontSize = 11.sp,
                                color = Color.White.copy(alpha = 0.8f)
                            )
                            Text(
                                text = edbgLocalhostUrl,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = Color.White
                            )
                        }
                        Button(
                            onClick = {
                                val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                val clip = ClipData.newPlainText("eDBG MCP URL", edbgLocalhostUrl)
                                clipboard.setPrimaryClip(clip)
                                Toast.makeText(context, "已复制", Toast.LENGTH_SHORT).show()
                            },
                            modifier = Modifier.size(32.dp),
                            contentPadding = PaddingValues(0.dp)
                        ) {
                            Text("📋", style = MaterialTheme.typography.bodyMedium)
                        }
                    }

                    Spacer(modifier = Modifier.height(4.dp))

                    // WiFi 地址
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = "WiFi地址:",
                                style = MaterialTheme.typography.bodySmall,
                                fontSize = 11.sp,
                                color = Color.White.copy(alpha = 0.8f)
                            )
                            Text(
                                text = edbgWifiUrl ?: wifiIp,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                color = Color.White
                            )
                        }
                        Button(
                            onClick = {
                                if (edbgWifiUrl != null) {
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    val clip = ClipData.newPlainText("eDBG MCP URL", edbgWifiUrl)
                                    clipboard.setPrimaryClip(clip)
                                    Toast.makeText(context, "已复制", Toast.LENGTH_SHORT).show()
                                } else {
                                    Toast.makeText(context, "WiFi未连接", Toast.LENGTH_SHORT).show()
                                }
                            },
                            modifier = Modifier.size(32.dp),
                            contentPadding = PaddingValues(0.dp)
                        ) {
                            Text("📋", style = MaterialTheme.typography.bodyMedium)
                        }
                    }
                } else {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "点击下方按钮启动eDBG动态调试（⚠️ 需 Root 权限）",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color.White.copy(alpha = 0.8f)
                    )
                }
            }
        }

        // eDBG Control Buttons
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 2.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Button(
                onClick = {
                    scope.launch(Dispatchers.IO) {
                        val success = ShellUtils.EDBG.start(context)
                        withContext(Dispatchers.Main) {
                            if (success) {
                                Toast.makeText(context, "eDBG 启动中...", Toast.LENGTH_SHORT).show()
                            } else {
                                Toast.makeText(context, "eDBG 启动失败，请检查 Root 权限", Toast.LENGTH_LONG).show()
                            }
                            refreshEdbgStatus()
                        }
                    }
                },
                modifier = Modifier.weight(1f).height(36.dp),
                enabled = !isEdbgRunning,
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)
            ) {
                Text("启动eDBG", style = MaterialTheme.typography.bodySmall)
            }

            Button(
                onClick = {
                    scope.launch(Dispatchers.IO) {
                        ShellUtils.EDBG.stop()
                        withContext(Dispatchers.Main) {
                            Toast.makeText(context, "eDBG 已停止", Toast.LENGTH_SHORT).show()
                            refreshEdbgStatus()
                        }
                    }
                },
                modifier = Modifier.weight(1f).height(36.dp),
                enabled = isEdbgRunning,
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.error
                ),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)
            ) {
                Text("停止eDBG", style = MaterialTheme.typography.bodySmall)
            }
        }

        // 输出配置卡片
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 3.dp)
        ) {
            Column(
                modifier = Modifier.padding(12.dp)
            ) {
                Text(
                    text = "输出配置",
                    style = MaterialTheme.typography.titleSmall
                )
                Text(
                    text = "⚠️ 超5万字符将显著增加Token消耗，耗尽上下文窗口将导致对话中断。",
                    style = MaterialTheme.typography.bodySmall,
                    fontSize = 11.sp,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.padding(bottom = 4.dp)
                )

                var maxLinesText by remember { mutableStateOf(R2AIConfig.getMaxLines().toString()) }
                var maxCharsText by remember { mutableStateOf(R2AIConfig.getMaxChars().toString()) }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    OutlinedTextField(
                        value = maxLinesText,
                        onValueChange = { maxLinesText = it.filter { c -> c.isDigit() } },
                        label = { Text("最大行数", style = MaterialTheme.typography.bodySmall) },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        textStyle = MaterialTheme.typography.bodySmall
                    )
                    OutlinedTextField(
                        value = maxCharsText,
                        onValueChange = { maxCharsText = it.filter { c -> c.isDigit() } },
                        label = { Text("最大字符数", style = MaterialTheme.typography.bodySmall) },
                        modifier = Modifier.weight(1f),
                        singleLine = true,
                        textStyle = MaterialTheme.typography.bodySmall
                    )
                }

                Spacer(modifier = Modifier.height(6.dp))

                Button(
                    onClick = {
                        val lines = maxLinesText.toIntOrNull() ?: 800
                        val chars = maxCharsText.toIntOrNull() ?: 24000
                        R2AIConfig.setMaxLines(lines)
                        R2AIConfig.setMaxChars(chars)
                        focusManager.clearFocus()
                        val imm = context.getSystemService(Context.INPUT_METHOD_SERVICE) as android.view.inputmethod.InputMethodManager
                        imm.hideSoftInputFromWindow(view.windowToken, 0)
                        Toast.makeText(context, "已保存", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.fillMaxWidth().height(36.dp),
                    contentPadding = PaddingValues(horizontal = 8.dp, vertical = 0.dp)
                ) {
                    Text("保存配置", style = MaterialTheme.typography.bodySmall)
                }
            }
        }

        // Real R2AI Logcat
        var isLogExpanded by remember { mutableStateOf(true) }
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = 6.dp, bottom = 2.dp)
                .clickable { isLogExpanded = !isLogExpanded },
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = if (isLogExpanded) "▼" else "▶",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(end = 4.dp)
                )
                Text(
                    text = "日志 (${realLogcatHistory.size})",
                    style = MaterialTheme.typography.titleSmall
                )
            }
            Row(
                modifier = Modifier,
                horizontalArrangement = Arrangement.Center,
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(
                    onClick = {
                        if (realLogcatHistory.isNotEmpty()) {
                            val allLogs = realLogcatHistory.joinToString("\n")
                            val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                            val clip = ClipData.newPlainText("R2AI Logs", allLogs)
                            clipboard.setPrimaryClip(clip)
                            Toast.makeText(context, "已复制全部日志", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(context, "无日志", Toast.LENGTH_SHORT).show()
                        }
                    },
                    modifier = Modifier.size(28.dp)
                ) {
                    Text(
                        text = "📋",
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
                Spacer(modifier = Modifier.width(8.dp))
                IconButton(
                    onClick = {
                        realLogcatHistory.clear()
                        Toast.makeText(context, "已清除", Toast.LENGTH_SHORT).show()
                    },
                    modifier = Modifier.size(28.dp)
                ) {
                    Text(
                        text = "🗑️",
                        style = MaterialTheme.typography.bodyMedium
                    )
                }
            }
        }
        
        if (isLogExpanded) {
        Card(
            modifier = Modifier
                .fillMaxWidth()
                .height(500.dp)
        ) {
            // 自动滚动到最新日志
            LaunchedEffect(realLogcatHistory.size) {
                if (realLogcatHistory.isNotEmpty()) {
                    logListState.animateScrollToItem(realLogcatHistory.size - 1)
                }
            }
            
            if (realLogcatHistory.isNotEmpty()) {
                LazyColumn(
                    state = logListState,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(8.dp)
                ) {
                    items(realLogcatHistory) { logLine ->
                        Card(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 2.dp)
                                .clickable {
                                    val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                                    val clip = ClipData.newPlainText("Logcat Line", logLine)
                                    clipboard.setPrimaryClip(clip)
                                    Toast.makeText(context, "已复制日志行", Toast.LENGTH_SHORT).show()
                                },
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.surfaceVariant
                            )
                        ) {
                            Text(
                                text = logLine,
                                style = MaterialTheme.typography.bodySmall,
                                fontFamily = FontFamily.Monospace,
                                modifier = Modifier.padding(8.dp)
                            )
                        }
                    }
                }
            } else {
                // 显示空状态
                Box(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(32.dp),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "暂无 R2AI 日志\n等待日志输出...",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = androidx.compose.ui.text.style.TextAlign.Center
                    )
                }
            }
        }
        } else {
            // 折叠状态下显示相关链接
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 2.dp)
            ) {
                Column(
                    modifier = Modifier.padding(12.dp)
                ) {
                    Text(
                        text = "项目链接",
                        style = MaterialTheme.typography.titleSmall,
                        modifier = Modifier.padding(bottom = 6.dp)
                    )

                    val links = listOf(
                        "R2AIBridge" to "https://github.com/muort521/R2AIBridge",
                        "Radare2" to "https://github.com/radareorg/radare2",
                        "eDBG" to "https://github.com/ShinoLeah/eDBG",
                        "MCP Protocol" to "https://modelcontextprotocol.io/"
                    )

                    links.forEach { (name, url) ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable {
                                    val intent = Intent(Intent.ACTION_VIEW, android.net.Uri.parse(url))
                                    context.startActivity(intent)
                                }
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "🔗",
                                style = MaterialTheme.typography.bodySmall,
                                modifier = Modifier.padding(end = 6.dp)
                            )
                            Text(
                                text = name,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.primary,
                                modifier = Modifier.weight(1f)
                            )
                            Text(
                                text = "→",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
}
