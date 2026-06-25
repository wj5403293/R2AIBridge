package com.r2aibridge

import java.io.BufferedReader
import java.io.InputStreamReader

object ShellUtils {
    data class CommandResult(
        val isSuccess: Boolean,
        val successMsg: String,
        val errorMsg: String
    )

    /**
     * 执行 Shell 命令
     * @param command 命令内容
     * @param isRoot 是否需要 Root 权限
     */
    fun execCommand(command: String, isRoot: Boolean): CommandResult {
        return try {
            val cmd = if (isRoot) arrayOf("su", "-c", command) else arrayOf("sh", "-c", command)
            val process = Runtime.getRuntime().exec(cmd)

            // 读取标准输出
            val successMsg = BufferedReader(InputStreamReader(process.inputStream)).use { it.readText() }
            // 读取错误输出
            val errorMsg = BufferedReader(InputStreamReader(process.errorStream)).use { it.readText() }

            val exitCode = process.waitFor()

            CommandResult(
                isSuccess = exitCode == 0,
                successMsg = successMsg,
                errorMsg = errorMsg
            )
        } catch (e: Exception) {
            CommandResult(false, "", e.message ?: "Unknown Shell Error")
        }
    }

    /**
     * eDBG 相关操作
     */
    object EDBG {
        private const val EDBG_ASSET_NAME = "eDBG"
        private const val EDBG_PORT = 19810

        private fun getEdbgPath(context: android.content.Context): String {
            return "${context.filesDir.absolutePath}/eDBG"
        }

        fun ensureBinary(context: android.content.Context): Boolean {
            return try {
                val edbgPath = getEdbgPath(context)
                val file = java.io.File(edbgPath)
                if (file.exists() && file.length() > 0 && file.canExecute()) {
                    true
                } else {
                    copyFromAssets(context, EDBG_ASSET_NAME, edbgPath)
                }
            } catch (e: Exception) {
                false
            }
        }

        private fun copyFromAssets(context: android.content.Context, assetName: String, destPath: String): Boolean {
            return try {
                val inputStream = context.assets.open(assetName)
                val destFile = java.io.File(destPath)
                val outputStream = java.io.FileOutputStream(destFile)

                inputStream.copyTo(outputStream)
                inputStream.close()
                outputStream.close()

                destFile.setExecutable(true, false)
                true
            } catch (e: Exception) {
                false
            }
        }

        fun isRunning(): Boolean {
            val result = execCommand("pgrep -f -- --mcp", isRoot = true)
            return result.isSuccess && result.successMsg.trim().isNotEmpty()
        }

        fun start(context: android.content.Context): Boolean {
            if (!ensureBinary(context)) {
                return false
            }
            val edbgPath = getEdbgPath(context)
            val result = execCommand("$edbgPath --mcp &", isRoot = true)
            return result.isSuccess
        }

        fun stop(): Boolean {
            val result = execCommand("pkill -f '.*--mcp'", isRoot = true)
            return result.isSuccess
        }

        fun getPort(): Int = EDBG_PORT

        fun getLocalhostUrl(): String = "http://127.0.0.1:$EDBG_PORT/mcp"

        fun getWifiUrl(wifiIp: String): String = "http://$wifiIp:$EDBG_PORT/mcp"
    }
}