package com.leadaxe.lxbox.android

import android.util.Log
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.URI
import java.util.concurrent.atomic.AtomicBoolean

/** Loopback-only SSO callback listener for OpenConnect browser challenges. */
class OpenConnectCallbackServer(
    val tag: String,
    val challengeId: String,
    private val port: Int,
    private val prefixes: List<String>,
    private val onUrl: (String) -> Unit,
) {
    companion object {
        private const val TAG = "LxBoxOpenConnect"
        private const val READ_TIMEOUT_MS = 5000
        private const val PAGE = "<!doctype html><html><head><meta charset=\"utf-8\"><title>Sign-in complete</title></head><body><h2>Sign-in complete</h2><p>You can return to LxBox.</p></body></html>"

        fun match(port: Int, prefixes: List<String>, requestUri: String): String? {
            val defaultUrl = "http://127.0.0.1:$port$requestUri"
            if (prefixes.isEmpty()) return defaultUrl.takeUnless { requestUri.startsWith("/favicon.ico") }
            for (prefixValue in prefixes) {
                val prefix = prefixValue.trim()
                if (defaultUrl.startsWith(prefix)) return defaultUrl
                val host = runCatching { URI(prefix).host }.getOrNull()
                    ?: prefix.removePrefix("http://").substringBefore(':').substringBefore('/')
                if (host.isNotEmpty()) {
                    val candidate = "http://$host:$port$requestUri"
                    if (candidate.startsWith(prefix)) return candidate
                }
            }
            return null
        }
    }

    private val closed = AtomicBoolean(false)
    private val delivered = AtomicBoolean(false)
    @Volatile private var server: ServerSocket? = null

    fun start(): String? {
        val socket = try {
            ServerSocket().apply {
                reuseAddress = true
                bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), port), 8)
            }
        } catch (t: Throwable) {
            return t.message ?: t.javaClass.simpleName
        }
        server = socket
        Thread({ acceptLoop(socket) }, "lxbox-oc-$port").apply { isDaemon = true }.start()
        return null
    }

    private fun acceptLoop(socket: ServerSocket) {
        while (!closed.get()) {
            val client: Socket
            try {
                client = socket.accept()
            } catch (_: SocketException) {
                return
            } catch (t: Throwable) {
                Log.w(TAG, "accept failed", t)
                return
            }
            try {
                handle(client)
            } catch (t: Throwable) {
                Log.w(TAG, "callback request failed", t)
            } finally {
                runCatching { client.close() }
            }
        }
    }

    private fun handle(client: Socket) {
        client.soTimeout = READ_TIMEOUT_MS
        val reader = BufferedReader(InputStreamReader(client.getInputStream(), Charsets.ISO_8859_1))
        val request = reader.readLine() ?: return
        while (true) { val line = reader.readLine() ?: break; if (line.isEmpty()) break }
        val uri = request.split(' ').getOrNull(1).orEmpty()
        val callbackUrl = if (uri.startsWith('/')) match(port, prefixes, uri) else null
        val output = client.getOutputStream()
        if (callbackUrl == null) {
            output.write("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
        } else {
            val body = PAGE.toByteArray(Charsets.UTF_8)
            output.write(("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nCache-Control: no-store\r\nContent-Length: ${body.size}\r\nConnection: close\r\n\r\n").toByteArray())
            output.write(body)
            if (delivered.compareAndSet(false, true)) onUrl(callbackUrl)
        }
        output.flush()
    }

    fun close() {
        if (!closed.compareAndSet(false, true)) return
        runCatching { server?.close() }
        server = null
    }
}
