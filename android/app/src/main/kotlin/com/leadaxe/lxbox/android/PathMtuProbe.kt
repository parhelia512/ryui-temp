package com.leadaxe.lxbox.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.SystemClock
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import org.json.JSONObject
import java.io.FileDescriptor
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface

/** Physical-network PMTU probe used by the JSON platform boundary. */
object PathMtuProbe {
    private const val IP_MTU_DISCOVER = 10
    private const val IP_PMTUDISC_DO = 2
    private const val IP_PMTUDISC_PROBE = 3
    private const val IPV6_MTU_DISCOVER = 23
    private const val IPV6_PMTUDISC_DO = 2
    private const val IPV6_PMTUDISC_PROBE = 3
    private const val IPV6_DONTFRAG = 62
    private const val ICMP_ECHO_REQUEST = 8
    private const val ICMP_ECHO_REPLY = 0
    private const val ICMPV6_ECHO_REQUEST = 128
    private const val ICMPV6_ECHO_REPLY = 129
    private const val IPV4_HEADER = 28
    private const val IPV6_HEADER = 48

    fun network(context: Context): JSONObject {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val network = physicalNetwork(cm) ?: throw IllegalStateException("no physical network")
        val props = cm.getLinkProperties(network)
        val caps = cm.getNetworkCapabilities(network)
        val iface = props?.interfaceName.orEmpty()
        var mtu = if (Build.VERSION.SDK_INT >= 29) props?.mtu ?: 0 else 0
        if (mtu <= 0 && iface.isNotEmpty()) mtu = runCatching { NetworkInterface.getByName(iface)?.mtu ?: 0 }.getOrDefault(0)
        return JSONObject().put("iface", iface).put("transport", transport(caps)).put("mtu", mtu.coerceAtLeast(0))
    }

    fun resolve(context: Context, target: String): JSONObject {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val network = physicalNetwork(cm) ?: throw IllegalStateException("no physical network")
        val host = target.trim()
        require(host.isNotEmpty()) { "target is required" }
        val address = network.getAllByName(host).firstOrNull { it is Inet4Address }
            ?: network.getAllByName(host).firstOrNull()
            ?: throw IllegalStateException("no address for $host")
        return JSONObject().put("ip", address.hostAddress)
    }

    fun probe(context: Context, args: JSONObject): JSONObject {
        val cm = context.getSystemService(ConnectivityManager::class.java)
        val network = physicalNetwork(cm) ?: throw IllegalStateException("no physical network")
        val ip = InetAddress.getByName(args.getString("ip"))
        val size = args.getInt("size")
        val timeout = args.optInt("timeoutMs", 1000).coerceIn(1, 60_000)
        val sequence = args.optInt("sequence", args.optInt("seq", 0))
        return try {
            probeOne(network, ip, size, timeout, sequence)
        } catch (t: Throwable) {
            JSONObject().put("status", "error").put("rtt_ms", 0).put("error", t.message ?: t.javaClass.simpleName)
        }
    }

    private fun probeOne(network: Network, address: InetAddress, size: Int, timeout: Int, sequence: Int): JSONObject {
        val v6 = address is Inet6Address
        val payloadSize = size - if (v6) IPV6_HEADER else IPV4_HEADER
        if (payloadSize < 8) return result("error", error = "size too small")
        val fd = if (v6) Os.socket(OsConstants.AF_INET6, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_ICMPV6)
        else Os.socket(OsConstants.AF_INET, OsConstants.SOCK_DGRAM, OsConstants.IPPROTO_ICMP)
        try {
            BoxVpnService.live?.let { vpn ->
                ParcelFileDescriptorCompat.dup(fd).use { duplicate ->
                    if (!vpn.protect(duplicate.fd)) throw IllegalStateException("protect failed for PMTU socket")
                }
            }
            network.bindSocket(fd)
            if (v6) {
                setProbeOption(fd, OsConstants.IPPROTO_IPV6, IPV6_MTU_DISCOVER, IPV6_PMTUDISC_PROBE, IPV6_PMTUDISC_DO)
                runCatching { Os.setsockoptInt(fd, OsConstants.IPPROTO_IPV6, IPV6_DONTFRAG, 1) }
            } else {
                setProbeOption(fd, OsConstants.IPPROTO_IP, IP_MTU_DISCOVER, IP_PMTUDISC_PROBE, IP_PMTUDISC_DO)
            }
            val packet = ByteArray(payloadSize)
            packet[0] = (if (v6) ICMPV6_ECHO_REQUEST else ICMP_ECHO_REQUEST).toByte()
            val seq = sequence and 0xffff
            packet[6] = (seq shr 8).toByte()
            packet[7] = seq.toByte()
            for (i in 8 until packet.size) packet[i] = (i and 0xff).toByte()
            val started = SystemClock.elapsedRealtime()
            try {
                Os.sendto(fd, packet, 0, packet.size, 0, address, 0)
            } catch (e: ErrnoException) {
                return if (e.errno == OsConstants.EMSGSIZE) result("too_big")
                else result("error", error = e.message ?: "sendto failed")
            }
            val buffer = ByteArray(maxOf(payloadSize, 2048))
            val deadline = started + timeout
            while (true) {
                val remaining = deadline - SystemClock.elapsedRealtime()
                if (remaining <= 0) return result("timeout")
                val pollfd = StructPollfd().apply { this.fd = fd; events = OsConstants.POLLIN.toShort() }
                val count = try { Os.poll(arrayOf(pollfd), remaining.toInt()) }
                catch (e: ErrnoException) {
                    if (e.errno == OsConstants.EINTR) continue
                    return result("error", error = e.message ?: "poll failed")
                }
                if (count <= 0) return result("timeout")
                val got = try { Os.recvfrom(fd, buffer, 0, buffer.size, 0, null) }
                catch (e: ErrnoException) {
                    if (e.errno == OsConstants.EAGAIN || e.errno == OsConstants.EINTR) continue
                    return result("timeout", error = e.message ?: "recv failed")
                }
                if (got < 8) continue
                val type = buffer[0].toInt() and 0xff
                val replySeq = ((buffer[6].toInt() and 0xff) shl 8) or (buffer[7].toInt() and 0xff)
                val expected = if (v6) ICMPV6_ECHO_REPLY else ICMP_ECHO_REPLY
                if (type == expected && replySeq == seq) return result("ok", SystemClock.elapsedRealtime() - started)
            }
        } finally {
            runCatching { Os.close(fd) }
        }
    }

    private fun setProbeOption(fd: FileDescriptor, level: Int, option: Int, preferred: Int, fallback: Int) {
        try { Os.setsockoptInt(fd, level, option, preferred) }
        catch (_: ErrnoException) { Os.setsockoptInt(fd, level, option, fallback) }
    }

    private fun result(status: String, rtt: Long = 0, error: String = "") =
        JSONObject().put("status", status).put("rtt_ms", rtt.toInt()).put("error", error)

    private fun physicalNetwork(cm: ConnectivityManager): Network? {
        val active = if (Build.VERSION.SDK_INT >= 23) cm.activeNetwork else null
        if (active != null && isPhysical(cm, active)) return active
        return cm.allNetworks.firstOrNull { isPhysical(cm, it) }
    }

    private fun isPhysical(cm: ConnectivityManager, network: Network): Boolean {
        val caps = cm.getNetworkCapabilities(network) ?: return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    private fun transport(caps: NetworkCapabilities?): String = when {
        caps == null -> "other"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
        else -> "other"
    }
}

/** Keeps the fd duplication in one small Android-only helper. */
private object ParcelFileDescriptorCompat {
    fun dup(fd: FileDescriptor): android.os.ParcelFileDescriptor = android.os.ParcelFileDescriptor.dup(fd)
}
