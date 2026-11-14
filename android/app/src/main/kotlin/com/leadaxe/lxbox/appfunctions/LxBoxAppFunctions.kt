package com.leadaxe.lxbox.appfunctions

import android.net.VpnService
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.appfunctions.AppFunctionDeclaration
import androidx.appfunctions.AppFunctionDisabledException
import androidx.appfunctions.AppFunctionElementNotFoundException
import androidx.appfunctions.AppFunctionPermissionRequiredException
import androidx.appfunctions.AppFunctionService
import androidx.appfunctions.AppFunctionServiceEntryPoint
import androidx.appfunctions.AppFunctionSerializable
import com.leadaxe.lxbox.android.BoxVpnService
import com.leadaxe.lxbox.android.LxBoxApplication
import com.leadaxe.lxbox.android.NativeBridge
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull

@RequiresApi(36)
@AppFunctionServiceEntryPoint(serviceName = "LxBoxAppFunctionService", appFunctionXmlFileName = "lxbox_app_functions")
abstract class LxBoxAppFunctions : AppFunctionService() {
    @AppFunctionDeclaration(isDescribedByKDoc = true, isEnabled = false)
    suspend fun startVpn(): VpnState {
        ensureEnabled()
        if (VpnService.prepare(applicationContext) != null) {
            throw AppFunctionPermissionRequiredException("VPN consent is required; open LxBox and connect once")
        }
        val result = NativeBridge.appCall("vpn.start")
        waitForStatus("started")
        return VpnState(result.optJSONObject("data")?.optString("state", "started") ?: "started")
    }

    @AppFunctionDeclaration(isDescribedByKDoc = true, isEnabled = false)
    suspend fun stopVpn(): VpnState {
        ensureEnabled()
        NativeBridge.appCall("vpn.stop")
        waitForStatus("stopped")
        return VpnState("stopped")
    }

    @AppFunctionDeclaration(isDescribedByKDoc = true, isEnabled = false)
    suspend fun getVpnStatus(): VpnState {
        ensureEnabled()
        val result = NativeBridge.appCall("vpn.status")
        return VpnState(result.optJSONObject("data")?.optString("state", "stopped") ?: "stopped")
    }

    private fun ensureEnabled() {
        if (!LxBoxApplication.prefs.getBoolean("appfunctions_enabled", false)) {
            throw AppFunctionDisabledException("AI assistant control is disabled")
        }
    }

    private suspend fun waitForStatus(target: String) {
        var seenTransition = false
        withTimeoutOrNull(15_000) {
            while (true) {
                val status = BoxVpnService.status
                if (status == target) break
                if (status == "starting" || status == "stopping") seenTransition = true
                if (seenTransition && status != "starting" && status != "stopping") break
                delay(200)
            }
        }
    }
}

@AppFunctionSerializable(isDescribedByKDoc = true)
data class VpnState(val status: String)
