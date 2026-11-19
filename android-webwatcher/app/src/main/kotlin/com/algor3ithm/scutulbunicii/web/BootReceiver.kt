package com.algor3ithm.scutulbunicii.web

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent

/** Starts the watcher again after a reboot or an app update, but only when she switched it on. */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val a = intent.action
        if (a != Intent.ACTION_BOOT_COMPLETED && a != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (!Prefs(context).background) return
        try { WatchService.start(context) } catch (_: Exception) { }
    }
}
