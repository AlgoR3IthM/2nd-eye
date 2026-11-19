package com.algor3ithm.scutulbunicii.web

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build

/** One scam result handed over to the alert layer. No message text, ever. */
data class Alert(
    val service: String, val sender: String, val verdict: String,
    val labelRo: String, val warningRo: String, val riskScore: Int, val alertId: String,
)

/** Implement this (inside the same APK after the merge) to receive every SCAM / SUSPICIOUS result. */
fun interface AlertListener { fun onAlert(alert: Alert) }

/**
 * The ONE class that hands results to the alert layer (the teammate's full-screen alert replaces the fallback).
 *  1. broadcast `com.algor3ithm.scamshield.ALERT` (extras documented in README, "For the alert teammate")
 *  2. in-app [listener] callback
 *  3. minimal fallback notification, behind [FALLBACK_NOTIFICATION]: delete at merge time.
 */
object AlertDispatcher {
    const val ACTION = "com.algor3ithm.scamshield.ALERT"
    /** Fallback so the demo shows something before the merge. Set to false (or delete the fallback code) at merge time. */
    const val FALLBACK_NOTIFICATION = true

    const val CHANNEL_ALERT = "alerts"
    const val CHANNEL_WATCH = "watch"

    @Volatile var listener: AlertListener? = null

    fun ensureChannels(ctx: Context) {
        val nm = ctx.getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ALERT, "Alerte de înșelăciune", NotificationManager.IMPORTANCE_HIGH).apply {
                enableVibration(true)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
        )
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_WATCH, "2nd Eye în fundal", NotificationManager.IMPORTANCE_LOW).apply {
                setShowBadge(false)
            }
        )
    }

    fun dispatch(ctx: Context, alert: Alert) {
        if (alert.verdict != "SCAM" && alert.verdict != "SUSPICIOUS") return
        try {
            ctx.sendBroadcast(
                Intent(ACTION)
                    .putExtra("service", alert.service).putExtra("sender", alert.sender)
                    .putExtra("verdict", alert.verdict).putExtra("label_ro", alert.labelRo)
                    .putExtra("warning_ro", alert.warningRo).putExtra("risk_score", alert.riskScore)
                    .putExtra("alert_id", alert.alertId)
            )
        } catch (_: Exception) { }
        try { listener?.onAlert(alert) } catch (_: Exception) { }
        if (FALLBACK_NOTIFICATION) fallback(ctx, alert)
    }

    private fun fallback(ctx: Context, alert: Alert) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ctx.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return
        ensureChannels(ctx)
        val title = alert.labelRo.ifBlank {
            if (alert.verdict == "SCAM") "Pare o țeapă! Nu răspundeți" else "Atenție, verificați înainte să răspundeți"
        }
        val open = PendingIntent.getActivity(
            ctx, 0, Intent(ctx, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val n = Notification.Builder(ctx, CHANNEL_ALERT)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle(title)
            .setContentText(alert.warningRo)
            .setStyle(Notification.BigTextStyle().bigText(alert.warningRo))
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setVisibility(Notification.VISIBILITY_PUBLIC)
            .setAutoCancel(true)
            .setContentIntent(open)
            .build()
        ctx.getSystemService(NotificationManager::class.java).notify(0x5C00 + (alert.alertId.hashCode() and 0xFFFF), n)
    }
}
