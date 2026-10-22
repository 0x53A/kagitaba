package org.kagitaba.android

import android.content.Context
import android.content.res.ColorStateList
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.StateListDrawable
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

/** Shared roles with the native and Firefox themes; Android keeps 48dp targets. */
object WalletTheme {
    val background = Color.rgb(6, 10, 13)
    val surface = Color.rgb(11, 18, 22)
    val card = Color.rgb(17, 27, 32)
    val line = Color.rgb(52, 82, 92)
    val ink = Color.rgb(216, 230, 234)
    val muted = Color.rgb(145, 170, 178)
    val accent = Color.rgb(47, 224, 200)
    fun dp(context: Context, value: Int) = (context.resources.displayMetrics.density * value).toInt()
    fun box(context: Context, fill: Int, stroke: Int = line) = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE; setColor(fill); setStroke(dp(context, 1).coerceAtLeast(1), stroke); cornerRadius = 0f
    }
    fun button(view: Button, primary: Boolean = false) = with(view) {
        isAllCaps = false; textSize = 15f; gravity = android.view.Gravity.CENTER_VERTICAL or android.view.Gravity.START
        typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        minHeight = dp(context, 48); minimumHeight = minHeight
        setPadding(dp(context, 16), dp(context, 10), dp(context, 16), dp(context, 10))
        backgroundTintList = null
        background = StateListDrawable().apply {
            addState(intArrayOf(-android.R.attr.state_enabled), box(context, card))
            addState(intArrayOf(android.R.attr.state_pressed), box(context, line, accent))
            addState(intArrayOf(android.R.attr.state_focused), box(context, card, accent))
            addState(intArrayOf(android.R.attr.state_hovered), box(context, line, accent))
            addState(intArrayOf(), box(context, if (primary) accent else card, if (primary) accent else line))
        }
        setTextColor(ColorStateList(
            arrayOf(intArrayOf(-android.R.attr.state_enabled), intArrayOf(android.R.attr.state_pressed), intArrayOf(android.R.attr.state_focused), intArrayOf(android.R.attr.state_hovered), intArrayOf()),
            intArrayOf(muted, ink, ink, ink, if (primary) WalletTheme.background else ink)))
        elevation = 0f; stateListAnimator = null
        layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, LinearLayout.LayoutParams.WRAP_CONTENT).apply { topMargin = dp(context, 8) }
    }
    fun caption(view: TextView) = with(view) {
        typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        textSize = 13f; setTextColor(muted)
        setPadding(0, dp(context, 14), 0, dp(context, 6))
    }
    fun heading(view: TextView, size: Float = 19f) = with(view) {
        typeface = Typeface.create("sans-serif-medium", Typeface.NORMAL)
        textSize = size; setTextColor(ink)
    }
    fun persistentScrollbar(view: android.view.View) = with(view) {
        // Programmatically enabling scrolling alone can leave Android's internal
        // ScrollBarDrawable null (notably EditText with a no-scrollbar theme).
        // Set a thumb first to initialize it before disabling fading.
        verticalScrollbarThumbDrawable = android.graphics.drawable.ColorDrawable(muted)
        isVerticalScrollBarEnabled = true; isScrollbarFadingEnabled = false
        scrollBarStyle = android.view.View.SCROLLBARS_INSIDE_INSET
    }
    fun dataFont(context: Context): Typeface = Typeface.createFromAsset(context.assets, "fonts/DejaVuSansMono.ttf")
    fun field(view: EditText) = with(view) {
        typeface = dataFont(context); fontFeatureSettings = "liga=0,calt=0"
        textSize = 16f; setTextColor(ink); setHintTextColor(muted)
        if (!isSingleLine) persistentScrollbar(this)
        backgroundTintList = null
        background = StateListDrawable().apply {
            addState(intArrayOf(android.R.attr.state_focused), box(context, WalletTheme.background, accent))
            addState(intArrayOf(), box(context, WalletTheme.background))
        }
        minHeight = dp(context, 48)
        setPadding(dp(context, 12), dp(context, 12), dp(context, 12), dp(context, 12))
    }
}
