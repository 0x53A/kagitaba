package org.kagitaba.android

import android.graphics.Bitmap
import android.graphics.Canvas
import android.view.View
import android.widget.EditText
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test

/** Synthetic views only: no wallet, activity, PIN or hardware access. */
class ScrollbarTest {
    @Test fun multilineEditorDrawsWithAndWithoutOverflow() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        instrumentation.runOnMainSync {
            val context = instrumentation.targetContext
            val field = EditText(context).apply {
                layoutParams = android.view.ViewGroup.LayoutParams(400, 160)
                setSingleLine(false)
                WalletTheme.field(this)
            }
            assertNotNull(field.verticalScrollbarThumbDrawable)
            assertFalse(field.isScrollbarFadingEnabled)
            val bitmap = Bitmap.createBitmap(400, 160, Bitmap.Config.ARGB_8888)
            try {
                for (overflow in listOf(false, true, false)) {
                    field.setText(if (overflow) (1..50).joinToString("\n") { "Synthetic line" } else "Short")
                    field.measure(View.MeasureSpec.makeMeasureSpec(400, View.MeasureSpec.EXACTLY),
                        View.MeasureSpec.makeMeasureSpec(160, View.MeasureSpec.EXACTLY))
                    field.layout(0, 0, 400, 160)
                    field.scrollTo(0, 0)
                    field.draw(Canvas(bitmap))
                    assertEquals(overflow, field.canScrollVertically(1))
                }
            } finally { bitmap.recycle() }
        }
    }
}
