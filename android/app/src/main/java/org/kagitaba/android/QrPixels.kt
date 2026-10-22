package org.kagitaba.android

import android.graphics.Bitmap
import android.graphics.BitmapFactory
import java.nio.ByteBuffer

/** Both acquisition paths feed the same bounded Rust QR decoder. */
object QrPixels {
    fun encoded(bytes:ByteArray):org.json.JSONObject {
        require(bytes.size<=16*1024*1024)
        val bounds=BitmapFactory.Options().apply{inJustDecodeBounds=true}
        BitmapFactory.decodeByteArray(bytes,0,bytes.size,bounds)
        require(bounds.outWidth in 1..8192 && bounds.outHeight in 1..8192)
        var sample=1
        while(bounds.outWidth/sample>2048||bounds.outHeight/sample>2048)sample*=2
        val bitmap=BitmapFactory.decodeByteArray(bytes,0,bytes.size,BitmapFactory.Options().apply{inSampleSize=sample;inMutable=true})?:error("Image could not be decoded")
        return try{bitmap(bitmap)}finally{bitmap.eraseColor(0);bitmap.recycle()}
    }
    fun bitmap(bitmap:Bitmap):org.json.JSONObject {
        require(bitmap.width in 1..2048 && bitmap.height in 1..2048)
        val colors=IntArray(bitmap.width*bitmap.height)
        bitmap.getPixels(colors,0,bitmap.width,0,0,bitmap.width,bitmap.height)
        val gray=ByteArray(colors.size){i->val c=colors[i];(((c shr 16 and 255)*77+(c shr 8 and 255)*150+(c and 255)*29) shr 8).toByte()}
        colors.fill(0)
        return decode(bitmap.width,bitmap.height,gray)
    }
    fun plane(width:Int,height:Int,rowStride:Int,pixelStride:Int,buffer:ByteBuffer):org.json.JSONObject {
        require(width in 1..2048&&height in 1..2048&&pixelStride>0&&rowStride>=width*pixelStride)
        val start=buffer.position()
        val gray=ByteArray(width*height){i->buffer.get(start+(i/width)*rowStride+(i%width)*pixelStride)}
        return decode(width,height,gray)
    }
    private fun decode(width:Int,height:Int,gray:ByteArray):org.json.JSONObject = try {
        NativeBridge.call("qr_scan",json("width" to width,"height" to height,"pixels" to b64(gray)))
    }finally{gray.fill(0)}
}
