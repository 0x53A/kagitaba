package org.kagitaba.android

import android.annotation.SuppressLint
import android.graphics.ImageFormat
import android.graphics.SurfaceTexture
import android.hardware.camera2.*
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import android.view.Surface
import android.view.TextureView
import android.widget.LinearLayout
import androidx.fragment.app.FragmentActivity

/** Local camera frames only. No camera intent, gallery write or network decoder. */
class QrCamera(private val activity:FragmentActivity,private val panel:LinearLayout,private val found:(org.json.JSONObject)->Unit,private val failed:()->Unit) {
    private val thread=HandlerThread("kagitaba-qr").apply{start()}
    private val handler=Handler(thread.looper)
    private val preview=TextureView(activity).apply { contentDescription="Camera preview";importantForAccessibility=android.view.View.IMPORTANT_FOR_ACCESSIBILITY_YES }
    @Volatile private var closed=false
    private var device:CameraDevice?=null
    private var session:CameraCaptureSession?=null
    private var reader:ImageReader?=null
    private var surface:Surface?=null
    fun start(){panel.addView(preview,LinearLayout.LayoutParams(-1,WalletTheme.dp(activity,240)));preview.surfaceTextureListener=object:TextureView.SurfaceTextureListener{
        override fun onSurfaceTextureAvailable(texture:SurfaceTexture,width:Int,height:Int){open(texture)}
        override fun onSurfaceTextureSizeChanged(texture:SurfaceTexture,width:Int,height:Int){}
        override fun onSurfaceTextureUpdated(texture:SurfaceTexture){}
        override fun onSurfaceTextureDestroyed(texture:SurfaceTexture):Boolean{close();return true}
    }}
    @SuppressLint("MissingPermission")
    @Suppress("DEPRECATION")
    private fun open(texture:SurfaceTexture){
        try{
            val manager=activity.getSystemService(CameraManager::class.java)
            val id=manager.cameraIdList.firstOrNull{manager.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING)==CameraCharacteristics.LENS_FACING_BACK}?:manager.cameraIdList.first()
            val map=manager.getCameraCharacteristics(id).get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)!!
            val size=map.getOutputSizes(ImageFormat.YUV_420_888).filter{it.width<=2048&&it.height<=2048}.minByOrNull{kotlin.math.abs(it.width*it.height-1280*720)}?:error("Size")
            texture.setDefaultBufferSize(size.width,size.height);surface=Surface(texture)
            val images=ImageReader.newInstance(size.width,size.height,ImageFormat.YUV_420_888,2);reader=images
            var last=0L
            images.setOnImageAvailableListener({source->
                val image=runCatching{source.acquireLatestImage()}.getOrNull()?:return@setOnImageAvailableListener
                image.use {
                    if(closed||android.os.SystemClock.elapsedRealtime()-last<500)return@setOnImageAvailableListener
                    last=android.os.SystemClock.elapsedRealtime();val plane=it.planes[0];val buffer=plane.buffer
                    try{val result=QrPixels.plane(it.width,it.height,plane.rowStride,plane.pixelStride,buffer);activity.runOnUiThread{if(!closed)found(result)}}catch(_:Exception){/* Keep scanning. */}
                }
            },handler)
            manager.openCamera(id,object:CameraDevice.StateCallback(){
                override fun onOpened(camera:CameraDevice){if(closed){camera.close();return};device=camera
                    try{camera.createCaptureSession(listOf(surface!!,images.surface),object:CameraCaptureSession.StateCallback(){
                        override fun onConfigured(capture:CameraCaptureSession){if(closed){capture.close();return};session=capture
                            try{val request=camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply{addTarget(surface!!);addTarget(images.surface);set(CaptureRequest.CONTROL_AF_MODE,CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)}.build();capture.setRepeatingRequest(request,null,handler)}catch(_:Exception){error()}}
                        override fun onConfigureFailed(capture:CameraCaptureSession){error()}
                    },handler)}catch(_:Exception){error()}}
                override fun onDisconnected(camera:CameraDevice){camera.close();error()}
                override fun onError(camera:CameraDevice,error:Int){camera.close();error()}
            },handler)
        }catch(_:Exception){error()}
    }
    private fun error(){activity.runOnUiThread{if(!closed){failed();close()}}}
    fun close(){if(closed)return;closed=true;preview.surfaceTextureListener=null;panel.removeView(preview);handler.post{session?.close();device?.close();reader?.close();surface?.release();thread.quitSafely()}}
}
