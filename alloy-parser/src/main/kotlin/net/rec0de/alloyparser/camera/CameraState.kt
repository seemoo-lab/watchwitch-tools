package net.rec0de.alloyparser.camera

import net.rec0de.alloyparser.*
import net.rec0de.alloyparser.bitmage.ByteOrder
import net.rec0de.alloyparser.bitmage.fromBytes
import net.rec0de.alloyparser.health.PBParsable
import java.nio.ByteBuffer
import java.util.*

class CameraState(
    val orientation: Int?,
    val zoomAmount: Float?,
    val flashSupport: Int?,
    val flashMode: Int?,
    val hdrSupport: Int?,
    val hdrMode: Int?,
    val irisSupport: Int?,
    val irisMode: Int?,
    val burstSupport: Int?,
    val captureMode: Int?,
    val toggleCameraDeviceSuppport: Int?,
    val zoomSupport: Boolean?,
    val supportedCaptureModes: List<Int>,
    val capturing: Boolean?,
    val captureStartDate: Date?,
    val showingLivePreview: Boolean?,
    val shallowDepthOfFieldStatus: Int?,
    val supportsMomentCapture: Boolean?,
    val supportedCaptureDevices: List<Int>,
    val captureDevice: Int?

) {
    companion object : PBParsable<CameraState>() {
        override fun fromSafePB(pb: ProtoBuf): CameraState {
            val orientation = pb.readOptShortVarInt(1)
            val zoomAmount = pb.readOptFloat(3)
            val flashSupport = pb.readOptShortVarInt(4)
            val flashMode = pb.readOptShortVarInt(5)
            val hdrSupport = pb.readOptShortVarInt(6)
            val hdrMode = pb.readOptShortVarInt(7)
            val irisSupport = pb.readOptShortVarInt(8)
            val irisMode = pb.readOptShortVarInt(9)
            val burstSupport = pb.readOptShortVarInt(10)
            val captureMode = pb.readOptShortVarInt(11)
            val toggleCameraDeviceSuppport = pb.readOptShortVarInt(12)
            val zoomSupport = pb.readOptBool(13)

            val supportedCaptureModes = pb.readMulti(14).flatMap {
                val capModes : List<Int> = if(it is ProtoLen) {
                    it.value.toList().chunked(4).map {
                        Int.fromBytes(it.toByteArray(), ByteOrder.BIG)
                    }
                }
                else if(it is ProtoVarInt) {
                    listOf(it.value.toInt())
                }
                else
                    throw Exception("Unknown capture mode enumeration: $it")
                capModes
            }

            val capturing = pb.readOptBool(15)
            val captureStartDate = pb.readOptDate(16)
            val showingLivePreview = pb.readOptBool(17)
            val shallowDepthOfFieldStatus = pb.readOptShortVarInt(18)
            val supportsMomentCapture = pb.readOptBool(19)

            val supportedCaptureDevices = pb.readMulti(20).flatMap {
                val capDevices : List<Int> = if(it is ProtoLen) {
                    it.value.toList().chunked(4).map {
                        Int.fromBytes(it.toByteArray(), ByteOrder.BIG)
                    }
                }
                else if(it is ProtoVarInt) {
                    listOf(it.value.toInt())
                }
                else
                    throw Exception("Unknown capture device enumeration: $it")
                capDevices
            }

            val captureDevice = pb.readOptShortVarInt(21)

            return CameraState(orientation, zoomAmount, flashSupport, flashMode, hdrSupport, hdrMode, irisSupport, irisMode, burstSupport, captureMode, toggleCameraDeviceSuppport, zoomSupport, supportedCaptureModes, capturing, captureStartDate, showingLivePreview, shallowDepthOfFieldStatus, supportsMomentCapture, supportedCaptureDevices, captureDevice)
        }

        private fun triStateModeToString(mode: Int?) = when(mode) {
            null -> "<null>"
            0 -> "off"
            1 -> "on"
            2 -> "auto"
            else -> throw Exception("Unsupported mode: $mode")
        }

        fun hdrModeToString(mode: Int?) = triStateModeToString(mode)
        fun flashModeToString(mode: Int?) = triStateModeToString(mode)
        fun irisModeToString(mode: Int?) = triStateModeToString(mode)

    }

    override fun toString(): String {
        var str = "CameraState("

        if(orientation != null)
            str += " orientation: $orientation"
        if(zoomAmount != null)
            str += " zoomAmount: $zoomAmount"
        if(flashSupport != null)
            str += " flashSupport: $flashSupport"
        if(flashMode != null)
            str += " flash: ${flashModeToString(flashMode)}"
        if(hdrSupport != null)
            str += " hdrSupport: $hdrSupport"
        if(hdrMode != null)
            str += " hdr: ${hdrModeToString(hdrMode)}"
        if(irisSupport != null)
            str += " livePicSupport: $irisSupport"
        if(irisMode != null)
            str += " livePics: ${irisModeToString(irisMode)}"
        if(burstSupport != null)
            str += " burstSupport: $burstSupport"
        if(captureMode != null)
            str += " captureMode: $captureMode"
        if(supportedCaptureModes.isNotEmpty())
            str += " supportedCapModes: ${supportedCaptureModes.joinToString(", ")}"
        if(toggleCameraDeviceSuppport != null)
            str += " toggleCameraSupport: $toggleCameraDeviceSuppport"
        if(zoomSupport != null)
            str += " zoomSupport: $zoomSupport"
        if(capturing != null)
            str += " capturing? $capturing"
        if(captureStartDate != null)
            str += " capture start: $captureStartDate"
        if(showingLivePreview != null)
            str += " livePreview? $showingLivePreview"
        if(shallowDepthOfFieldStatus != null)
            str += " shallowDoFStatus: $shallowDepthOfFieldStatus"
        if(supportsMomentCapture != null)
            str += " momentSupport? $supportsMomentCapture"
        if(captureDevice != null)
            str += " captureDevice: $captureDevice"
        if(supportedCaptureDevices.isNotEmpty())
            str += " supportedCaptureDevices: ${supportedCaptureDevices.joinToString(", ")}"


        str += ")"
        return str
    }

}