package net.rec0de.alloyparser.camera

import net.rec0de.alloyparser.*
import net.rec0de.alloyparser.bitmage.*
import net.rec0de.alloyparser.health.PBParsable

abstract class CameraRequest {
    companion object {
        fun parse(bytes: ByteArray) : CameraRequest? {
            val type = UInt.fromBytes(bytes.sliceArray(0 until 2), ByteOrder.LITTLE).toInt()
            val pb = ProtobufParser().parse(bytes.fromIndex(3))

            // from NCCompanionCamera::init in companioncamerad
            return when(type) {
                0x01 -> OpenCameraRequest.fromSafePB(pb)
                0x02 -> PressShutterRequest.fromSafePB(pb)
                0x04 -> SetCaptureModeRequest.fromSafePB(pb)
                0x05 -> StartCaptureRequest.fromSafePB(pb)
                0x06 -> StopCaptureRequest.fromSafePB(pb)
                0x07 -> SetFocusPointRequest.fromSafePB(pb)
                0x08 -> CameraOpenStateChangeRequest.fromSafePB(pb)
                0x09 -> UpdateThumbnailRequest.fromSafePB(pb)
                0x0a -> CameraStateChangedRequest.fromSafePB(pb)
                0x0d -> SetZoomRequest.fromSafePB(pb)
                0x0e -> SetFlashModeRequest.fromSafePB(pb)
                0x10 -> SetHDRModeRequest.fromSafePB(pb)
                0x11 -> SetIrisModeRequest.fromSafePB(pb)
                0x12 -> BeginBurstCaptureRequest.fromSafePB(pb)
                0x13 -> EndBurstCaptureRequest.fromSafePB(pb)
                0x14 -> SetCaptureDeviceRequest.fromSafePB(pb)
                else -> {
                    println("Unknown CompanionCamera request type $type")
                    println(pb)
                    return null
                }
            }
        }
    }
}

// all following structures from readFrom functions in corresponding classes in companioncamerad

class OpenCameraRequest(val supportedCaptureModes: List<Int>) : CameraRequest() {
    companion object : PBParsable<OpenCameraRequest>() {
        override fun fromSafePB(pb: ProtoBuf): OpenCameraRequest {
            val supportedCaptureModes = pb.readAssertedSinglet(1)
            val capModes : List<Int> = if(supportedCaptureModes is ProtoVarInt)
                    listOf(supportedCaptureModes.value.toInt())
                else if(supportedCaptureModes is ProtoLen)
                    supportedCaptureModes.value.toList().chunked(4).map { Int.fromBytes(it.toByteArray(), ByteOrder.BIG) }
                else
                    throw Exception("Unsupported capture mode enumeration: $supportedCaptureModes")

            return OpenCameraRequest(capModes)
        }
    }

    override fun toString() = "OpenCameraRequest(cap modes: ${supportedCaptureModes.joinToString(", ")})"

}

class PressShutterRequest(val countdown: Int?) : CameraRequest() {
    companion object : PBParsable<PressShutterRequest>() {
        override fun fromSafePB(pb: ProtoBuf): PressShutterRequest {
            val countdown = pb.readOptShortVarInt(1)
            return PressShutterRequest(countdown)
        }
    }

    override fun toString() = "PressShutterRequest(countdown ${countdown}s)"
}

class BeginBurstCaptureRequest() : CameraRequest() {
    companion object : PBParsable<BeginBurstCaptureRequest>() {
        override fun fromSafePB(pb: ProtoBuf): BeginBurstCaptureRequest {
            // empty protobuf?
            return BeginBurstCaptureRequest()
        }
    }

    override fun toString() = "BeginBurstCaptureRequest"
}

class EndBurstCaptureRequest() : CameraRequest() {
    companion object : PBParsable<EndBurstCaptureRequest>() {
        override fun fromSafePB(pb: ProtoBuf): EndBurstCaptureRequest {
            // empty protobuf?
            return EndBurstCaptureRequest()
        }
    }

    override fun toString() = "EndBurstCaptureRequest"
}

class CameraOpenStateChangeRequest(val openState: Int?, val cameraState: CameraState?) : CameraRequest() {
    companion object : PBParsable<CameraOpenStateChangeRequest>() {
        override fun fromSafePB(pb: ProtoBuf): CameraOpenStateChangeRequest {
            val openState = pb.readOptShortVarInt(1)
            val internalState = CameraState.fromPB(pb.readOptPB(2))
            return CameraOpenStateChangeRequest(openState, internalState)
        }
    }

    override fun toString() = "CameraOpenStateChangeRequest(openState $openState, camState $cameraState)"
}

class CameraStateChangedRequest(val state: CameraState) : CameraRequest() {
    companion object : PBParsable<CameraStateChangedRequest>() {
        override fun fromSafePB(pb: ProtoBuf): CameraStateChangedRequest {
            val state = CameraState.fromSafePB(pb)
            return CameraStateChangedRequest(state)
        }
    }

    override fun toString() = "CameraStateChangedRequest(state $state)"
}

class SetCaptureDeviceRequest(val captureDevice: Int?) : CameraRequest() {
    companion object : PBParsable<SetCaptureDeviceRequest>() {
        override fun fromSafePB(pb: ProtoBuf): SetCaptureDeviceRequest {
            val captureDevice = pb.readOptShortVarInt(1)
            return SetCaptureDeviceRequest(captureDevice)
        }
    }

    override fun toString() = "SetCaptureDeviceRequest(device $captureDevice)"
}

class SetCaptureModeRequest(val captureMode: Int?) : CameraRequest() {
    companion object : PBParsable<SetCaptureModeRequest>() {
        override fun fromSafePB(pb: ProtoBuf): SetCaptureModeRequest {
            val captureMode = pb.readOptShortVarInt(1)
            return SetCaptureModeRequest(captureMode)
        }
    }

    override fun toString() = "SetCaptureModeRequest(mode $captureMode)"
}

class SetFlashModeRequest(val flashMode: Int?) : CameraRequest() {
    companion object : PBParsable<SetFlashModeRequest>() {
        override fun fromSafePB(pb: ProtoBuf): SetFlashModeRequest {
            val flashMode = pb.readOptShortVarInt(1)
            return SetFlashModeRequest(flashMode)
        }
    }

    override fun toString() = "SetFlashModeRequest(mode ${CameraState.flashModeToString(flashMode)})"
}

class SetFocusPointRequest(val points: List<Float>) : CameraRequest() {
    companion object : PBParsable<SetFocusPointRequest>() {
        override fun fromSafePB(pb: ProtoBuf): SetFocusPointRequest {
            val points = pb.readMulti(1).flatMap {
                val floats : List<Float> = if(it is ProtoLen) {
                    it.value.toList().chunked(4).map {
                        it.toByteArray().readFloat(ByteOrder.LITTLE)
                    }
                }
                else if(it is ProtoI32) {
                    listOf(it.asFloat())
                }
                else
                    throw Exception("Unknown focus point enumeration: $it")
                floats
            }
            return SetFocusPointRequest(points)
        }
    }

    override fun toString() = "SetFocusPointRequest(points ${points.joinToString(", ")})"
}

class SetHDRModeRequest(val hdrMode: Int?) : CameraRequest() {
    companion object : PBParsable<SetHDRModeRequest>() {
        override fun fromSafePB(pb: ProtoBuf): SetHDRModeRequest {
            val hdrMode = pb.readOptShortVarInt(1)
            return SetHDRModeRequest(hdrMode)
        }
    }

    override fun toString() = "SetHDRModeRequest(mode ${CameraState.hdrModeToString(hdrMode)})"
}

class SetIrisModeRequest(val irisMode: Int?) : CameraRequest() {
    companion object : PBParsable<SetIrisModeRequest>() {
        override fun fromSafePB(pb: ProtoBuf): SetIrisModeRequest {
            val irisMode = pb.readOptShortVarInt(1)
            return SetIrisModeRequest(irisMode)
        }
    }

    override fun toString() = "SetIrisModeRequest(live photos ${CameraState.irisModeToString(irisMode)})"
}

class SetZoomRequest(val zoomAmount: Double?) : CameraRequest() {
    companion object : PBParsable<SetZoomRequest>() {
        override fun fromSafePB(pb: ProtoBuf): SetZoomRequest {
            val zoomAmount = pb.readOptDouble(1)
            return SetZoomRequest(zoomAmount)
        }
    }

    override fun toString() = "SetZoomRequest(amount $zoomAmount)"
}

class StartCaptureRequest(val captureMode: Int?) : CameraRequest() {
    companion object : PBParsable<StartCaptureRequest>() {
        override fun fromSafePB(pb: ProtoBuf): StartCaptureRequest {
            val captureMode = pb.readOptShortVarInt(1)
            return StartCaptureRequest(captureMode)
        }
    }

    override fun toString() = "StartCaptureRequest(capMode $captureMode)"
}

class StopCaptureRequest() : CameraRequest() {
    companion object : PBParsable<StopCaptureRequest>() {
        override fun fromSafePB(pb: ProtoBuf): StopCaptureRequest {
            // empty protobuf
            return StopCaptureRequest()
        }
    }

    override fun toString() = "StopCaptureRequest()"
}

class UpdateThumbnailRequest(val jpegData: ByteArray, val captureDuration: Double?, val isVideo: Boolean?) : CameraRequest() {
    companion object : PBParsable<UpdateThumbnailRequest>() {
        override fun fromSafePB(pb: ProtoBuf): UpdateThumbnailRequest {
            val jpegData = (pb.readAssertedSinglet(1) as ProtoLen).value
            val captureDuration = pb.readOptDouble(2)
            val isVideo = pb.readOptBool(3)
            return UpdateThumbnailRequest(jpegData, captureDuration, isVideo)
        }
    }

    override fun toString() = "UpdateThumbnailRequest(isVideo? $isVideo duration $captureDuration, jpeg: ${jpegData.hex()})"
}