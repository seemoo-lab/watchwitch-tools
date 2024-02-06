package net.rec0de.alloyparser.camera

import net.rec0de.alloyparser.*
import net.rec0de.alloyparser.health.PBParsable

abstract class CameraResponse {
    companion object {
        fun parse(bytes: ByteArray) : CameraResponse? {
            val type = UInt.fromBytesLittle(bytes.sliceArray(0 until 2)).toInt()
            val pb = ProtobufParser().parse(bytes.fromIndex(2))

            // from NCCompanionCamera::init in companioncamerad
            return when(type) {
                0x01 -> OpenCameraResponse.fromSafePB(pb)
                0x02 -> PressShutterResponse.fromSafePB(pb)
                0x04 -> SetCaptureModeResponse.fromSafePB(pb)
                0x05 -> StartCaptureResponse.fromSafePB(pb)
                0x06 -> StopCaptureResponse.fromSafePB(pb)
                0x08 -> CameraOpenStateChangeResponse.fromSafePB(pb)
                0x0d -> SetZoomResponse.fromSafePB(pb)
                0x0e -> SetFlashModeResponse.fromSafePB(pb)
                0x10 -> SetHDRModeResponse.fromSafePB(pb)
                0x11 -> SetIrisModeResponse.fromSafePB(pb)
                0x12 -> BeginBurstCaptureResponse.fromSafePB(pb)
                0x13 -> EndBurstCaptureResponse.fromSafePB(pb)
                0x14 -> SetCaptureDeviceResponse.fromSafePB(pb)
                else -> {
                    println("Unknown CompanionCamera response type $type")
                    println(pb)
                    return null
                }
            }
        }
    }
}

// all following structures from readFrom functions in corresponding classes in companioncamerad

class OpenCameraResponse(val openState: Int?, val cameraState: CameraState?) : CameraResponse() {
    companion object : PBParsable<OpenCameraResponse>() {
        override fun fromSafePB(pb: ProtoBuf): OpenCameraResponse {
            val openState = pb.readOptShortVarInt(1)
            val cameraState = CameraState.fromPB(pb.readOptPB(2))

            return OpenCameraResponse(openState, cameraState)
        }
    }

    override fun toString() = "OpenCameraResponse(openState: $openState, camState: $cameraState)"

}

class PressShutterResponse(val success: Boolean?) : CameraResponse() {
    companion object : PBParsable<PressShutterResponse>() {
        override fun fromSafePB(pb: ProtoBuf): PressShutterResponse {
            val success = pb.readOptBool(1)
            return PressShutterResponse(success)
        }
    }

    override fun toString() = "PressShutterResponse(success? $success)"
}

class BeginBurstCaptureResponse(val success: Boolean?) : CameraResponse() {
    companion object : PBParsable<BeginBurstCaptureResponse>() {
        override fun fromSafePB(pb: ProtoBuf): BeginBurstCaptureResponse {
            val success = pb.readOptBool(1)
            return BeginBurstCaptureResponse(success)
        }
    }

    override fun toString() = "BeginBurstCaptureResponse(success? $success)"
}

class EndBurstCaptureResponse(val success: Boolean?, val numberOfPhotos: Int?) : CameraResponse() {
    companion object : PBParsable<EndBurstCaptureResponse>() {
        override fun fromSafePB(pb: ProtoBuf): EndBurstCaptureResponse {
            val success = pb.readOptBool(1)
            val numberOfPhotos = pb.readOptShortVarInt(2)
            return EndBurstCaptureResponse(success, numberOfPhotos)
        }
    }

    override fun toString() = "EndBurstCaptureResponse(success? $success, #pics $numberOfPhotos)"
}

class CameraOpenStateChangeResponse(val acknowledge: Boolean?) : CameraResponse() {
    companion object : PBParsable<CameraOpenStateChangeResponse>() {
        override fun fromSafePB(pb: ProtoBuf): CameraOpenStateChangeResponse {
            val acknowledge = pb.readOptBool(1)
            return CameraOpenStateChangeResponse(acknowledge)
        }
    }

    override fun toString() = "CameraOpenStateChangeResponse(ack? $acknowledge)"
}

class SetCaptureDeviceResponse(val success: Boolean?, val cameraState: CameraState?) : CameraResponse() {
    companion object : PBParsable<SetCaptureDeviceResponse>() {
        override fun fromSafePB(pb: ProtoBuf): SetCaptureDeviceResponse {
            val success = pb.readOptBool(1)
            val cameraState = CameraState.fromPB(pb.readOptPB(2))

            return SetCaptureDeviceResponse(success, cameraState)
        }
    }

    override fun toString() = "SetCaptureDeviceResponse(success? $success, camState $cameraState)"
}

class SetCaptureModeResponse(val captureMode: Int?, val success: Boolean?, val cameraState: CameraState?) : CameraResponse() {
    companion object : PBParsable<SetCaptureModeResponse>() {
        override fun fromSafePB(pb: ProtoBuf): SetCaptureModeResponse {
            val captureMode = pb.readOptShortVarInt(1)
            val success = pb.readOptBool(2)
            val cameraState = CameraState.fromPB(pb.readOptPB(3))
            return SetCaptureModeResponse(captureMode, success, cameraState)
        }
    }

    override fun toString() = "SetCaptureModeResponse(success? $success, capMode $captureMode, camState $cameraState)"
}

class SetFlashModeResponse(val flashMode: Int?) : CameraResponse() {
    companion object : PBParsable<SetFlashModeResponse>() {
        override fun fromSafePB(pb: ProtoBuf): SetFlashModeResponse {
            val flashMode = pb.readOptShortVarInt(1)
            return SetFlashModeResponse(flashMode)
        }
    }

    override fun toString() = "SetFlashModeResponse(mode ${CameraState.flashModeToString(flashMode)})"
}

class SetHDRModeResponse(val hdrMode: Int?) : CameraResponse() {
    companion object : PBParsable<SetHDRModeResponse>() {
        override fun fromSafePB(pb: ProtoBuf): SetHDRModeResponse {
            val hdrMode = pb.readOptShortVarInt(1)
            return SetHDRModeResponse(hdrMode)
        }
    }

    override fun toString() = "SetHDRModeResponse(mode ${CameraState.hdrModeToString(hdrMode)})"
}

class SetIrisModeResponse(val irisMode: Int?) : CameraResponse() {
    companion object : PBParsable<SetIrisModeResponse>() {
        override fun fromSafePB(pb: ProtoBuf): SetIrisModeResponse {
            val irisMode = pb.readOptShortVarInt(1)
            return SetIrisModeResponse(irisMode)
        }
    }

    override fun toString() = "SetIrisModeResponse(live photos ${CameraState.irisModeToString(irisMode)})"
}

class SetZoomResponse(val zoomAmount: Double?) : CameraResponse() {
    companion object : PBParsable<SetZoomResponse>() {
        override fun fromSafePB(pb: ProtoBuf): SetZoomResponse {
            val zoomAmount = pb.readOptDouble(1)
            return SetZoomResponse(zoomAmount)
        }
    }

    override fun toString() = "SetZoomResponse(amount $zoomAmount)"
}

class StartCaptureResponse(val success: Boolean?) : CameraResponse() {
    companion object : PBParsable<StartCaptureResponse>() {
        override fun fromSafePB(pb: ProtoBuf): StartCaptureResponse {
            val success = pb.readOptBool(1)
            return StartCaptureResponse(success)
        }
    }

    override fun toString() = "StartCaptureResponse(success? $success)"
}

class StopCaptureResponse(val success: Boolean?) : CameraResponse() {
    companion object : PBParsable<StopCaptureResponse>() {
        override fun fromSafePB(pb: ProtoBuf): StopCaptureResponse {
            val success = pb.readOptBool(1)
            return StopCaptureResponse(success)
        }
    }

    override fun toString() = "StopCaptureResponse(success? $success)"
}