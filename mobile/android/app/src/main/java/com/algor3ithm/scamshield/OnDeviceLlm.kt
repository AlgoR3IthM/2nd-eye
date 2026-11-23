package com.algor3ithm.scamshield

object OnDeviceLlm {
    init {
        System.loadLibrary("scamshield_llm")
    }

    external fun initModel(modelPath: String): Boolean
    external fun generateJson(prompt: String): String
}