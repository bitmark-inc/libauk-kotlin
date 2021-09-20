package com.bitmark.libauk.util

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

inline fun <reified T> Gson.fromJson(json: String): T =
    this.fromJson(json, object : TypeToken<T>() {}.type)

fun newGsonInstance(): Gson =
    Gson().newBuilder().disableHtmlEscaping().excludeFieldsWithoutExposeAnnotation().create()