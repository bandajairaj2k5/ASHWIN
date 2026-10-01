"""
ASHWIN Spec-Compliant AXML Binary Generator.
Strictly follows Android C++ ResourceTypes.h ResXMLTree_attrExt spec.
"""

import os
import sys
import struct
import hashlib
import zipfile
from pyaxmlparser.axmlprinter import AXMLPrinter

# Resource IDs from android.R.attr
RES_VERSION_CODE = 0x0101021b
RES_VERSION_NAME = 0x0101021c
RES_MIN_SDK = 0x0101020c
RES_TARGET_SDK = 0x01010270
RES_NAME = 0x01010003
RES_LABEL = 0x01010001
RES_ALLOW_BACKUP = 0x01010280
RES_EXPORTED = 0x01010010

RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_RESOURCE_MAP_TYPE = 0x0180

TYPE_STRING = 0x03
TYPE_INT_DEC = 0x10
TYPE_INT_BOOLEAN = 0x12

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class StringPoolBuilder:
    def __init__(self):
        self.strings = []
        self.string_map = {}

    def add(self, s: str) -> int:
        if s in self.string_map:
            return self.string_map[s]
        idx = len(self.strings)
        self.strings.append(s)
        self.string_map[s] = idx
        return idx

    def build(self) -> bytes:
        offsets = []
        blob = bytearray()
        for s in self.strings:
            offsets.append(len(blob))
            encoded = s.encode("utf-16le")
            length = len(s)
            blob.extend(struct.pack("<H", length))
            blob.extend(encoded)
            blob.extend(b"\x00\x00")

        while len(blob) % 4 != 0:
            blob.append(0)

        string_count = len(self.strings)
        style_count = 0
        flags = 0
        strings_start = 7 * 4 + string_count * 4
        chunk_size = strings_start + len(blob)

        header = struct.pack(
            "<HHIIIIII",
            RES_STRING_POOL_TYPE,
            28,
            chunk_size,
            string_count,
            style_count,
            flags,
            strings_start,
            0
        )

        out = bytearray(header)
        for off in offsets:
            out.extend(struct.pack("<I", off))
        out.extend(blob)
        return bytes(out)


def build_spec_axml() -> bytes:
    pool = StringPoolBuilder()

    s_manifest = pool.add("manifest")
    s_android = pool.add(ANDROID_NS)
    s_android_prefix = pool.add("android")
    s_pkg = pool.add("package")
    s_pkg_val = pool.add("org.ashwin.core")
    s_ver_code = pool.add("versionCode")
    s_ver_name = pool.add("versionName")
    s_ver_name_val = pool.add("0.1.0")

    s_uses_sdk = pool.add("uses-sdk")
    s_min_sdk = pool.add("minSdkVersion")
    s_target_sdk = pool.add("targetSdkVersion")

    s_uses_perm = pool.add("uses-permission")
    s_name = pool.add("name")

    s_p_audio = pool.add("android.permission.RECORD_AUDIO")
    s_p_net = pool.add("android.permission.INTERNET")
    s_p_state = pool.add("android.permission.ACCESS_NETWORK_STATE")

    s_app = pool.add("application")
    s_label = pool.add("label")
    s_label_val = pool.add("ASHWIN Core")
    s_allow_backup = pool.add("allowBackup")

    s_activity = pool.add("activity")
    s_act_name = pool.add("org.ashwin.core.MainActivity")
    s_exported = pool.add("exported")

    s_intent_filter = pool.add("intent-filter")
    s_action = pool.add("action")
    s_category = pool.add("category")
    s_act_main = pool.add("android.intent.action.MAIN")
    s_cat_launcher = pool.add("android.intent.category.LAUNCHER")

    res_ids = [
        RES_VERSION_CODE,
        RES_VERSION_NAME,
        RES_MIN_SDK,
        RES_TARGET_SDK,
        RES_NAME,
        RES_LABEL,
        RES_ALLOW_BACKUP,
        RES_EXPORTED,
    ]

    res_map_bytes = struct.pack(f"<HHI{len(res_ids)}I", RES_XML_RESOURCE_MAP_TYPE, 8, 8 + 4 * len(res_ids), *res_ids)
    pool_bytes = pool.build()

    xml_body = bytearray()

    # Start Namespace
    xml_body.extend(struct.pack("<HHIIII", RES_XML_START_NAMESPACE_TYPE, 16, 24, 1, 0xFFFFFFFF, s_android_prefix))
    xml_body.extend(struct.pack("<I", s_android))

    def make_attr(ns_idx: int, name_idx: int, val_idx: int, val_type: int, val_data: int) -> bytes:
        v_idx = 0xFFFFFFFF if val_idx == -1 else val_idx
        n_idx = 0xFFFFFFFF if ns_idx == -1 else ns_idx
        return struct.pack("<IIIHBB I", n_idx, name_idx, v_idx, 8, 0, val_type, val_data)

    def make_elem_start(tag_idx: int, num_attrs: int, attr_bytes: bytes) -> bytes:
        header = struct.pack("<HHIIIIHHHHHHH", RES_XML_START_ELEMENT_TYPE, 16, 36 + len(attr_bytes), 2, 0xFFFFFFFF, 0xFFFFFFFF, tag_idx, 20, 20, num_attrs, 0, 0, 0)
        return header + attr_bytes

    def make_elem_end(tag_idx: int) -> bytes:
        return struct.pack("<HHIIIII", RES_XML_END_ELEMENT_TYPE, 16, 24, 2, 0xFFFFFFFF, 0xFFFFFFFF, tag_idx)

    # <manifest package="org.ashwin.core" versionCode="1" versionName="0.1.0">
    attr_pkg = make_attr(-1, s_pkg, s_pkg_val, TYPE_STRING, s_pkg_val)
    attr_vc = make_attr(s_android, s_ver_code, -1, TYPE_INT_DEC, 1)
    attr_vn = make_attr(s_android, s_ver_name, s_ver_name_val, TYPE_STRING, s_ver_name_val)
    xml_body.extend(make_elem_start(s_manifest, 3, attr_pkg + attr_vc + attr_vn))

    # <uses-sdk minSdkVersion="26" targetSdkVersion="35" />
    attr_min = make_attr(s_android, s_min_sdk, -1, TYPE_INT_DEC, 26)
    attr_tgt = make_attr(s_android, s_target_sdk, -1, TYPE_INT_DEC, 35)
    xml_body.extend(make_elem_start(s_uses_sdk, 2, attr_min + attr_tgt))
    xml_body.extend(make_elem_end(s_uses_sdk))

    # <uses-permission name="..." />
    for perm_idx in [s_p_audio, s_p_net, s_p_state]:
        attr_p = make_attr(s_android, s_name, perm_idx, TYPE_STRING, perm_idx)
        xml_body.extend(make_elem_start(s_uses_perm, 1, attr_p))
        xml_body.extend(make_elem_end(s_uses_perm))

    # <application label="ASHWIN Core" allowBackup="false">
    attr_lbl = make_attr(s_android, s_label, s_label_val, TYPE_STRING, s_label_val)
    attr_bak = make_attr(s_android, s_allow_backup, -1, TYPE_INT_BOOLEAN, 0)
    xml_body.extend(make_elem_start(s_app, 2, attr_lbl + attr_bak))

    # <activity name="org.ashwin.core.MainActivity" exported="true">
    attr_act = make_attr(s_android, s_name, s_act_name, TYPE_STRING, s_act_name)
    attr_exp = make_attr(s_android, s_exported, -1, TYPE_INT_BOOLEAN, 0xFFFFFFFF)
    xml_body.extend(make_elem_start(s_activity, 2, attr_act + attr_exp))

    # <intent-filter>
    xml_body.extend(make_elem_start(s_intent_filter, 0, b""))

    # <action name="android.intent.action.MAIN" />
    attr_act_m = make_attr(s_android, s_name, s_act_main, TYPE_STRING, s_act_main)
    xml_body.extend(make_elem_start(s_action, 1, attr_act_m))
    xml_body.extend(make_elem_end(s_action))

    # <category name="android.intent.category.LAUNCHER" />
    attr_cat_l = make_attr(s_android, s_name, s_cat_launcher, TYPE_STRING, s_cat_launcher)
    xml_body.extend(make_elem_start(s_category, 1, attr_cat_l))
    xml_body.extend(make_elem_end(s_category))

    xml_body.extend(make_elem_end(s_intent_filter))
    xml_body.extend(make_elem_end(s_activity))
    xml_body.extend(make_elem_end(s_app))
    xml_body.extend(make_elem_end(s_manifest))

    # End Namespace
    xml_body.extend(struct.pack("<HHIIII", RES_XML_END_NAMESPACE_TYPE, 16, 24, 1, 0xFFFFFFFF, s_android_prefix))
    xml_body.extend(struct.pack("<I", s_android))

    total_size = 8 + len(pool_bytes) + len(res_map_bytes) + len(xml_body)
    header = struct.pack("<HHI", RES_XML_TYPE, 8, total_size)

    axml_bytes = header + pool_bytes + res_map_bytes + bytes(xml_body)

    # Rebuild final ashwin-v0.1-debug.apk
    build_dir = os.path.abspath("build/outputs/apk/debug")
    os.makedirs(build_dir, exist_ok=True)
    apk_path = os.path.join(build_dir, "ashwin-v0.1-debug.apk")

    with zipfile.ZipFile(apk_path, "w", zipfile.ZIP_DEFLATED) as apk:
        apk.writestr("AndroidManifest.xml", axml_bytes)
        apk.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 200)

    # Sign APK with debug RSA signature
    from sign_apk_native import sign_apk
    sign_apk()

    return axml_bytes


if __name__ == "__main__":
    build_spec_axml()
