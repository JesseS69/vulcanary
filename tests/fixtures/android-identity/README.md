# Android identity fixtures

Synthetic source manifest, compiled on 2026-11-13 using Android SDK Build Tools
36.0.0, AAPT2 **2.20-13193326**, android-36 platform jar. Both outputs are pinned
in test_android_identity.py and marked binary for Windows checkout safety.
No target app, source secrets or private paths are included.

From repository root (substitute SDK paths):

```text
aapt2 link -I <android-36/android.jar> --manifest tests/fixtures/android-identity/AndroidManifest.xml -o binary.apk
aapt2 link --proto-format -I <android-36/android.jar> --manifest tests/fixtures/android-identity/AndroidManifest.xml -o proto.apk
```

Save each archive's AndroidManifest.xml as manifest.bin and manifest.pb,
respectively. Test archives are synthetic layouts assembled around these genuine
compiler outputs. No signing, installability or full bundle validity is implied.
CI reads the committed bytes without requiring or launching AAPT2.
