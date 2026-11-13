# Independently compiled protobuf XML fixture

The adjacent manifest and resources are synthetic test inputs. `compiled/`
contains their AAPT2 outputs, generated 2026-11-12 with Android SDK Build Tools
36.0.0, `aapt2 version`: **2.20-13193326**, using the android-36 platform jar.
No target app, credentials or private artifact is included. The test pins all
four output digests and packages these bytes under the AAB base layout.

Reproduction from the repository root (substitute SDK paths):

```text
aapt2 compile --dir tests/fixtures/aab/res -o resources.zip
aapt2 link --proto-format -I <android-36/android.jar> --manifest tests/fixtures/aab/AndroidManifest.xml -o proto.apk resources.zip
```

Copy `AndroidManifest.xml`, `resources.pb`, `res/xml/backup.xml` and
`res/xml/extraction.xml` from that archive to `compiled/` by basename. Compiler
versions can change bytes; review any pin update. CI reads the committed outputs
without requiring or launching the Android SDK. The synthetic BundleConfig used
in the test is a marker only: this fixture tests protobuf declarations, not
bundletool validity or installability.

Format reference: [AOSP Resources.proto](https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/tools/aapt2/Resources.proto).
