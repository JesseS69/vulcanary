import io
import json
import unittest
from unittest.mock import patch

from vulcanary.updates import check_for_update


class _Response(io.BytesIO):
    def __enter__(self): return self
    def __exit__(self, *args): self.close()


class UpdateTests(unittest.TestCase):
    def test_update_check_is_read_only_and_validates_release_origin(self) -> None:
        payload = {"tag_name": "v99.0.0", "html_url": "https://github.com/JesseS69/vulcanary/releases/tag/v99.0.0"}
        with patch("vulcanary.updates.urlopen", return_value=_Response(json.dumps(payload).encode())) as opened:
            result = check_for_update()
        self.assertTrue(result["update_available"])
        request = opened.call_args.args[0]
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.full_url, "https://api.github.com/repos/JesseS69/vulcanary/releases/latest")
        payload["html_url"] = "https://attacker.invalid/release"
        with patch("vulcanary.updates.urlopen", return_value=_Response(json.dumps(payload).encode())):
            with self.assertRaisesRegex(ValueError, "invalid"):
                check_for_update()


if __name__ == "__main__":
    unittest.main()
