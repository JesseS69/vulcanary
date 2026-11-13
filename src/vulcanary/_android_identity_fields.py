"""Shared packaged identity semantics; strings stay internal until hashed."""
from ._android_manifest import ANDROID, require

IDS = {'versionCode': 0x0101021b, 'versionName': 0x0101021c, 'versionCodeMajor': 0x01010576}


def identity(attributes):
    values = {}
    for (namespace, name), (ident, value) in attributes.items():
        if ident in IDS.values():
            require((namespace, name) == (ANDROID, next(k for k, v in IDS.items() if v == ident)))
        if name == 'package' and not namespace:
            require(ident == 0 and (value is None or isinstance(value, str)))
            values['package'] = value or None
        if namespace == ANDROID and name in IDS:
            require(ident == IDS[name])
            if name == 'versionName':
                require(value is None or isinstance(value, str))
            else:
                require(value is None or type(value) is int and 0 <= value <= 0x7fffffff)
            values[name] = value
    low, high = values.get('versionCode'), values.get('versionCodeMajor', 0)
    return {'application_id': values.get('package'),
            'version_name': values.get('versionName'),
            'version_code': None if low is None or high is None else (high << 32) | low}
