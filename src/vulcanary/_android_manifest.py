"""Bounded subset of Android binary XML; never resolves resource references.

Format reference: AOSP androidfw/ResourceTypes.h. Attribute IDs: android.R.attr.
This is an inspection parser, not an Android installability validator.
"""
import struct

ANDROID = 'http://schemas.android.com/apk/res/android'
ATTRIBUTES = {'debuggable': 0x0101000f, 'allowBackup': 0x01010280}
NONE = 0xffffffff
MAX_XML = 1024 * 1024


class ManifestError(ValueError):
    pass


def require(condition):
    if not condition:
        raise ManifestError('unsupported_or_invalid_manifest')


def unpack(fmt, data, offset):
    size = struct.calcsize(fmt)
    require(0 <= offset <= len(data) - size)
    return struct.unpack_from(fmt, data, offset)


def strings(data, header):
    require(header == 28)
    count, styles, flags, start, style_start = unpack('<5I', data, 8)
    require(count <= 8192 and styles == 0 and style_start == 0 and flags & ~0x101 == 0)
    require(header + 4 * count <= start <= len(data))
    values = []
    decoded_bytes = 0
    for index in range(count):
        offset = start + unpack('<I', data, header + index * 4)[0]
        require(start <= offset < len(data))
        if flags & 0x100:
            def length(position):
                first = unpack('<B', data, position)[0]
                if first & 0x80:
                    return ((first & 0x7f) << 8) | unpack('<B', data, position + 1)[0], position + 2
                return first, position + 1
            units, offset = length(offset)
            size, offset = length(offset)
            require(size <= 4096 and offset + size < len(data) and data[offset + size] == 0)
            value = data[offset:offset + size].decode('utf-8')
            require(len(value.encode('utf-16-le')) // 2 == units)
        else:
            units = unpack('<H', data, offset)[0]
            offset += 2
            if units & 0x8000:
                units = ((units & 0x7fff) << 16) | unpack('<H', data, offset)[0]
                offset += 2
            size = units * 2
            require(size <= 4096 and offset + size + 2 <= len(data) and data[offset + size:offset + size + 2] == b'\0\0')
            value = data[offset:offset + size].decode('utf-16-le')
        require('\0' not in value)
        decoded_bytes += len(value.encode('utf-8'))
        require(decoded_bytes <= MAX_XML)
        values.append(value)
    return values


def parse(data):
    require(8 <= len(data) <= MAX_XML)
    kind, header, total = unpack('<HHI', data, 0)
    require(kind == 3 and header == 8 and total == len(data))
    pool, resource_map = None, None
    stack, namespaces = [], []
    root_seen = False
    application = None
    position, chunks = 8, 0

    def string(index):
        if index == NONE:
            return None
        require(pool is not None and index < len(pool))
        return pool[index]

    while position < total:
        chunks += 1
        require(chunks <= 8192)
        kind, header, size = unpack('<HHI', data, position)
        require(8 <= header <= size and size <= total - position)
        chunk = data[position:position + size]
        position += size
        if kind == 1:
            require(pool is None and not root_seen)
            pool = strings(chunk, header)
            continue
        require(pool is not None)
        if kind == 0x180:
            require(resource_map is None and not root_seen and header == 8 and (size - 8) % 4 == 0)
            require((size - 8) // 4 <= len(pool))
            resource_map = list(unpack('<' + 'I' * ((size - 8) // 4), chunk, 8))
            require(len(resource_map) <= len(pool))
            continue
        require(header == 16)
        if kind in (0x100, 0x101):
            require(size == 24)
            pair = unpack('<II', chunk, 16)
            require(string(pair[0]) is not None and string(pair[1]) is not None)
            if kind == 0x100:
                require(len(namespaces) < 64)
                namespaces.append(pair)
            else:
                require(namespaces and namespaces.pop() == pair)
            continue
        if kind == 0x103:
            require(size == 24)
            ns, name = unpack('<II', chunk, 16)
            require(stack and stack.pop() == (string(ns), string(name)))
            continue
        require(kind == 0x102 and size >= 36)
        ns, name, attr_start, attr_size, count, id_index, class_index, style_index = unpack('<II6H', chunk, 16)
        element = (string(ns), string(name))
        require(element[1] is not None and len(stack) < 64)
        require(attr_start >= 20 and attr_size == 20 and count <= 256)
        require(16 + attr_start + count * attr_size <= size)
        require(all(index <= count for index in (id_index, class_index, style_index)))
        if not stack:
            require(not root_seen and element == (None, 'manifest'))
            root_seen = True
        is_application = element == (None, 'application')
        if is_application:
            require(stack == [(None, 'manifest')] and application is None)
            application = {}
        seen = set()
        for index in range(count):
            offset = 16 + attr_start + index * attr_size
            attr_ns, attr_name, raw, value_size, reserved, value_type, value = unpack('<IIIHBBI', chunk, offset)
            key = (string(attr_ns), string(attr_name))
            require(key[1] is not None and key not in seen and value_size == 8 and reserved == 0)
            seen.add(key)
            raw_value = string(raw)
            resource = resource_map[attr_name] if resource_map and attr_name < len(resource_map) else 0
            known_name = next((label for label, ident in ATTRIBUTES.items() if ident == resource), None)
            if known_name is not None:
                require(key == (ANDROID, known_name))
            if is_application and key[0] == ANDROID and key[1] in ATTRIBUTES:
                require(resource == ATTRIBUTES[key[1]])
                boolean = bool(value) if value_type == 0x12 else None
                if boolean is not None and raw_value is not None:
                    require(raw_value == ('true' if boolean else 'false'))
                application[key[1]] = boolean
        stack.append(element)
    require(root_seen and not stack and not namespaces and application is not None)
    return application
