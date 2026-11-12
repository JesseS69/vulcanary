"""Bounded packaged explicit-exclusion evidence, not Android runtime emulation."""
import hashlib
import json

from ._android_manifest import MAX_XML, NONE, require, strings, unpack

DOMAINS = frozenset(('root', 'file', 'database', 'sharedpref', 'external',
                     'device_root', 'device_file', 'device_database', 'device_sharedpref'))
MODES = {'legacy': 'fullBackupContent', 'cloud': 'dataExtractionRules', 'device': 'dataExtractionRules'}
MAX_REQUIREMENTS = 128
MAX_REQUIREMENT_BYTES = 65536


def path_value(value):
    require(isinstance(value, str) and 0 < len(value.encode('utf-8')) <= 512)
    require(not any(ord(c) < 32 or c in '\\:*?[]' for c in value))
    if value in ('.', './'):
        return '.'
    if value.endswith('/'):
        value = value[:-1]
    require(all(part not in ('', '.', '..') for part in value.split('/')))
    return value


def requirements(value):
    require(isinstance(value, list) and 0 < len(value) <= MAX_REQUIREMENTS)
    result, seen = [], set()
    for row in value:
        require(isinstance(row, dict) and set(row) == {'mode', 'domain', 'path'})
        require(isinstance(row['mode'], str) and row['mode'] in MODES)
        require(isinstance(row['domain'], str) and row['domain'] in DOMAINS)
        normalized = {'mode': row['mode'], 'domain': row['domain'], 'path': path_value(row['path'])}
        key = tuple(normalized.values())
        require(key not in seen)
        seen.add(key)
        result.append(normalized)
    return result


def read_requirements(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    with path.open('rb') as stream:
        data = stream.read(MAX_REQUIREMENT_BYTES + 1)
    require(len(data) <= MAX_REQUIREMENT_BYTES)
    return requirements(json.loads(data.decode('utf-8'), object_pairs_hook=unique))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                     ensure_ascii=True).encode()).hexdigest()


def nodes(data):
    """Strict unnamespaced binary XML subset used by backup rule documents."""
    require(8 <= len(data) <= MAX_XML)
    require(unpack('<HHI', data, 0) == (3, 8, len(data)))
    pool, stack, result, position, chunk_count, map_seen = None, [], [], 8, 0, False
    def string(index):
        require(pool is not None and index < len(pool))
        return pool[index]
    while position < len(data):
        chunk_count += 1
        require(chunk_count <= 8192)
        kind, header, size = unpack('<HHI', data, position)
        require(8 <= header <= size <= len(data) - position)
        chunk = data[position:position + size]
        position += size
        if kind == 1:
            require(pool is None and not result)
            pool = strings(chunk, header)
            continue
        require(pool is not None)
        if kind == 0x180:
            require(not result and not map_seen and header == 8 and (size - 8) % 4 == 0)
            require((size - 8) // 4 <= len(pool) and not any(chunk[8:]))
            map_seen = True
            continue
        require(header == 16)
        if kind == 0x103:
            require(size == 24 and stack)
            ns, name = unpack('<II', chunk, 16)
            require(ns == NONE and result[stack[-1]][0] == string(name))
            stack.pop()
            continue
        require(kind == 0x102 and size >= 36 and len(result) < 1024 and len(stack) < 4)
        ns, name, start, stride, count, ident, cls, style = unpack('<II6H', chunk, 16)
        require(ns == NONE and start == 20 and stride == 20 and count <= 8)
        require(16 + start + stride * count == size and ident == cls == style == 0)
        require(stack or not result)
        attrs = {}
        for index in range(count):
            ns, key, raw, value_size, reserved, value_type, value = unpack('<IIIHBBI', chunk, 36 + index * 20)
            require(ns == NONE and value_size == 8 and reserved == 0)
            key = string(key)
            require(key not in attrs)
            require(value_type in (3, 0x12))  # References and unfamiliar types are unresolved.
            decoded = string(value) if value_type == 3 else bool(value)
            if raw != NONE:
                expected = ('true' if decoded else 'false') if isinstance(decoded, bool) else decoded
                require(string(raw) == expected)
            attrs[key] = decoded
        result.append((string(name), stack[-1] if stack else None, attrs))
        stack.append(len(result) - 1)
    require(result and not stack)
    return result


def parse(data, attribute):
    tree = nodes(data)
    expected = 'full-backup-content' if attribute == 'fullBackupContent' else 'data-extraction-rules'
    require(attribute in MODES.values() and tree[0] == (expected, None, {}))
    exclusions = {'legacy': set(), 'cloud': set(), 'device': set()}
    sections = {}
    for index, (name, parent, attrs) in enumerate(tree[1:], 1):
        if expected == 'data-extraction-rules' and parent == 0:
            require(name in ('cloud-backup', 'device-transfer') and name not in sections.values())
            allowed = {'disableIfNoEncryptionCapabilities'} if name == 'cloud-backup' else set()
            require(set(attrs) <= allowed and all(isinstance(v, bool) for v in attrs.values()))
            sections[index] = name
            continue
        if expected == 'full-backup-content':
            require(parent == 0)
            mode = 'legacy'
        else:
            require(parent in sections)
            mode = 'cloud' if sections[parent] == 'cloud-backup' else 'device'
        require(name in ('include', 'exclude'))
        allowed = {'domain', 'path'}
        if name == 'include' and mode == 'legacy':
            allowed.add('requireFlags')
        require({'domain', 'path'} <= set(attrs) <= allowed)
        require(isinstance(attrs['domain'], str) and attrs['domain'] in DOMAINS)
        path = path_value(attrs['path'])
        if 'requireFlags' in attrs:
            flags = attrs['requireFlags']
            require(isinstance(flags, str) and flags and set(flags.split('|')) <=
                    {'clientSideEncryption', 'deviceToDeviceTransfer'})
        if name == 'exclude':
            exclusions[mode].add((attrs['domain'], path))
    return exclusions


def evaluate(requested, parsed):
    rows = []
    for index, row in enumerate(requested):
        evidence = parsed.get(MODES[row['mode']])
        state, basis = 'BLOCKED', 'rules_unavailable_or_unsupported'
        if evidence is not None:
            matches = evidence[row['mode']]
            found = (row['domain'], row['path']) in matches or (row['domain'], '.') in matches
            state = 'PASS' if found else 'FAIL'
            basis = 'explicit_exclusion_present' if found else 'explicit_exclusion_not_found'
        rows.append({'id': 'backup-requirement-' + str(index + 1), 'mode': row['mode'],
                     'requirement_sha256': digest(row), 'state': state, 'basis': basis,
                     'expected': True, 'observed': None if evidence is None else state == 'PASS',
                     'evidence_method': 'packaged-explicit-exclusion'})
    return rows
