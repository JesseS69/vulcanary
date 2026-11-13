"""Bounded inspection subset of AAPT2 Resources.proto; no generated code execution.

Reference: AOSP tools/aapt2/Resources.proto. Unknown semantic fields in inspected
messages, duplicate singular fields and ambiguous oneofs are refused, not merged.
Unrelated resource payloads and source-position metadata are not interpreted.
"""
from ._android_manifest import require, ANDROID, ATTRIBUTES, BACKUP_ATTRIBUTES
from . import _android_backup as backup

MAX_FIELDS = 500000
MAX_NODES = 8192
MAX_DEPTH = 64
MAX_TEXT = 4 * 1024 * 1024


class Decoder:
    def __init__(self):
        self.fields = 0
        self.text_bytes = 0

    def message(self, data, allowed, repeated=()):
        result, pos = {}, 0
        def varint():
            nonlocal pos
            value = 0
            for index in range(10):
                require(pos < len(data))
                byte = data[pos]
                pos += 1
                require(index != 9 or byte <= 1)
                value |= (byte & 127) << (index * 7)
                if byte < 128:
                    require(index == 0 or byte != 0)
                    return value
            require(False)
        while pos < len(data):
            self.fields += 1
            require(self.fields <= MAX_FIELDS)
            key = varint()
            field, wire = key >> 3, key & 7
            require(field in allowed and wire == allowed[field])
            require(field not in result or field in repeated)
            if wire == 0:
                value = varint()
            else:
                require(wire == 2)
                length = varint()
                require(length <= len(data) - pos)
                value = data[pos:pos + length]
                pos += length
            if field in repeated:
                result.setdefault(field, []).append(value)
            else:
                result[field] = value
        return result

    def text(self, value):
        self.text_bytes += len(value)
        require(self.text_bytes <= MAX_TEXT)
        text = value.decode('utf-8')
        require('\0' not in text)
        return text

    def xml(self, data):
        result = []
        def visit(raw, parent, depth):
            require(depth < MAX_DEPTH and len(result) < MAX_NODES)
            node = self.message(raw, {1: 2, 2: 2, 3: 2})
            require((1 in node) != (2 in node))
            if 2 in node:
                require(parent is not None and not self.text(node[2]).strip())
                return
            element = self.message(node[1], {1: 2, 2: 2, 3: 2, 4: 2, 5: 2}, (1, 4, 5))
            ns, name = self.text(element.get(2, b'')), self.text(element.get(3, b''))
            require(name)
            declarations = set()
            for raw_ns in element.get(1, []):
                namespace = self.message(raw_ns, {1: 2, 2: 2, 3: 2})
                prefix, uri = self.text(namespace.get(1, b'')), self.text(namespace.get(2, b''))
                require(prefix not in declarations and uri)
                declarations.add(prefix)
            attrs = {}
            require(len(element.get(4, [])) <= 256)
            for raw_attr in element.get(4, []):
                attr = self.message(raw_attr, {1: 2, 2: 2, 3: 2, 4: 2, 5: 0, 6: 2})
                key = (self.text(attr.get(1, b'')), self.text(attr.get(2, b'')))
                require(key[1] and key not in attrs)
                value = self.text(attr[3]) if 3 in attr else None
                attrs[key] = (value, attr.get(5, 0), attr.get(6))
            index = len(result)
            result.append((ns, name, parent, attrs))
            for child in element.get(5, []):
                visit(child, index, depth + 1)
        visit(data, None, 0)
        return result

    def item(self, data):
        item = self.message(data, {1: 2, 2: 2, 3: 2, 4: 2, 5: 2, 6: 2, 7: 2})
        require(len(item) == 1)
        return next(iter(item.items()))

    def boolean(self, compiled, raw):
        if compiled is None:
            return None
        kind, payload = self.item(compiled)
        if kind != 7:
            return None
        prim = self.message(payload, {8: 0})
        require(set(prim) == {8} and prim[8] in (0, 1))
        value = bool(prim[8])
        require(raw in (None, '', 'true' if value else 'false'))
        return value

    def manifest(self, data, *, include_identity=False):
        tree = self.xml(data)
        require(tree and tree[0][:3] == ('', 'manifest', None))
        application = None
        known = {**ATTRIBUTES, **BACKUP_ATTRIBUTES}
        for ns, name, parent, attrs in tree:
            for key, (_, ident, _) in attrs.items():
                if ident in known.values():
                    require(key == (ANDROID, next(k for k, v in known.items() if v == ident)))
            if (ns, name) != ('', 'application'):
                continue
            require(parent == 0 and application is None)
            application = {}
            for key, (raw, ident, compiled) in attrs.items():
                if key[0] != ANDROID or key[1] not in known:
                    continue
                label = key[1]
                require(ident == known[label])
                if label in ATTRIBUTES:
                    application[label] = self.boolean(compiled, raw)
                    continue
                value = {'kind': 'unsupported'}
                if compiled is not None:
                    kind, payload = self.item(compiled)
                    if kind == 1:
                        ref = self.message(payload, {1: 0, 2: 0, 3: 2, 4: 0, 5: 2, 6: 0, 7: 0})
                        require(ref.get(1, 0) == 0 and 0 < ref.get(2, 0) <= 0xffffffff)
                        require(ref.get(4, 0) in (0, 1) and ref.get(7, 0) in (0, 1) and ref.get(6, 0) <= 0xffffffff)
                        if 5 in ref:
                            require(self.message(ref[5], {1: 0}).get(1, 0) == 0)
                        value = {'kind': 'reference', 'value': ref[2]}
                    elif kind == 7 and label == 'fullBackupContent':
                        value = {'kind': 'boolean', 'value': self.boolean(compiled, raw)}
                application[label] = value
        require(application is not None)
        if include_identity:
            from ._android_identity_fields import IDS, identity
            attributes = {}
            for key, (raw, ident, compiled) in tree[0][3].items():
                if key != ('', 'package') and not (key[0] == ANDROID and key[1] in IDS) and ident not in IDS.values():
                    continue
                decoded = raw if key == ('', 'package') or key == (ANDROID, 'versionName') else None
                if compiled is not None:
                    kind, payload = self.item(compiled)
                    decoded = None
                    if kind in (2, 3):
                        string = self.message(payload, {1: 2})
                        decoded = self.text(string.get(1, b''))
                        require(raw in (None, '', decoded))
                    elif kind == 7:
                        prim = self.message(payload, {6: 0, 7: 0})
                        require(len(prim) == 1)
                        decoded = next(iter(prim.values()))
                        require(raw in (None, '', str(decoded), hex(decoded)))
                elif decoded is not None and decoded.startswith(('@', '?')):
                    decoded = None
                attributes[key] = (ident, decoded)
            application['_identity'] = identity(attributes)
        return application

    def backup_rules(self, data, attribute):
        tree = []
        for ns, name, parent, attrs in self.xml(data):
            require(not ns)
            decoded = {}
            for (attr_ns, label), (raw, ident, compiled) in attrs.items():
                require(not attr_ns and ident == 0)
                if compiled is None:
                    require(raw is not None)
                    value = raw
                else:
                    kind, payload = self.item(compiled)
                    if kind == 7:
                        value = self.boolean(compiled, raw)
                    else:
                        require(kind in (2, 3))
                        string = self.message(payload, {1: 2})
                        value = self.text(string.get(1, b''))
                        require(raw in (None, value))
                decoded[label] = value
            tree.append((name, parent, decoded))
        return backup.parse_tree(tree, attribute)

    def resolve_xml(self, data, reference):
        table = self.message(data, {1: 2, 2: 2, 4: 2}, (2, 4))
        selected, package_ids = [], set()
        for raw_package in table.get(2, []):
            package = self.message(raw_package, {1: 2, 2: 2, 3: 2}, (3,))
            ident = self.message(package.get(1, b''), {1: 0}).get(1, 0)
            require(0 < ident <= 255 and ident not in package_ids)
            package_ids.add(ident)
            types = set()
            for raw_type in package.get(3, []):
                typ = self.message(raw_type, {1: 2, 2: 2, 3: 2}, (3,))
                tid = self.message(typ.get(1, b''), {1: 0}).get(1, 0)
                require(0 < tid <= 255 and tid not in types)
                types.add(tid)
                entries = set()
                for raw_entry in typ.get(3, []):
                    entry = self.message(raw_entry, {1: 2, 2: 2, 3: 2, 4: 2, 5: 2, 6: 2, 7: 2, 8: 2}, (6, 8))
                    require(1 in entry)
                    eid = self.message(entry[1], {1: 0}).get(1, 0)
                    require(eid <= 65535 and eid not in entries)
                    entries.add(eid)
                    if (ident << 24 | tid << 16 | eid) == reference:
                        require(self.text(typ.get(2, b'')) == 'xml' and not any(k in entry for k in (4, 5, 7, 8)))
                        selected.append(entry)
        require(len(selected) == 1)
        values = selected[0].get(6, [])
        # A single default configuration only: no platform/configuration guessing.
        require(len(values) == 1)
        config = self.message(values[0], {1: 2, 2: 2})
        require(not config.get(1, b'') and 2 in config)
        value = self.message(config[2], {1: 2, 2: 2, 3: 0, 4: 2})
        require(not value.get(3, 0) and 4 in value)
        kind, payload = self.item(value[4])
        require(kind == 5)
        file = self.message(payload, {1: 2, 2: 0})
        require(file.get(2) == 3)
        path = self.text(file.get(1, b''))
        require(path.startswith('res/') and path.endswith('.xml') and '\\' not in path and ':' not in path)
        require(all(p not in ('', '.', '..') for p in path.split('/')))
        return path
