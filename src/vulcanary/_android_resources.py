"""Bounded direct XML resource links; aliases and configuration choices are refused.

Layout reference: AOSP androidfw ResourceTypes.h. No resource values are exported.
"""
from ._android_manifest import require, strings, unpack

MAX_TABLE = 8 * 1024 * 1024
MAX_STRINGS = 65536


def chunks(data, begin, end):
    position, count = begin, 0
    while position < end:
        kind, header, size = unpack('<HHI', data, position)
        require(8 <= header <= size <= end - position)
        count += 1
        require(count <= 8192)
        yield position, kind, header, data[position:position + size]
        position += size
    require(position == end)


def resolve_xml(data, reference):
    require(12 <= len(data) <= MAX_TABLE and 0 < reference <= 0xffffffff)
    kind, header, size, packages = unpack('<HHII', data, 0)
    require(kind == 2 and header == 12 and size == len(data) and 0 < packages <= 32)
    pool, package_chunks, seen_ids = None, [], set()
    for _, kind, header, chunk in chunks(data, 12, len(data)):
        if kind == 1:
            require(pool is None and not package_chunks)
            pool = strings(chunk, header, max_count=MAX_STRINGS)
        else:
            require(kind == 0x200 and pool is not None and header in (284, 288))
            package_id = unpack('<I', chunk, 8)[0]
            require(0 < package_id <= 255 and package_id not in seen_ids)
            seen_ids.add(package_id)
            package_chunks.append((package_id, header, chunk))
    require(pool is not None and len(package_chunks) == packages)
    matches = [item for item in package_chunks if item[0] == reference >> 24]
    require(len(matches) == 1)
    _, package_header, package = matches[0]
    type_pool_offset = unpack('<I', package, 268)[0]
    key_pool_offset = unpack('<I', package, 276)[0]
    type_offset = unpack('<I', package, 284)[0] if package_header == 288 else 0
    require(type_offset <= 255)
    wanted_type, wanted_entry = (reference >> 16) & 255, reference & 65535
    require(wanted_type > type_offset)
    raw_type = wanted_type - type_offset
    children = list(chunks(package, package_header, len(package)))
    pools = {}
    for position, kind, header, chunk in children:
        if kind == 1:
            require(position in (type_pool_offset, key_pool_offset) and position not in pools)
            pools[position] = strings(chunk, header, max_count=MAX_STRINGS)
        else:
            # Overlay, library, staged-alias and unfamiliar package chunks can alter resolution.
            require(kind in (0x201, 0x202))
    require(type_pool_offset != key_pool_offset and set(pools) == {type_pool_offset, key_pool_offset})
    type_names, key_names = pools[type_pool_offset], pools[key_pool_offset]
    require(raw_type <= len(type_names) and type_names[raw_type - 1] == 'xml')
    specs = {}
    for _, kind, header, chunk in children:
        if kind != 0x202:
            continue
        require(header == 16)
        type_id, reserved, types_count, count = unpack('<BBHI', chunk, 8)
        require(0 < type_id <= len(type_names) and reserved == 0 and count <= 65536)
        require(len(chunk) == 16 + 4 * count and type_id not in specs)
        actual_types = sum(kind == 0x201 and unpack('<B', child, 8)[0] == type_id
                           for _, kind, _, child in children)
        require(types_count == 0 or types_count == actual_types)
        specs[type_id] = count
    require(raw_type in specs and wanted_entry < specs[raw_type])
    values, default_seen, configurations = [], False, set()
    for _, kind, header, chunk in children:
        if kind == 1:
            continue
        require(header >= 16)
        type_id, flags, reserved, count = unpack('<BBHI', chunk, 8)
        require(0 < type_id <= len(type_names) and count <= 65536)
        if kind == 0x202:
            require(header == 16 and flags == 0 and len(chunk) == 16 + 4 * count)
            continue
        require(reserved == 0)
        if type_id != raw_type:
            continue
        require(count <= specs[raw_type])
        require(header >= 24 and flags == 0)  # Sparse/offset16 layouts are not guessed.
        entries_start, config_size = unpack('<II', chunk, 16)
        require(28 <= config_size <= 128 and header == 20 + config_size)
        require(header + 4 * count <= entries_start <= len(chunk))
        config = chunk[20:header]
        require(config not in configurations)
        configurations.add(config)
        if wanted_entry >= count:
            continue
        offset = unpack('<I', chunk, header + 4 * wanted_entry)[0]
        if offset == 0xffffffff:
            continue
        entry = entries_start + offset
        require(offset % 4 == 0 and entries_start <= entry <= len(chunk) - 16)
        entry_size, entry_flags, key = unpack('<HHI', chunk, entry)
        require(entry_size == 8 and entry_flags in (0, 2) and key < len(key_names))
        value_size, value_reserved, value_type, value = unpack('<HBBI', chunk, entry + 8)
        require(value_size == 8 and value_reserved == 0 and value_type == 3 and value < len(pool))
        path = pool[value]
        require(path.startswith('res/') and path.endswith('.xml') and '\\' not in path and ':' not in path)
        require(all(part not in ('', '.', '..') for part in path.split('/')))
        values.append(path)
        default_seen |= not any(config[4:])
    require(default_seen and values and len(set(values)) == 1)
    return values[0]
