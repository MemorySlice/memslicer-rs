/// Frida JavaScript agent script injected into the target process.
pub const AGENT_SCRIPT: &str = r#"
'use strict';

// -----------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------

function _isAnon(r) {
    return r.file === null || r.file === undefined ||
           (r.file && (r.file.path === '' || r.file.path === undefined));
}

function _enrichedResult(r, readable, skipReason, pagesResident) {
    return {
        base: r.base.toString(), size: r.size, protection: r.protection,
        file: r.file || null,
        readable: readable, skipReason: skipReason,
        pagesResident: pagesResident
    };
}

// -----------------------------------------------------------------------
// Platform-specific enrichment helpers
// -----------------------------------------------------------------------

function _enrichLinux(ranges) {
    // Parse /proc/self/smaps line-by-line for Rss, VmFlags per VMA
    var smapsData = {};
    try {
        var f = new File('/proc/self/smaps', 'r');
        var currentBase = null;
        var currentInfo = null;
        var line;
        while ((line = f.readLine()) !== '') {
            // VMA header line: "7f1234000-7f1235000 r-xp ..."
            var headerMatch = line.match(/^([0-9a-f]+)-[0-9a-f]+\s/);
            if (headerMatch) {
                if (currentBase !== null && currentInfo !== null) {
                    smapsData[currentBase] = currentInfo;
                }
                currentBase = '0x' + headerMatch[1];
                currentInfo = { rss: -1, vmFlags: '' };
                continue;
            }
            if (currentInfo === null) continue;
            if (line.indexOf('Rss:') === 0) {
                var rssMatch = line.match(/Rss:\s+(\d+)/);
                if (rssMatch) currentInfo.rss = parseInt(rssMatch[1]) * 1024;
            } else if (line.indexOf('VmFlags:') === 0) {
                currentInfo.vmFlags = line.substring(8).trim();
            }
        }
        if (currentBase !== null && currentInfo !== null) {
            smapsData[currentBase] = currentInfo;
        }
        f.close();
    } catch (e) {
        // smaps not available (non-Linux, restricted), fall through
    }

    return ranges.map(function(r) {
        var base = r.base.toString();
        var info = smapsData[base];
        var readable = true;
        var skipReason = null;
        var pagesResident = -1;

        if (info) {
            var rss = info.rss;
            var flags = info.vmFlags;
            pagesResident = rss > 0 ? Math.ceil(rss / Process.pageSize) : 0;

            // Skip large anonymous regions with Rss=0 (JVM/ART pre-alloc)
            if (_isAnon(r) && rss === 0 && r.size >= 1048576) {
                readable = false;
                skipReason = 'anonymous Rss=0, size >= 1MB';
            }
            // VmFlags-based skips
            if (flags.indexOf('dd') !== -1) {
                readable = false;
                skipReason = 'VmFlags dd (don\'t dump)';
            }
            if (flags.indexOf('io') !== -1) {
                readable = false;
                skipReason = 'VmFlags io (device I/O)';
            }
            if (flags.indexOf('um') !== -1 || flags.indexOf('uw') !== -1) {
                readable = false;
                skipReason = 'VmFlags um/uw (userfaultfd)';
            }
        }

        // Device file path skip (except ashmem)
        var filePath = (r.file && r.file.path) ? r.file.path : '';
        if (filePath.indexOf('/dev/') === 0 && filePath.indexOf('ashmem') === -1) {
            readable = false;
            skipReason = 'device file: ' + filePath;
        }

        return _enrichedResult(r, readable, skipReason, pagesResident);
    });
}

function _enrichDarwin(ranges) {
    var machTaskSelf = null;
    var machVmRegion = null;
    var initialized = false;

    try {
        machTaskSelf = new NativeFunction(
            Module.findExportByName(null, 'mach_task_self'),
            'uint', []
        );
        machVmRegion = new NativeFunction(
            Module.findExportByName(null, 'mach_vm_region'),
            'int', ['uint', 'pointer', 'pointer', 'int', 'pointer', 'pointer', 'pointer']
        );
        initialized = true;
    } catch (e) {
        // mach APIs not available
    }

    if (!initialized) {
        return ranges.map(function(r) {
            return _enrichedResult(r, true, null, -1);
        });
    }

    // Hoist allocations and task port outside the loop
    var task = machTaskSelf();
    var addrBuf = Memory.alloc(8);
    var sizeBuf = Memory.alloc(8);
    var infoSize = 64;
    var infoBuf = Memory.alloc(infoSize);
    var infoCountBuf = Memory.alloc(4);
    var objectNameBuf = Memory.alloc(4);

    return ranges.map(function(r) {
        var readable = true;
        var skipReason = null;
        var pagesResident = -1;

        try {
            addrBuf.writeU64(uint64(r.base.toString()));
            sizeBuf.writeU64(uint64('0'));
            infoCountBuf.writeU32(infoSize / 4);

            var kr = machVmRegion(task, addrBuf, sizeBuf, 13, infoBuf, infoCountBuf, objectNameBuf);
            if (kr === 0) {
                // pages_resident is at offset 16 in vm_region_extended_info_data_t (uint32)
                pagesResident = infoBuf.add(16).readU32();
                var pagesSwappedOut = infoBuf.add(20).readU32();

                if (pagesResident === 0 && pagesSwappedOut === 0 && _isAnon(r)) {
                    readable = false;
                    skipReason = 'pages_resident=0, not file-backed';
                }
            }
        } catch (e) {
            // mach_vm_region failed, assume readable
        }

        return _enrichedResult(r, readable, skipReason, pagesResident);
    });
}

function _enrichWindows(ranges) {
    var virtualQuery = null;
    var initialized = false;

    try {
        virtualQuery = new NativeFunction(
            Module.findExportByName('Kernel32.dll', 'VirtualQuery'),
            'uint', ['pointer', 'pointer', 'uint']
        );
        initialized = true;
    } catch (e) {
        // VirtualQuery not available
    }

    if (!initialized) {
        return ranges.map(function(r) {
            return _enrichedResult(r, true, null, -1);
        });
    }

    // MEMORY_BASIC_INFORMATION size: 48 bytes on x64, 28 on x86
    var mbiSize = Process.pointerSize === 8 ? 48 : 28;
    var stateOffset = Process.pointerSize === 8 ? 24 : 16;
    var protectOffset = Process.pointerSize === 8 ? 28 : 20;
    // Hoist allocation outside the loop
    var mbi = Memory.alloc(mbiSize);

    return ranges.map(function(r) {
        var readable = true;
        var skipReason = null;

        try {
            var ret = virtualQuery(ptr(r.base.toString()), mbi, mbiSize);
            if (ret > 0) {
                var state = mbi.add(stateOffset).readU32();
                var protect = mbi.add(protectOffset).readU32();

                // MEM_RESERVE = 0x2000
                if (state === 0x2000) {
                    readable = false;
                    skipReason = 'MEM_RESERVE (not committed)';
                }
                // PAGE_GUARD = 0x100
                if ((protect & 0x100) !== 0) {
                    readable = false;
                    skipReason = 'PAGE_GUARD';
                }
                // PAGE_NOACCESS = 0x01
                if (protect === 0x01) {
                    readable = false;
                    skipReason = 'PAGE_NOACCESS';
                }
            }
        } catch (e) {
            // VirtualQuery failed, assume readable
        }

        return _enrichedResult(r, readable, skipReason, -1);
    });
}

// -----------------------------------------------------------------------
// RPC exports
// -----------------------------------------------------------------------

rpc.exports = {
    getPlatformInfo: function() {
        return {
            platform: Process.platform,
            arch: Process.arch,
            pageSize: Process.pageSize,
            pid: Process.id
        };
    },

    enumerateRanges: function(prot) {
        return Process.enumerateRanges(prot || '---');
    },

    enumerateRangesEnriched: function() {
        var ranges = Process.enumerateRanges('r--');
        var platform = Process.platform;
        if (platform === 'linux') return _enrichLinux(ranges);
        if (platform === 'darwin') return _enrichDarwin(ranges);
        if (platform === 'windows') return _enrichWindows(ranges);
        // Fallback: no enrichment
        return ranges.map(function(r) {
            return _enrichedResult(r, true, null, -1);
        });
    },

    enumerateModules: function() {
        return Process.enumerateModules();
    }
};

// -----------------------------------------------------------------------
// Binary memory read handler (via send/recv instead of RPC)
// -----------------------------------------------------------------------

function _onMessage(message) {
    if (message.type === 'read') {
        try {
            var buf = ptr(message.addr).readVolatile(message.size);
            if (buf !== null && buf.byteLength > 0) {
                send({type: 'mem', id: message.id, result: 'ok', returns: {ok: true}}, buf);
            } else {
                send({type: 'mem', id: message.id, result: 'ok', returns: {ok: false}});
            }
        } catch (e) {
            send({type: 'mem', id: message.id, result: 'ok', returns: {ok: false}});
        }
    } else if (message.type === 'readPages') {
        var addr = ptr(message.addr);
        var pageSize = message.pageSize;
        var pageCount = message.pageCount;
        var pageMap = [];
        var chunks = [];
        var totalSize = 0;
        for (var i = 0; i < pageCount; i++) {
            try {
                var buf = addr.add(i * pageSize).readVolatile(pageSize);
                if (buf !== null && buf.byteLength > 0) {
                    pageMap.push(true);
                    chunks.push(buf);
                    totalSize += buf.byteLength;
                } else {
                    pageMap.push(false);
                }
            } catch (e) {
                pageMap.push(false);
            }
        }
        var combined = new ArrayBuffer(totalSize);
        var view = new Uint8Array(combined);
        var offset = 0;
        for (var j = 0; j < chunks.length; j++) {
            view.set(new Uint8Array(chunks[j]), offset);
            offset += chunks[j].byteLength;
        }
        send({type: 'mem', id: message.id, result: 'ok', returns: {ok: true, pageMap: pageMap}}, combined);
    }
    recv(_onMessage);
}
recv(_onMessage);
"#;
