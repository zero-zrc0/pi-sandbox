'use strict';

var node_worker_threads = require('node:worker_threads');

function isHostToWorkerMessage(value) {
    return typeof value === "object" && value !== null && value.type === "result";
}

/**
 * Minimal WASI shim for running QuickJS in any WebAssembly environment.
 *
 * Implements the subset of WASI snapshot_preview1 that QuickJS needs:
 *   - clock_time_get (for Date.now() and Math.random() PRNG seeding)
 *   - fd_write (for QuickJS runtime internal logging)
 *   - fd_close (stub)
 *   - fd_fdstat_get (stub)
 *   - fd_seek (stub)
 *   - random_get (for crypto extension and WASI libc init)
 *
 * Users can override any of these by providing their own implementations
 * in the `wasi` option when creating a VM. Overrides are applied to both
 * the main module and all loaded extensions.
 */
/** Returns a wasi_snapshot_preview1 import object with built-in defaults. */
function createWasiShim(memoryAccessor) {
    // WASI error codes
    const ERRNO_SUCCESS = 0;
    const ERRNO_BADF = 8;
    const ERRNO_NOSYS = 52;
    // Clock IDs
    const CLOCK_REALTIME = 0;
    const CLOCK_MONOTONIC = 1;
    return {
        clock_time_get(clockId, _precision, resultPtr) {
            const mem = memoryAccessor();
            const view = new DataView(mem.buffer);
            if (clockId === CLOCK_REALTIME || clockId === CLOCK_MONOTONIC) {
                const timeNs = BigInt(Date.now()) * 1000000n;
                view.setBigUint64(resultPtr, timeNs, true);
                return ERRNO_SUCCESS;
            }
            return ERRNO_NOSYS;
        },
        fd_write(fd, iovsPtr, iovsLen, nwrittenPtr) {
            const mem = memoryAccessor();
            const view = new DataView(mem.buffer);
            const bytes = new Uint8Array(mem.buffer);
            let totalWritten = 0;
            if (fd !== 1 && fd !== 2) {
                return ERRNO_BADF;
            }
            for (let i = 0; i < iovsLen; i++) {
                const bufPtr = view.getUint32(iovsPtr + i * 8, true);
                const bufLen = view.getUint32(iovsPtr + i * 8 + 4, true);
                const chunk = bytes.slice(bufPtr, bufPtr + bufLen);
                const text = new TextDecoder().decode(chunk);
                if (fd === 1) {
                    if (typeof process !== 'undefined' && process.stdout) {
                        process.stdout.write(text);
                    }
                    else {
                        console.log(text);
                    }
                }
                else {
                    if (typeof process !== 'undefined' && process.stderr) {
                        process.stderr.write(text);
                    }
                    else {
                        console.error(text);
                    }
                }
                totalWritten += bufLen;
            }
            view.setUint32(nwrittenPtr, totalWritten, true);
            return ERRNO_SUCCESS;
        },
        fd_close(_fd) {
            return ERRNO_NOSYS;
        },
        fd_fdstat_get(fd, statPtr) {
            const mem = memoryAccessor();
            const view = new DataView(mem.buffer);
            if (fd === 1 || fd === 2) {
                view.setUint8(statPtr, 2); // fs_filetype = CHARACTER_DEVICE
                view.setUint16(statPtr + 2, 0, true); // fs_flags
                view.setBigUint64(statPtr + 8, 0n, true); // fs_rights_base
                view.setBigUint64(statPtr + 16, 0n, true); // fs_rights_inheriting
                return ERRNO_SUCCESS;
            }
            return ERRNO_BADF;
        },
        fd_seek(_fd, _offset, _whence, _resultPtr) {
            return ERRNO_NOSYS;
        },
        random_get(bufPtr, bufLen) {
            const mem = memoryAccessor();
            const bytes = new Uint8Array(mem.buffer, bufPtr, bufLen);
            if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
                crypto.getRandomValues(bytes);
            }
            else {
                for (let i = 0; i < bufLen; i++) {
                    bytes[i] = Math.floor(Math.random() * 256);
                }
            }
            return ERRNO_SUCCESS;
        },
    };
}

/**
 * WASM Dynamic Linking - Extension Loader
 *
 * Loads WASM shared libraries (.so) compiled with wasi-sdk as extensions
 * for the QuickJS WASM runtime. Extensions can call QuickJS C API functions
 * directly through dynamic linking (shared memory + symbol resolution).
 *
 * Key concepts:
 * - Extensions are WASM shared libraries with a `dylink.0` custom section
 * - They share linear memory and the indirect function table with the main module
 * - Symbol imports (env.*) are resolved against the main module's exports
 * - Each extension gets a unique __memory_base and __table_base
 * - Extensions export an init function (e.g., `qjs_ext_url_init`)
 */
const decoder = new TextDecoder();
/**
 * Parse a null-terminated "key=value\nkey=value" string from WASM memory
 * into a Record<string, string>. Used to read version info from extensions.
 */
function parseVersionString(memory, ptr) {
    const mem = new Uint8Array(memory.buffer);
    let end = ptr;
    while (mem[end] !== 0)
        end++;
    if (end === ptr)
        return {};
    const str = decoder.decode(mem.slice(ptr, end));
    const result = {};
    for (const line of str.split('\n')) {
        const eq = line.indexOf('=');
        if (eq > 0) {
            result[line.slice(0, eq)] = line.slice(eq + 1);
        }
    }
    return result;
}
/**
 * Check if an extension exports a versions function and parse the result.
 */
function extractExtensionVersions(ext, memory) {
    const versionsFnName = `qjs_ext_${ext.name.replace(/-/g, '_')}_versions`;
    const versionsFn = ext.instance.exports[versionsFnName];
    if (typeof versionsFn !== 'function')
        return undefined;
    const ptr = versionsFn();
    if (ptr === 0)
        return undefined;
    return parseVersionString(memory, ptr);
}
// ---- dylink.0 parser ----
/** Read a ULEB128-encoded integer from a byte array */
function readULEB128(bytes, offset) {
    let result = 0;
    let shift = 0;
    while (offset.value < bytes.length) {
        const byte = bytes[offset.value++];
        result |= (byte & 0x7f) << shift;
        if ((byte & 0x80) === 0)
            break;
        shift += 7;
    }
    return result;
}
/** Parse the dylink.0 custom section from a WASM module */
function parseDylink(module) {
    const sections = WebAssembly.Module.customSections(module, 'dylink.0');
    if (sections.length === 0)
        return null;
    const bytes = new Uint8Array(sections[0]);
    const offset = { value: 0 };
    const info = {
        memorySize: 0,
        memoryAlignment: 0,
        tableSize: 0,
        tableAlignment: 0,
        needed: [],
    };
    while (offset.value < bytes.length) {
        const subsectionType = readULEB128(bytes, offset);
        const subsectionSize = readULEB128(bytes, offset);
        const subsectionEnd = offset.value + subsectionSize;
        if (subsectionType === 1) {
            // WASM_DYLINK_MEM_INFO
            info.memorySize = readULEB128(bytes, offset);
            info.memoryAlignment = readULEB128(bytes, offset);
            info.tableSize = readULEB128(bytes, offset);
            info.tableAlignment = readULEB128(bytes, offset);
        }
        else if (subsectionType === 2) {
            // WASM_DYLINK_NEEDED
            const count = readULEB128(bytes, offset);
            for (let i = 0; i < count; i++) {
                const len = readULEB128(bytes, offset);
                const name = new TextDecoder().decode(bytes.slice(offset.value, offset.value + len));
                offset.value += len;
                info.needed.push(name);
            }
        }
        offset.value = subsectionEnd;
    }
    return info;
}
// ---- Extension Loader ----
/**
 * Load a WASM shared library extension and link it against the main module.
 *
 * @param descriptor - Extension description (name, wasm bytes, init function)
 * @param mainExports - The main QuickJS WASM module's exports
 * @param wasiBuiltins - Built-in WASI implementations (lowest priority)
 * @param wasiUserOverrides - User-provided WASI overrides (highest priority)
 * @param memoryProxy - A memory proxy for extension WASI factories
 * @param allocBase - Optional fixed memory/table bases (for snapshot restore)
 */
async function loadExtension(descriptor, mainExports, wasiBuiltins, wasiUserOverrides, memoryProxy, allocBase) {
    // Compile the extension module
    let module;
    if (descriptor.wasm instanceof WebAssembly.Module) {
        module = descriptor.wasm;
    }
    else {
        module = await WebAssembly.compile(descriptor.wasm);
    }
    // Parse dylink.0 section
    const dylink = parseDylink(module);
    if (!dylink) {
        throw new Error(`Extension "${descriptor.name}" is not a WASM shared library (missing dylink.0 section)`);
    }
    const memory = mainExports.memory;
    const table = mainExports.__indirect_function_table;
    const stackPointer = mainExports.__stack_pointer;
    const mallocFn = mainExports.malloc;
    if (!memory)
        throw new Error('Main module does not export memory');
    if (!table)
        throw new Error('Main module does not export __indirect_function_table');
    if (!mallocFn)
        throw new Error('Main module does not export malloc');
    // Allocate memory region for the extension's static data
    let memoryBase;
    let tableBase;
    if (allocBase) {
        // Restore mode: use the exact same bases as before
        memoryBase = allocBase.memoryBase;
        tableBase = allocBase.tableBase;
    }
    else {
        // Fresh allocation
        if (dylink.memorySize > 0) {
            // Use malloc from the main module to allocate in the shared heap
            memoryBase = mallocFn(dylink.memorySize);
            if (memoryBase === 0) {
                throw new Error(`Failed to allocate ${dylink.memorySize} bytes for extension "${descriptor.name}"`);
            }
            // Zero-initialize the region
            new Uint8Array(memory.buffer, memoryBase, dylink.memorySize).fill(0);
        }
        else {
            memoryBase = 0;
        }
    }
    // Grow the function table if needed
    if (allocBase) {
        tableBase = allocBase.tableBase;
        // Ensure table is large enough
        if (tableBase + dylink.tableSize > table.length) {
            table.grow(tableBase + dylink.tableSize - table.length);
        }
    }
    else {
        tableBase = table.length;
        if (dylink.tableSize > 0) {
            table.grow(dylink.tableSize);
        }
    }
    // Build the import object
    const extImports = WebAssembly.Module.imports(module);
    const importObj = {
        env: {},
        'GOT.mem': {},
        'GOT.func': {},
    };
    // Provide wasi_snapshot_preview1 imports to extensions that need them.
    // Layered merge: builtins → extension-provided → user overrides.
    const needsWasi = extImports.some((imp) => imp.module === 'wasi_snapshot_preview1');
    if (needsWasi) {
        const extWasi = (descriptor.wasi && memoryProxy) ? descriptor.wasi(memoryProxy) : undefined;
        importObj['wasi_snapshot_preview1'] = {
            ...wasiBuiltins, // 1. Built-in defaults (lowest priority)
            ...extWasi, // 2. Extension-provided
            ...wasiUserOverrides // 3. User overrides (highest priority)
        };
    }
    // Collect names of functions the extension exports (for self-resolution)
    const extExportNames = new Set(WebAssembly.Module.exports(module)
        .filter((e) => e.kind === 'function')
        .map((e) => e.name));
    const unresolvedFuncs = new Set();
    for (const imp of extImports) {
        if (imp.module === 'env') {
            if (imp.name === 'memory' && imp.kind === 'memory') {
                importObj.env.memory = memory;
            }
            else if (imp.name === '__indirect_function_table' &&
                imp.kind === 'table') {
                importObj.env.__indirect_function_table = table;
            }
            else if (imp.name === '__memory_base' && imp.kind === 'global') {
                importObj.env.__memory_base = new WebAssembly.Global({ value: 'i32', mutable: false }, memoryBase);
            }
            else if (imp.name === '__table_base' && imp.kind === 'global') {
                importObj.env.__table_base = new WebAssembly.Global({ value: 'i32', mutable: false }, tableBase);
            }
            else if (imp.name === '__stack_pointer' && imp.kind === 'global') {
                importObj.env.__stack_pointer = stackPointer;
            }
            else if (imp.kind === 'function') {
                // Resolve function imports from the main module's exports
                const resolved = mainExports[imp.name];
                if (resolved && typeof resolved === 'function') {
                    importObj.env[imp.name] = resolved;
                }
                else {
                    // Provide a trap stub for unresolved symbols (e.g., C++ runtime
                    // functions like wstring methods that are imported but never called).
                    // If actually called at runtime, this will throw.
                    unresolvedFuncs.add(imp.name);
                    importObj.env[imp.name] = () => {
                        throw new Error(`Extension "${descriptor.name}" called unresolved symbol: env.${imp.name}`);
                    };
                }
            }
            else if (imp.kind === 'global') {
                // Other globals - try to resolve from main exports
                const resolved = mainExports[imp.name];
                if (resolved instanceof WebAssembly.Global) {
                    importObj.env[imp.name] = resolved;
                }
                else {
                    // Create a zero-initialized mutable global as fallback
                    importObj.env[imp.name] = new WebAssembly.Global({ value: 'i32', mutable: true }, 0);
                }
            }
        }
        else if (imp.module === 'GOT.mem' && imp.kind === 'global') {
            // GOT.mem entries are mutable globals containing memory addresses of symbols
            // Try to resolve the symbol's address - for now, create mutable globals
            // that can be patched by __wasm_apply_data_relocs
            importObj['GOT.mem'][imp.name] = new WebAssembly.Global({ value: 'i32', mutable: true }, 0);
        }
        else if (imp.module === 'GOT.func' && imp.kind === 'global') {
            // GOT.func entries are mutable globals containing table indices of functions.
            // We resolve these by finding the function in the main module's exports,
            // adding it to the indirect function table, and providing the table index.
            const resolved = mainExports[imp.name];
            if (resolved && typeof resolved === 'function') {
                const idx = table.length;
                table.grow(1);
                table.set(idx, resolved);
                importObj['GOT.func'][imp.name] = new WebAssembly.Global({ value: 'i32', mutable: true }, idx);
            }
            else {
                importObj['GOT.func'][imp.name] = new WebAssembly.Global({ value: 'i32', mutable: true }, 0);
            }
        }
    }
    // Self-resolve: in WASM shared libraries, the linker with --allow-undefined
    // may leave symbols as both imports and exports (e.g., C++ weak symbols from
    // libc++ string.cpp.o that satisfy references from ada.o). We use indirection
    // through mutable wrapper functions: first create wrappers that initially trap,
    // then instantiate, then patch the wrappers to forward to the instance's own exports.
    // This way all internal calls go through the wrappers which point to the final exports.
    const selfResolvable = [...unresolvedFuncs].filter((name) => extExportNames.has(name));
    // For self-resolvable symbols, create mutable wrappers
    const wrappers = {};
    for (const name of selfResolvable) {
        const wrapper = { target: null };
        wrappers[name] = wrapper;
        // Replace the trap stub with a wrapper that forwards to the target
        importObj.env[name] = (...args) => {
            if (!wrapper.target) {
                throw new Error(`Extension "${descriptor.name}" called unresolved symbol during init: env.${name}`);
            }
            return wrapper.target(...args);
        };
    }
    const instance = await WebAssembly.instantiate(module, importObj);
    const extExports = instance.exports;
    // Patch wrappers to point to the instance's own exports
    for (const name of selfResolvable) {
        const selfExport = extExports[name];
        if (typeof selfExport === 'function') {
            wrappers[name].target = selfExport;
        }
    }
    // Apply data relocations if the extension has them
    if (typeof extExports.__wasm_apply_data_relocs === 'function') {
        extExports.__wasm_apply_data_relocs();
    }
    // Call constructors if present
    if (typeof extExports.__wasm_call_ctors === 'function') {
        extExports.__wasm_call_ctors();
    }
    const initFn = descriptor.initFn ?? `qjs_ext_${descriptor.name.replace(/-/g, '_')}_init`;
    const ext = {
        name: descriptor.name,
        module,
        instance,
        dylink,
        memoryBase,
        tableBase,
        initFn,
    };
    // Check for version reporting
    ext.versions = extractExtensionVersions(ext, memory);
    return ext;
}
/**
 * Call the extension's init function, passing the JSContext and JSRuntime
 * pointers from the main module.
 */
function initExtension(ext, mainExports) {
    const initFunc = ext.instance.exports[ext.initFn];
    if (typeof initFunc !== 'function') {
        throw new Error(`Extension "${ext.name}" does not export init function "${ext.initFn}"`);
    }
    // Get the JSContext and JSRuntime pointers from the main module
    const ctxPtr = mainExports.qjs_get_context_ptr();
    const rtPtr = mainExports.qjs_get_runtime_ptr();
    // Call the extension's init function: qjs_ext_xxx_init(ctx, rt)
    const result = initFunc(ctxPtr, rtPtr);
    if (result !== 0) {
        throw new Error(`Extension "${ext.name}" init function returned error code ${result}`);
    }
}
/**
 * Re-instantiate extensions for snapshot restore.
 *
 * During restore, we need to:
 * 1. Instantiate extension modules with the same memory/table bases
 * 2. Let them populate the function table (via elem segments and __wasm_apply_data_relocs)
 * 3. Do NOT call the init function (the state is already in the snapshot memory)
 *
 * This reconstructs the function table entries that extensions need, without
 * modifying linear memory (which will be overwritten by the snapshot).
 */
async function restoreExtensions(descriptors, extensionMeta, mainExports, wasiBuiltins, wasiUserOverrides, memoryProxy) {
    const loaded = [];
    for (const meta of extensionMeta) {
        // Find the descriptor for this extension
        const descriptor = descriptors.find((d) => d.name === meta.name);
        if (!descriptor) {
            throw new Error(`Extension "${meta.name}" required by snapshot but not provided`);
        }
        // Load with fixed bases
        const ext = await loadExtension(descriptor, mainExports, wasiBuiltins, wasiUserOverrides, memoryProxy, {
            memoryBase: meta.memoryBase,
            tableBase: meta.tableBase,
        });
        ext.initFn = meta.initFn;
        loaded.push(ext);
    }
    return loaded;
}

// Auto-synced with package.json version. Do not edit manually.
const VERSION = "3.6.2";

/**
 * QuickJS WASM - A snapshotable JavaScript runtime via WebAssembly.
 *
 * Provides a clean JavaScript API for running sandboxed JS code in a QuickJS
 * VM compiled to WASM. The key differentiator is the ability to snapshot the
 * entire VM state (including pending promises) and restore it in a fresh
 * WASM instance.
 */
var __addDisposableResource = (undefined && undefined.__addDisposableResource) || function (env, value, async) {
    if (value !== null && value !== void 0) {
        if (typeof value !== "object" && typeof value !== "function") throw new TypeError("Object expected.");
        var dispose, inner;
        if (async) {
            if (!Symbol.asyncDispose) throw new TypeError("Symbol.asyncDispose is not defined.");
            dispose = value[Symbol.asyncDispose];
        }
        if (dispose === void 0) {
            if (!Symbol.dispose) throw new TypeError("Symbol.dispose is not defined.");
            dispose = value[Symbol.dispose];
            if (async) inner = dispose;
        }
        if (typeof dispose !== "function") throw new TypeError("Object not disposable.");
        if (inner) dispose = function() { try { inner.call(this); } catch (e) { return Promise.reject(e); } };
        env.stack.push({ value: value, dispose: dispose, async: async });
    }
    else if (async) {
        env.stack.push({ async: true });
    }
    return value;
};
var __disposeResources = (undefined && undefined.__disposeResources) || (function (SuppressedError) {
    return function (env) {
        function fail(e) {
            env.error = env.hasError ? new SuppressedError(e, env.error, "An error was suppressed during disposal.") : e;
            env.hasError = true;
        }
        var r, s = 0;
        function next() {
            while (r = env.stack.pop()) {
                try {
                    if (!r.async && s === 1) return s = 0, env.stack.push(r), Promise.resolve().then(next);
                    if (r.dispose) {
                        var result = r.dispose.call(r.value);
                        if (r.async) return s |= 2, Promise.resolve(result).then(next, function(e) { fail(e); return next(); });
                    }
                    else s |= 1;
                }
                catch (e) {
                    fail(e);
                }
            }
            if (s === 1) return env.hasError ? Promise.reject(env.error) : Promise.resolve();
            if (env.hasError) throw env.error;
        }
        return next();
    };
})(typeof SuppressedError === "function" ? SuppressedError : function (error, suppressed, message) {
    var e = new Error(message);
    return e.name = "SuppressedError", e.error = error, e.suppressed = suppressed, e;
});
// ---- Public types ----
/**
 * Largest supported QuickJS native stack limit for the shipped WASM binary.
 *
 * The binary has a 1 MiB linker-defined stack; reserving half of it leaves
 * headroom for native frames and stack-overflow exception handling.
 */
const MAX_STACK_SIZE = 512 * 1024;
/**
 * Intrinsic flags for `QuickJSOptions.intrinsics` controlling which
 * built-in JavaScript features are available in the VM.
 *
 * By default all intrinsics are enabled. Pass a bitmask of these flags
 * to create a minimal context. For example, omit `Intrinsics.EVAL` to
 * prevent `eval()` usage, or omit `Intrinsics.PROXY` to disallow `Proxy`.
 *
 * `BaseObjects` (Object, Array, Number, String, Boolean, Error, etc.)
 * is always included and cannot be disabled.
 */
const Intrinsics = {
    /** All intrinsics enabled (default). */
    ALL: 0xFFFFFFFF,
};
// ---- Snapshot serialization ----
/** Magic bytes: "QJSS" (QuickJS Snapshot) */
const SNAPSHOT_MAGIC = 0x514A5353;
/** Current serialization format version (2 = added extension metadata) */
const SNAPSHOT_VERSION = 2;
/**
 * Header layout (version 2):
 *   0-3:   Magic "QJSS" (u32 big-endian)
 *   4:     Version (u8)
 *   5-7:   Reserved (zero)
 *   8-11:  Memory size in bytes (u32 little-endian)
 *   12-15: Stack pointer (u32 little-endian)
 *   16-19: Runtime pointer (u32 little-endian)
 *   20-23: Context pointer (u32 little-endian)
 *   24-27: Extension count (u32 little-endian)
 *   28+:   Extension entries (variable length):
 *          nameLen(u32) + name(utf8) + memoryBase(u32) + tableBase(u32) + initFnLen(u32) + initFn(utf8)
 *   N+:    Memory data (N = memory size from offset 8)
 *
 * Version 1 (legacy): no extension metadata, memory starts at offset 24.
 */
const SNAPSHOT_HEADER_SIZE = 24;
// ---- QuickJS VM ----
class QuickJS {
    exports;
    module;
    instance;
    encoder = new TextEncoder();
    decoder = new TextDecoder();
    disposed = false;
    /** Registry of host callbacks, keyed by function name */
    hostCallbacks = new Map();
    /** Counter for internal-only callbacks (e.g. promise settle handlers) */
    nextInternalId = 1;
    interruptHandler = null;
    unhandledRejectionHandler = null;
    moduleNormalizeHandler = null;
    moduleLoadHandler = null;
    timezoneOffsetHandler = null;
    // Cached singleton handles
    _global = null;
    _versions = null;
    _undefined = null;
    _null = null;
    _true = null;
    _false = null;
    // Handles that must be freed on dispose (e.g. unresolved promise resolve/reject functions)
    _ownedHandles = new Set();
    /**
     * The innermost active `withScope()` batch, if any. New non-singleton
     * handles register themselves here so they can be freed together.
     * @internal
     */
    _activeScope = null;
    /** Loaded extensions in deterministic order */
    loadedExtensions = [];
    constructor(module) {
        this.module = module;
        this.instance = null;
        this.exports = null;
    }
    setInstance(instance) {
        this.instance = instance;
        this.exports = instance.exports;
    }
    // ---- Cached property accessors ----
    /**
     * Version information for the runtime and loaded native libraries.
     * Always includes `"quickjs-wasi"` (the npm package version) and
     * `"quickjs"` (the QuickJS engine version). Extensions may contribute
     * additional entries for their native dependencies (e.g. `"ada"`, `"mbedtls"`).
     */
    get versions() {
        this.assertNotDisposed();
        if (!this._versions) {
            const result = {
                'quickjs-wasi': VERSION,
                quickjs: this.readCString(this.exports.qjs_get_quickjs_version()),
            };
            for (const ext of this.loadedExtensions) {
                if (ext.versions) {
                    Object.assign(result, ext.versions);
                }
            }
            this._versions = result;
        }
        return this._versions;
    }
    /** The global object. Cached; do not dispose. */
    get global() {
        if (!this._global) {
            this._global = new JSValueHandle(this, this.exports.qjs_get_global(), true);
        }
        return this._global;
    }
    /** The undefined value. Cached; do not dispose. */
    get undefined() {
        if (!this._undefined) {
            this._undefined = new JSValueHandle(this, this.exports.qjs_get_undefined(), true);
        }
        return this._undefined;
    }
    /** The null value. Cached; do not dispose. */
    get null() {
        if (!this._null) {
            this._null = new JSValueHandle(this, this.exports.qjs_get_null(), true);
        }
        return this._null;
    }
    /** The true value. Cached; do not dispose. */
    get true() {
        if (!this._true) {
            this._true = new JSValueHandle(this, this.exports.qjs_get_true(), true);
        }
        return this._true;
    }
    /** The false value. Cached; do not dispose. */
    get false() {
        if (!this._false) {
            this._false = new JSValueHandle(this, this.exports.qjs_get_false(), true);
        }
        return this._false;
    }
    /**
     * Create a fresh QuickJS VM instance.
     *
     * @param options - Optional configuration. Can also pass raw WASM bytes
     *                  directly for backwards compatibility.
     */
    static async create(options) {
        const opts = QuickJS.normalizeOptions(options);
        const module = await QuickJS.resolveModule(opts.wasm);
        const vm = new QuickJS(module);
        const { instance, wasiBuiltins, wasiUserOverrides, memoryProxy } = await QuickJS.instantiate(module, vm, opts.wasi);
        vm.setInstance(instance);
        // Initialize the WASI reactor
        vm.exports._initialize();
        // Initialize QuickJS runtime and context
        const result = opts.intrinsics !== undefined
            ? vm.exports.qjs_init2(opts.intrinsics)
            : vm.exports.qjs_init();
        if (result !== 0) {
            throw new Error('Failed to initialize QuickJS runtime');
        }
        // Load and initialize extensions
        if (opts.extensions) {
            const mainExports = instance.exports;
            for (const desc of opts.extensions) {
                const ext = await loadExtension(desc, mainExports, wasiBuiltins, wasiUserOverrides, memoryProxy);
                vm.loadedExtensions.push(ext);
                initExtension(ext, mainExports);
            }
        }
        // Apply runtime limits
        QuickJS.applyLimits(vm, opts);
        return vm;
    }
    /**
     * Restore a QuickJS VM from a snapshot.
     *
     * @param snapshot - The snapshot to restore from.
     * @param options - Optional configuration. Can also pass raw WASM bytes
     *                  directly for backwards compatibility.
     */
    static async restore(snapshot, options) {
        const opts = QuickJS.normalizeOptions(options);
        const module = await QuickJS.resolveModule(opts.wasm);
        const vm = new QuickJS(module);
        const { instance, wasiBuiltins, wasiUserOverrides, memoryProxy } = await QuickJS.instantiate(module, vm, opts.wasi);
        vm.setInstance(instance);
        const mainExports = instance.exports;
        const exportedMemory = vm.exports.memory;
        // Grow memory FIRST: extensions need the memory to be large enough
        // for their __memory_base offsets (which were allocated in the original
        // larger memory during create()).
        const currentPages = exportedMemory.buffer.byteLength / 65536;
        const neededPages = Math.ceil(snapshot.memory.byteLength / 65536);
        if (neededPages > currentPages) {
            exportedMemory.grow(neededPages - currentPages);
        }
        // Re-instantiate extensions BEFORE overwriting memory.
        // This populates the indirect function table with the extension's
        // function pointers (via elem segments and __wasm_apply_data_relocs).
        // We use the exact same memory/table bases from the snapshot so that
        // function table indices match what the snapshotted QuickJS state expects.
        if (snapshot.extensions.length > 0) {
            const descriptors = opts.extensions ?? [];
            vm.loadedExtensions = await restoreExtensions(descriptors, snapshot.extensions, mainExports, wasiBuiltins, wasiUserOverrides, memoryProxy);
        }
        // Copy snapshot data into the module's own memory.
        // This overwrites EVERYTHING, including the regions that extensions
        // just initialized. That's correct because the snapshot already contains
        // the complete state including extension data.
        const dst = new Uint8Array(exportedMemory.buffer);
        dst.set(snapshot.memory);
        // Set runtime/context pointers (they already exist in the restored memory)
        vm.exports.qjs_set_runtime_and_context(snapshot.runtimePtr, snapshot.contextPtr);
        // Restore the stack pointer
        vm.exports.__stack_pointer.value = snapshot.stackPointer;
        // Apply runtime limits
        QuickJS.applyLimits(vm, opts);
        return vm;
    }
    // ---- Snapshot serialization ----
    /**
     * Serialize a snapshot to a binary buffer for persistent storage.
     *
     * The format includes a versioned header followed by the raw memory.
     * Apply your own compression (gzip, zstd, etc.) on top for smaller
     * storage. The memory compresses well due to its large zero regions.
     *
     * Format (version 1):
     * ```
     * Offset  Size  Field
     * 0       4     Magic: "QJSS" (0x514A5353, big-endian)
     * 4       1     Version: 1
     * 5       3     Reserved (zero)
     * 8       4     Memory size in bytes (u32 little-endian)
     * 12      4     Stack pointer (u32 little-endian)
     * 16      4     Runtime pointer (u32 little-endian)
     * 20      4     Context pointer (u32 little-endian)
     * 24      N     Memory data (N = memory size from offset 8)
     * ```
     */
    static serializeSnapshot(snapshot) {
        const textEncoder = new TextEncoder();
        // Calculate extension metadata size
        let extMetaSize = 4; // extCount (u32)
        const extEncodedNames = [];
        const extEncodedInitFns = [];
        for (const ext of snapshot.extensions) {
            const nameBytes = textEncoder.encode(ext.name);
            const initFnBytes = textEncoder.encode(ext.initFn);
            extEncodedNames.push(nameBytes);
            extEncodedInitFns.push(initFnBytes);
            extMetaSize += 4 + nameBytes.length + 4 + 4 + 4 + initFnBytes.length;
        }
        const totalSize = SNAPSHOT_HEADER_SIZE + extMetaSize + snapshot.memory.byteLength;
        const buffer = new ArrayBuffer(totalSize);
        const view = new DataView(buffer);
        const bytes = new Uint8Array(buffer);
        // Header
        view.setUint32(0, SNAPSHOT_MAGIC, false); // big-endian for readability in hex
        view.setUint8(4, SNAPSHOT_VERSION);
        // bytes 5-7 are reserved (already zero)
        view.setUint32(8, snapshot.memory.byteLength, true);
        view.setUint32(12, snapshot.stackPointer, true);
        view.setUint32(16, snapshot.runtimePtr, true);
        view.setUint32(20, snapshot.contextPtr, true);
        // Extension metadata (version 2)
        let offset = SNAPSHOT_HEADER_SIZE;
        view.setUint32(offset, snapshot.extensions.length, true);
        offset += 4;
        for (let i = 0; i < snapshot.extensions.length; i++) {
            const ext = snapshot.extensions[i];
            const nameBytes = extEncodedNames[i];
            const initFnBytes = extEncodedInitFns[i];
            view.setUint32(offset, nameBytes.length, true);
            offset += 4;
            bytes.set(nameBytes, offset);
            offset += nameBytes.length;
            view.setUint32(offset, ext.memoryBase, true);
            offset += 4;
            view.setUint32(offset, ext.tableBase, true);
            offset += 4;
            view.setUint32(offset, initFnBytes.length, true);
            offset += 4;
            bytes.set(initFnBytes, offset);
            offset += initFnBytes.length;
        }
        // Memory data
        bytes.set(snapshot.memory, offset);
        return bytes;
    }
    /**
     * Deserialize a snapshot from a binary buffer produced by `serializeSnapshot()`.
     */
    static deserializeSnapshot(data) {
        if (data.length < SNAPSHOT_HEADER_SIZE) {
            throw new Error('Invalid snapshot: too small');
        }
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        // Validate magic
        const magic = view.getUint32(0, false);
        if (magic !== SNAPSHOT_MAGIC) {
            throw new Error(`Invalid snapshot: bad magic (expected 0x${SNAPSHOT_MAGIC.toString(16)}, got 0x${magic.toString(16)})`);
        }
        // Validate version
        const version = view.getUint8(4);
        if (version !== SNAPSHOT_VERSION && version !== 1) {
            throw new Error(`Unsupported snapshot version: ${version} (expected ${SNAPSHOT_VERSION})`);
        }
        const memorySize = view.getUint32(8, true);
        const stackPointer = view.getUint32(12, true);
        const runtimePtr = view.getUint32(16, true);
        const contextPtr = view.getUint32(20, true);
        let extensions = [];
        let memoryOffset = SNAPSHOT_HEADER_SIZE;
        if (version >= 2) {
            // Version 2 adds extension metadata between the header and the memory data
            const extCount = view.getUint32(24, true);
            let offset = 28;
            const textDecoder = new TextDecoder();
            for (let i = 0; i < extCount; i++) {
                // name length (u32) + name (utf8) + memoryBase (u32) + tableBase (u32) + initFn length (u32) + initFn (utf8)
                const nameLen = view.getUint32(offset, true);
                offset += 4;
                const name = textDecoder.decode(data.slice(offset, offset + nameLen));
                offset += nameLen;
                const memBase = view.getUint32(offset, true);
                offset += 4;
                const tblBase = view.getUint32(offset, true);
                offset += 4;
                const initFnLen = view.getUint32(offset, true);
                offset += 4;
                const initFn = textDecoder.decode(data.slice(offset, offset + initFnLen));
                offset += initFnLen;
                extensions.push({ name, memoryBase: memBase, tableBase: tblBase, initFn });
            }
            memoryOffset = offset;
        }
        const expectedSize = memoryOffset + memorySize;
        if (data.length < expectedSize) {
            throw new Error(`Invalid snapshot: expected ${expectedSize} bytes, got ${data.length}`);
        }
        const memory = data.slice(memoryOffset, memoryOffset + memorySize);
        return { memory, stackPointer, runtimePtr, contextPtr, extensions };
    }
    // ---- Internal instantiation helpers ----
    static normalizeOptions(options) {
        if (!options) {
            // resolveModule() will throw a helpful error.
            return { wasm: undefined };
        }
        if (options instanceof WebAssembly.Module)
            return { wasm: options };
        if (typeof options === 'object' && ('wasm' in options || 'wasi' in options || 'memoryLimit' in options || 'maxStackSize' in options || 'interruptHandler' in options || 'onUnhandledRejection' in options || 'moduleLoader' in options || 'intrinsics' in options || 'extensions' in options || 'timezoneOffset' in options)) {
            const opts = options;
            if (opts.maxStackSize !== undefined &&
                (!Number.isInteger(opts.maxStackSize) ||
                    opts.maxStackSize < 0 ||
                    opts.maxStackSize > MAX_STACK_SIZE)) {
                throw new RangeError(`maxStackSize must be an integer between 0 and ${MAX_STACK_SIZE}`);
            }
            return opts;
        }
        // BufferSource (ArrayBuffer or ArrayBufferView)
        return { wasm: options };
    }
    static applyLimits(vm, opts) {
        if (opts.memoryLimit !== undefined) {
            vm.exports.qjs_set_memory_limit(opts.memoryLimit);
        }
        if (opts.maxStackSize !== undefined) {
            vm.exports.qjs_set_max_stack_size(opts.maxStackSize);
        }
        if (opts.interruptHandler) {
            vm.interruptHandler = opts.interruptHandler;
            vm.exports.qjs_set_interrupt_handler(1);
        }
        if (opts.onUnhandledRejection) {
            vm.unhandledRejectionHandler = opts.onUnhandledRejection;
            vm.exports.qjs_set_promise_rejection_handler(1);
        }
        if (opts.moduleLoader) {
            vm.moduleLoadHandler = opts.moduleLoader.load;
            vm.moduleNormalizeHandler = opts.moduleLoader.normalize ?? null;
            vm.exports.qjs_set_module_loader(1);
        }
        // Configure timezone handler.
        // The internal handler always returns the UTC offset in *seconds*
        // (positive east of UTC), which is what libc's __secs_to_zone expects.
        const tz = opts.timezoneOffset;
        if (typeof tz === 'function') {
            // User callback returns minutes (getTimezoneOffset convention:
            // positive west of UTC). Convert to seconds with sign flip.
            vm.timezoneOffsetHandler = (timeSecs) => -tz(timeSecs) * 60;
        }
        else if (typeof tz === 'number') {
            // Fixed offset in minutes, convert to seconds with sign flip.
            const offsetSecs = -tz * 60;
            vm.timezoneOffsetHandler = () => offsetSecs;
        }
        else {
            // 'host' (default): use the host's timezone
            vm.timezoneOffsetHandler = (timeSecs) => {
                return -new Date(timeSecs * 1000).getTimezoneOffset() * 60;
            };
        }
    }
    static async resolveModule(wasmInput) {
        if (wasmInput instanceof WebAssembly.Module) {
            return wasmInput;
        }
        if (wasmInput) {
            return WebAssembly.compile(wasmInput);
        }
        throw new TypeError('QuickJS: `wasm` option is required. Provide WASM bytes or a compiled ' +
            '`WebAssembly.Module`. The binary is shipped at `quickjs-wasi/quickjs.wasm` ' +
            'and can be loaded via your environment\'s preferred mechanism (e.g. ' +
            "`fetch()`, `node:fs/promises`, or a bundler import like Vite's `?url`).");
    }
    static async instantiate(module, vm, wasiOptions) {
        let memory = null;
        // Create a memory proxy that defers to the actual memory once set.
        // This allows WASI override factories to close over the memory reference
        // before the WASM instance is created.
        const memoryProxy = new Proxy({}, {
            get(_target, prop) {
                return memory[prop];
            },
        });
        // Build the builtins (no user overrides)
        const wasiBuiltins = createWasiShim(() => memory);
        // Resolve user overrides via factory
        const wasiUserOverrides = wasiOptions ? wasiOptions(memoryProxy) : undefined;
        // Final shim for the main module: builtins + user overrides
        const wasiShim = { ...wasiBuiltins, ...wasiUserOverrides };
        const hostCall = (namePtr, nameLen, thisPtr, argc, argvPtr) => {
            return vm.handleHostCall(namePtr, nameLen, thisPtr, argc, argvPtr);
        };
        const hostInterrupt = () => {
            return vm.interruptHandler ? (vm.interruptHandler() ? 1 : 0) : 0;
        };
        const hostPromiseRejection = (promisePtr, reasonPtr, isHandled) => {
            if (!vm.unhandledRejectionHandler) {
                // No handler registered; free the heap-allocated values
                vm.exports.qjs_free_value(promisePtr);
                vm.exports.qjs_free_value(reasonPtr);
                return;
            }
            const promise = new JSValueHandle(vm, promisePtr);
            const reason = new JSValueHandle(vm, reasonPtr);
            try {
                vm.unhandledRejectionHandler(promise, reason, isHandled !== 0);
            }
            finally {
                promise.dispose();
                reason.dispose();
            }
        };
        // Throw a host-side error into the QuickJS context so module loader
        // failures surface with their real message instead of the generic
        // "could not load module" error.
        const throwIntoContext = (err) => {
            const errHandle = vm.newError(err instanceof Error ? err : String(err));
            vm.exports.qjs_throw(errHandle.ptr);
            errHandle.dispose();
        };
        // Guard against async (or otherwise non-string-returning) module loader
        // callbacks. The WASM boundary is synchronous (a Promise cannot be
        // awaited here), so fail with a clear error instead of coercing the
        // Promise to source text.
        const assertSyncString = (value, callbackName) => {
            if (typeof value === 'string')
                return value;
            const got = value !== null && typeof value === 'object' && typeof value.then === 'function'
                ? 'a Promise'
                : `type ${typeof value}`;
            throw new TypeError(`moduleLoader.${callbackName} must synchronously return a string (got ${got}). ` +
                `Async module loading is not supported. Pre-fetch module sources instead ` +
                `(see the "ES Modules" section of the quickjs-wasi README).`);
        };
        // Module normalizer: resolve a specifier relative to a base name.
        // Returns a malloc'd null-terminated string in WASM memory, or 0 (NULL) on error.
        const hostModuleNormalize = (baseNamePtr, namePtr) => {
            if (!vm.moduleNormalizeHandler) {
                // No normalize handler; return a copy of the specifier as-is
                const name = vm.readCString(namePtr);
                return vm.writeString(name).ptr;
            }
            const baseName = vm.readCString(baseNamePtr);
            const specifier = vm.readCString(namePtr);
            try {
                const normalized = assertSyncString(vm.moduleNormalizeHandler(baseName, specifier), 'normalize');
                return vm.writeString(normalized).ptr;
            }
            catch (err) {
                throwIntoContext(err);
                return 0;
            }
        };
        // Module loader: return source code for a module.
        // Returns a malloc'd string pointer, writes length to *outLenPtr.
        const hostModuleLoad = (namePtr, outLenPtr) => {
            if (!vm.moduleLoadHandler)
                return 0;
            const name = vm.readCString(namePtr);
            try {
                const source = assertSyncString(vm.moduleLoadHandler(name), 'load');
                const { ptr, len } = vm.writeString(source);
                new Uint32Array(vm.exports.memory.buffer, outLenPtr, 1)[0] = len;
                return ptr;
            }
            catch (err) {
                throwIntoContext(err);
                return 0;
            }
        };
        // host_get_timezone_offset receives time as split i32 (hi, lo) and
        // returns the UTC offset in seconds.
        const hostGetTimezoneOffset = (hi, lo) => {
            const timeSecs = Number((BigInt(hi) << 32n) | BigInt(lo >>> 0));
            return vm.timezoneOffsetHandler ? vm.timezoneOffsetHandler(timeSecs) : 0;
        };
        const instance = await WebAssembly.instantiate(module, {
            env: {
                host_call: hostCall,
                host_interrupt: hostInterrupt,
                host_promise_rejection: hostPromiseRejection,
                host_module_normalize: hostModuleNormalize,
                host_module_load: hostModuleLoad,
                host_get_timezone_offset: hostGetTimezoneOffset,
            },
            wasi_snapshot_preview1: wasiShim,
        });
        memory = instance.exports.memory;
        return { instance, wasiBuiltins, wasiUserOverrides, memoryProxy };
    }
    /**
     * Called from WASM when a host function is invoked from QuickJS code.
     */
    handleHostCall(namePtr, nameLen, thisPtr, argc, argvPtr) {
        const name = this.decoder.decode(new Uint8Array(this.exports.memory.buffer, namePtr, nameLen));
        const callback = this.hostCallbacks.get(name);
        if (!callback) {
            // Throw inside the guest, as the docs promise: `newEphemeralFunction`
            // ("calling it after the handle is disposed throws, because the
            // callback is gone") and `unregisterHostCallback` ("any QuickJS
            // function still referencing the name will throw when called").
            // Silently returning `undefined` here masked real bugs, e.g. a
            // snapshot-restored VM calling a host function that was never
            // re-registered would corrupt results instead of failing loud.
            // Guest code can catch this like any other error.
            // A string (not a host Error object): newError copies an Error's
            // host .stack into the guest, which would leak host file paths into
            // guest-observable space and shadow any guest backtrace. This error
            // is library-generated; there is no host stack worth preserving.
            const errHandle = this.newError(`Host callback "${name}" is not registered: it was unregistered, ` +
                'its ephemeral function handle was disposed, or it was never ' +
                're-registered after a snapshot restore.');
            this.exports.qjs_throw(errHandle.ptr);
            errHandle.dispose();
            return 0;
        }
        // `thisPtr` and the argv entries are OWNED BY THE C TRAMPOLINE, which
        // frees them after this call returns. Wrap them as borrowed handles:
        // dispose() is a no-op and they are exempt from `withScope()`
        // tracking: a scope active around guest execution (e.g. a host
        // serializer driving a `forEach` visitor) must not free them at its
        // boundary, which would double-free the guest values and corrupt the
        // heap. Callbacks retain arguments past their invocation via `dup()`.
        const thisHandle = new JSValueHandle(this, thisPtr, false, true);
        const args = [];
        if (argc > 0 && argvPtr !== 0) {
            const view = new DataView(this.exports.memory.buffer);
            for (let i = 0; i < argc; i++) {
                const argPtr = view.getUint32(argvPtr + i * 4, true);
                args.push(new JSValueHandle(this, argPtr, false, true));
            }
        }
        try {
            const result = callback.call(thisHandle, ...args);
            return this.exports.qjs_dup_value(result.ptr);
        }
        catch (err) {
            // Throw an exception inside QuickJS and return NULL to signal
            // to the C trampoline that an exception was thrown.
            const errHandle = this.newError(err instanceof Error ? err : String(err));
            this.exports.qjs_throw(errHandle.ptr);
            errHandle.dispose();
            return 0;
        }
    }
    // ---- String helpers ----
    /** Write a JS string into WASM memory, returning the pointer. Caller must free. */
    writeString(str) {
        // WTF-8 (not plain TextEncoder): lone surrogates in the input must
        // reach the guest intact: quickjs's decoder accepts the 3-byte
        // surrogate sequences, so a JS string round-trips exactly.
        const encoded = encodeWtf8(str);
        const ptr = this.exports.wasm_malloc(encoded.length + 1);
        if (ptr === 0)
            throw new Error('wasm_malloc failed');
        const mem = new Uint8Array(this.exports.memory.buffer);
        mem.set(encoded, ptr);
        mem[ptr + encoded.length] = 0;
        return { ptr, len: encoded.length };
    }
    /** Read a null-terminated C string from WASM memory */
    readCString(ptr) {
        const mem = new Uint8Array(this.exports.memory.buffer);
        let end = ptr;
        while (mem[end] !== 0)
            end++;
        return this.decoder.decode(mem.slice(ptr, end));
    }
    // ---- Public API ----
    /**
     * Check if a result handle is an exception and throw a JSException if so.
     * Used internally by evalCode and callFunction.
     */
    throwIfException(result) {
        if (this.exports.qjs_is_exception(result.ptr) !== 0) {
            const exc = this.getException();
            result.dispose();
            // Track the handle so it gets cleaned up if the VM is disposed
            // before the caller disposes the exception.
            this._ownedHandles.add(exc);
            throw new JSException(exc);
        }
        return result;
    }
    /**
     * Evaluate JavaScript code and return the result as a handle.
     * If the code throws, a `JSException` (which extends `Error`) is thrown
     * on the host side, matching standard JavaScript semantics.
     *
     * @param code - The JavaScript source code to evaluate.
     * @param filename - Optional filename for error stack traces (default `'<eval>'`).
     * @param flags - Optional bitwise OR of `EvalFlags.*` constants.
     *   For example, pass `EvalFlags.ASYNC` to allow top-level `await`; the
     *   returned handle will be a Promise that resolves to the completion value.
     *   With `EvalFlags.TYPE_MODULE` the returned handle is a Promise that
     *   resolves to the module's namespace object (its exports).
     */
    evalCode(code, filename = '<eval>', flags = 0) {
        this.assertNotDisposed();
        const codeStr = this.writeString(code);
        const fnStr = this.writeString(filename);
        const resultPtr = this.exports.qjs_eval(codeStr.ptr, codeStr.len, fnStr.ptr, flags);
        this.exports.wasm_free(codeStr.ptr);
        this.exports.wasm_free(fnStr.ptr);
        return this.throwIfException(new JSValueHandle(this, resultPtr));
    }
    /**
     * Compile JavaScript source code to bytecode without executing it.
     * The returned `Uint8Array` can be stored, transferred, or later executed
     * with `evalBytecode()`.
     *
     * @param code - The JavaScript source code to compile.
     * @param filename - Optional filename for error stack traces (default `'<compile>'`).
     * @param evalFlags - Optional bitwise OR of `EvalFlags.*` constants.
     *   Use `EvalFlags.TYPE_MODULE` to compile as a module.
     * @param compileFlags - Optional bitwise OR of `CompileFlags.*` constants.
     *   Use `CompileFlags.STRIP_SOURCE` and/or `CompileFlags.STRIP_DEBUG` to
     *   reduce bytecode size.
     */
    compile(code, filename = '<compile>', evalFlags = 0, compileFlags = 0) {
        this.assertNotDisposed();
        const codeStr = this.writeString(code);
        const fnStr = this.writeString(filename);
        // Allocate space for the output length (size_t = 4 bytes in wasm32)
        const outLenPtr = this.exports.wasm_malloc(4);
        const bufPtr = this.exports.qjs_compile(codeStr.ptr, codeStr.len, fnStr.ptr, evalFlags, compileFlags, outLenPtr);
        this.exports.wasm_free(codeStr.ptr);
        this.exports.wasm_free(fnStr.ptr);
        if (bufPtr === 0) {
            this.exports.wasm_free(outLenPtr);
            // Compilation failed; throw the QuickJS exception
            const exc = this.getException();
            throw new Error(`Compilation error: ${exc.toString()}`);
        }
        const outLen = new Uint32Array(this.exports.memory.buffer, outLenPtr, 1)[0];
        this.exports.wasm_free(outLenPtr);
        // Copy the bytecode out of WASM memory before freeing
        const bytecode = new Uint8Array(this.exports.memory.buffer, bufPtr, outLen).slice();
        this.exports.wasm_free(bufPtr);
        return bytecode;
    }
    /**
     * Execute previously compiled bytecode (from `compile()`).
     * Returns the evaluation result as a handle.
     *
     * For module bytecode (compiled with `EvalFlags.TYPE_MODULE`), the
     * returned handle is a Promise that resolves to the module's namespace
     * object (its exports).
     *
     * @param bytecode - The bytecode `Uint8Array` from `compile()`.
     */
    evalBytecode(bytecode) {
        this.assertNotDisposed();
        const bufPtr = this.exports.wasm_malloc(bytecode.byteLength);
        new Uint8Array(this.exports.memory.buffer, bufPtr, bytecode.byteLength).set(bytecode);
        const resultPtr = this.exports.qjs_eval_bytecode(bufPtr, bytecode.byteLength);
        this.exports.wasm_free(bufPtr);
        return this.throwIfException(new JSValueHandle(this, resultPtr));
    }
    /**
     * Execute all pending microtask jobs (promise reactions, etc.)
     * Returns the number of jobs executed.
     */
    executePendingJobs() {
        this.assertNotDisposed();
        let count = 0;
        while (this.exports.qjs_is_job_pending()) {
            const result = this.exports.qjs_execute_pending_job();
            if (result < 0) {
                const exc = this.getException();
                throw new Error(`Job execution error: ${exc.toString()}`);
            }
            count++;
        }
        return count;
    }
    /**
     * Explicitly trigger garbage collection. QuickJS runs GC automatically,
     * but this can be useful to reclaim memory at a known point or before
     * taking a snapshot.
     */
    runGC() {
        this.assertNotDisposed();
        this.exports.qjs_run_gc();
    }
    /**
     * The GC threshold in bytes. When allocated memory exceeds this value,
     * garbage collection is triggered automatically. Set to 0 to disable
     * automatic GC.
     */
    get gcThreshold() {
        this.assertNotDisposed();
        return this.exports.qjs_get_gc_threshold();
    }
    set gcThreshold(threshold) {
        this.assertNotDisposed();
        this.exports.qjs_set_gc_threshold(threshold);
    }
    /**
     * Get detailed memory usage statistics from the QuickJS runtime.
     * Returns counts and sizes for atoms, strings, objects, functions, etc.
     */
    getMemoryUsage() {
        this.assertNotDisposed();
        // Allocate a buffer for 26 int64 fields (26 * 8 = 208 bytes)
        const bufPtr = this.exports.wasm_malloc(26 * 8);
        this.exports.qjs_compute_memory_usage(bufPtr);
        const view = new BigInt64Array(this.exports.memory.buffer, bufPtr, 26);
        const result = {
            mallocSize: Number(view[0]),
            mallocLimit: Number(view[1]),
            memoryUsedSize: Number(view[2]),
            mallocCount: Number(view[3]),
            memoryUsedCount: Number(view[4]),
            atomCount: Number(view[5]),
            atomSize: Number(view[6]),
            strCount: Number(view[7]),
            strSize: Number(view[8]),
            objCount: Number(view[9]),
            objSize: Number(view[10]),
            propCount: Number(view[11]),
            propSize: Number(view[12]),
            shapeCount: Number(view[13]),
            shapeSize: Number(view[14]),
            jsFuncCount: Number(view[15]),
            jsFuncSize: Number(view[16]),
            jsFuncCodeSize: Number(view[17]),
            jsFuncPc2lineCount: Number(view[18]),
            jsFuncPc2lineSize: Number(view[19]),
            cFuncCount: Number(view[20]),
            arrayCount: Number(view[21]),
            fastArrayCount: Number(view[22]),
            fastArrayElements: Number(view[23]),
            binaryObjectCount: Number(view[24]),
            binaryObjectSize: Number(view[25]),
        };
        this.exports.wasm_free(bufPtr);
        return result;
    }
    /**
     * Get the global object. Prefer the cached `vm.global` property.
     */
    getGlobal() {
        this.assertNotDisposed();
        return new JSValueHandle(this, this.exports.qjs_get_global());
    }
    /**
     * Create a new QuickJS string value.
     */
    newString(str) {
        this.assertNotDisposed();
        const { ptr, len } = this.writeString(str);
        const resultPtr = this.exports.qjs_new_string(ptr, len);
        this.exports.wasm_free(ptr);
        return new JSValueHandle(this, resultPtr);
    }
    /**
     * Create a new QuickJS number value.
     */
    newNumber(num) {
        this.assertNotDisposed();
        return new JSValueHandle(this, this.exports.qjs_new_number(num));
    }
    /**
     * Create a new QuickJS BigInt value.
     */
    newBigInt(val) {
        this.assertNotDisposed();
        // Split the bigint into lo/hi 32-bit halves
        const lo = Number(val & 0xffffffffn);
        const hi = Number((val >> 32n) & 0xffffffffn);
        return new JSValueHandle(this, this.exports.qjs_new_big_int64(lo, hi));
    }
    /**
     * Create a new QuickJS object value.
     */
    newObject() {
        this.assertNotDisposed();
        return new JSValueHandle(this, this.exports.qjs_new_object());
    }
    /**
     * Create a new QuickJS array value.
     */
    newArray() {
        this.assertNotDisposed();
        return new JSValueHandle(this, this.exports.qjs_new_array());
    }
    /**
     * Create a global symbol (`Symbol.for(description)`).
     * Global symbols with the same description are always the same symbol,
     * even across snapshot/restore.
     */
    newSymbolFor(description) {
        this.assertNotDisposed();
        const { ptr, len } = this.writeString(description);
        const result = new JSValueHandle(this, this.exports.qjs_new_symbol(ptr, len, 1));
        this.exports.wasm_free(ptr);
        return result;
    }
    /**
     * Create a new QuickJS ArrayBuffer by copying data from a host buffer.
     */
    newArrayBuffer(data) {
        this.assertNotDisposed();
        const bytes = data instanceof ArrayBuffer ? new Uint8Array(data) : data;
        const ptr = this.exports.wasm_malloc(bytes.length);
        if (ptr === 0)
            throw new Error('wasm_malloc failed');
        new Uint8Array(this.exports.memory.buffer).set(bytes, ptr);
        const result = new JSValueHandle(this, this.exports.qjs_new_array_buffer(ptr, bytes.length));
        this.exports.wasm_free(ptr);
        return result;
    }
    /**
     * Create a new QuickJS Uint8Array by copying data from a host buffer.
     */
    newUint8Array(data) {
        this.assertNotDisposed();
        const ptr = this.exports.wasm_malloc(data.length);
        if (ptr === 0)
            throw new Error('wasm_malloc failed');
        new Uint8Array(this.exports.memory.buffer).set(data, ptr);
        const result = new JSValueHandle(this, this.exports.qjs_new_uint8_array(ptr, data.length));
        this.exports.wasm_free(ptr);
        return result;
    }
    /**
     * Get undefined. Prefer the cached `vm.undefined` property.
     */
    getUndefined() {
        this.assertNotDisposed();
        return new JSValueHandle(this, this.exports.qjs_get_undefined());
    }
    /**
     * Get null. Prefer the cached `vm.null` property.
     */
    getNull() {
        this.assertNotDisposed();
        return new JSValueHandle(this, this.exports.qjs_get_null());
    }
    /**
     * Get true. Prefer the cached `vm.true` property.
     */
    getTrue() {
        this.assertNotDisposed();
        return new JSValueHandle(this, this.exports.qjs_get_true());
    }
    /**
     * Get false. Prefer the cached `vm.false` property.
     */
    getFalse() {
        this.assertNotDisposed();
        return new JSValueHandle(this, this.exports.qjs_get_false());
    }
    /**
     * Create a new QuickJS function backed by a host callback.
     *
     * When the function is called inside QuickJS, the host callback is invoked
     * with the `this` value and arguments as JSValueHandles.
     */
    newFunction(name, fn) {
        this.assertNotDisposed();
        if (this.hostCallbacks.has(name)) {
            throw new Error(`Host callback with name "${name}" is already registered`);
        }
        this.hostCallbacks.set(name, fn);
        const { ptr: namePtr, len: nameLen } = this.writeString(name);
        const resultPtr = this.exports.qjs_new_host_function(namePtr, nameLen, 0);
        this.exports.wasm_free(namePtr);
        return new JSValueHandle(this, resultPtr);
    }
    /**
     * Run `fn` with a handle scope: every handle created during the call is
     * disposed when it returns, except those passed to `scope.escape()`.
     *
     * This is the bulk alternative to disposing handles individually, for code
     * that creates many intermediates, such as walking a large value:
     *
     * ```ts
     * const name = vm.withScope((scope) => {
     *   const user = root.getProp('user');       // freed automatically
     *   const profile = user.getProp('profile'); // freed automatically
     *   return scope.escape(profile.getProp('name'));
     * });
     * ```
     *
     * Scopes nest: `escape()` transfers the handle to the enclosing scope when
     * there is one, so it is still cleaned up at the outer boundary.
     *
     * `fn` must be synchronous. Handles created after an `await` are outside
     * the scope, because it closes as soon as `fn` returns.
     *
     * Host callbacks are safe to trigger inside a scope: the `this`/argument
     * handles the trampoline passes to a callback wrap C-owned pointers and
     * are exempt from scope tracking (see `handleHostCall`), so the scope
     * frees only handles the host actually owns. Handles a callback CREATES
     * (including `dup()`s of its arguments) are tracked normally.
     */
    withScope(fn) {
        this.assertNotDisposed();
        const enclosing = this._activeScope;
        const tracked = new Set();
        this._activeScope = tracked;
        const scope = {
            escape: (handle) => {
                tracked.delete(handle);
                enclosing?.add(handle);
                return handle;
            },
        };
        try {
            return fn(scope);
        }
        finally {
            this._activeScope = enclosing;
            for (const handle of tracked)
                handle.dispose();
        }
    }
    /**
     * Export a handle as a snapshot-portable token.
     *
     * A handle's heap box lives in the VM's linear memory, so a
     * `snapshot()` taken while the handle is alive carries it, and a VM
     * restored from that snapshot has the identical box at the identical
     * offset. `importHandle(token)` on the restored VM (or on this VM)
     * re-materializes an owned handle for the same guest value without
     * evaluating any guest code.
     *
     * Contract:
     * - the handle must stay undisposed until after `snapshot()`; its
     *   box (and the reference it holds) must be part of the memory image;
     * - the token is only meaningful to THIS VM and VMs restored from a
     *   snapshot of it taken while the handle was alive;
     * - `importHandle` duplicates the underlying value (fresh reference,
     *   fresh box), so it can be called any number of times and each
     *   returned handle is independently owned and disposable. The
     *   exported box's own reference is intentionally never released on
     *   restored VMs (one retained reference per VM image, reclaimed
     *   with the VM).
     *
     * The intended use is boot-time capture: snapshot a VM after capturing
     * references to pristine intrinsics but BEFORE evaluating untrusted or
     * user code, then restore per task and import the captured handles,
     * guaranteeing the references predate anything user code patched,
     * without re-running capture code in the restored VM (where user-
     * patched globals could observe it). See vercel/workflow's host-side
     * serde for a worked example.
     */
    exportHandle(handle) {
        this.assertNotDisposed();
        if (handle.vm !== this) {
            throw new Error('exportHandle: handle belongs to a different VM');
        }
        if (handle.disposed) {
            throw new Error('exportHandle: handle is disposed');
        }
        if (handle._isBorrowed) {
            // Host-callback this/argument handles wrap boxes OWNED BY THE C
            // TRAMPOLINE, freed when the callback returns; a token minted
            // from one would point at freed memory in every restored VM.
            // Callbacks that need to persist an argument must dup() it first
            // (the duplicate is an owned box) and export the duplicate.
            throw new Error('exportHandle: cannot export a borrowed handle (host-callback ' +
                'this/argument); its box is freed when the callback returns. ' +
                'dup() it and export the duplicate.');
        }
        return handle.ptr;
    }
    /**
     * Re-materialize a handle from a token produced by `exportHandle`,
     * on this VM, or on a VM restored from a snapshot taken while the
     * exported handle was alive. Returns a NEW owned handle (the
     * underlying value's refcount is incremented); dispose it like any
     * other handle. See `exportHandle` for the full contract.
     */
    importHandle(token) {
        this.assertNotDisposed();
        // Best-effort validation before handing the value to qjs_dup_value,
        // which dereferences it as a raw JSValue* inside the WASM instance.
        // A malformed token (0, negative, fractional, out of address range)
        // would otherwise read arbitrary memory. A well-formed but FORGED
        // token remains undefined behavior: like any raw pointer, tokens
        // are only meaningful under the exportHandle contract.
        if (!Number.isInteger(token) ||
            token <= 0 ||
            token >= this.exports.memory.buffer.byteLength) {
            throw new Error(`importHandle: invalid token ${token}`);
        }
        return new JSValueHandle(this, this.exports.qjs_dup_value(token));
    }
    /**
     * Create a QuickJS function backed by a host callback whose registration is
     * tied to the returned handle: disposing the handle unregisters the
     * callback.
     *
     * Use this for short-lived callbacks (e.g. a visitor passed to
     * `Map.prototype.forEach`) where the name is an implementation detail.
     * `newFunction()` keeps its callback registered for the lifetime of the VM
     * (by design, so that names can be re-registered after a snapshot is
     * restored), which makes it unsuitable for callbacks created in a loop.
     *
     * The guest must not retain the function past disposal: calling it after
     * the handle is disposed throws, because the callback is gone. Ephemeral
     * functions do not survive snapshot/restore.
     */
    newEphemeralFunction(fn) {
        this.assertNotDisposed();
        const name = `__ephemeral:${this.nextInternalId++}`;
        this.hostCallbacks.set(name, fn);
        const { ptr: namePtr, len: nameLen } = this.writeString(name);
        const resultPtr = this.exports.qjs_new_host_function(namePtr, nameLen, 0);
        this.exports.wasm_free(namePtr);
        const handle = new JSValueHandle(this, resultPtr);
        handle._onDispose = () => {
            this.hostCallbacks.delete(name);
        };
        return handle;
    }
    /**
     * Remove a host callback registered with `newFunction()` or
     * `registerHostCallback()`. Returns true if a callback was removed.
     *
     * Any QuickJS function still referencing the name will throw when called,
     * so only unregister once the guest can no longer reach it.
     */
    unregisterHostCallback(name) {
        return this.hostCallbacks.delete(name);
    }
    /**
     * Create an internal host function that bypasses the duplicate-name check.
     * Used for ephemeral callbacks (promise settle handlers, resolvePromise, etc.)
     * that are not intended to survive snapshot/restore.
     */
    newInternalFunction(name, fn) {
        this.hostCallbacks.set(name, fn);
        const { ptr: namePtr, len: nameLen } = this.writeString(name);
        const resultPtr = this.exports.qjs_new_host_function(namePtr, nameLen, 0);
        this.exports.wasm_free(namePtr);
        return new JSValueHandle(this, resultPtr);
    }
    /**
     * Create a new promise.
     *
     * Returns a Deferred with:
     * - `handle` - the QuickJS promise object
     * - `settled` - a host Promise that resolves when the QuickJS promise settles
     * - `resolve(value)` - resolve the promise with a QuickJS value
     * - `reject(value)` - reject the promise with a QuickJS value
     */
    newPromise() {
        this.assertNotDisposed();
        const resolveOutPtr = this.exports.wasm_malloc(4);
        const rejectOutPtr = this.exports.wasm_malloc(4);
        const promisePtr = this.exports.qjs_new_promise(resolveOutPtr, rejectOutPtr);
        const view = new DataView(this.exports.memory.buffer);
        const resolvePtr = view.getUint32(resolveOutPtr, true);
        const rejectPtr = view.getUint32(rejectOutPtr, true);
        this.exports.wasm_free(resolveOutPtr);
        this.exports.wasm_free(rejectOutPtr);
        const promiseHandle = new JSValueHandle(this, promisePtr);
        const resolveHandle = new JSValueHandle(this, resolvePtr);
        const rejectHandle = new JSValueHandle(this, rejectPtr);
        const vm = this;
        // Track resolve/reject handles so they can be freed on VM dispose
        // if the promise is never resolved/rejected
        vm._ownedHandles.add(resolveHandle);
        vm._ownedHandles.add(rejectHandle);
        // Lazily-created settled promise: only attaches .then() handler when accessed
        let _settled = null;
        return {
            handle: promiseHandle,
            get settled() {
                if (!_settled) {
                    let settledResolve;
                    _settled = new Promise((res) => {
                        settledResolve = res;
                    });
                    const settleName = `__settle:${vm.nextInternalId++}`;
                    const onSettleFn = vm.newInternalFunction(settleName, () => {
                        settledResolve();
                        vm.hostCallbacks.delete(settleName);
                        return vm.undefined;
                    });
                    vm.promiseThenRaw(promiseHandle, onSettleFn, onSettleFn).dispose();
                    onSettleFn.dispose();
                }
                return _settled;
            },
            resolve(value) {
                vm.callFunctionRaw(resolveHandle, vm.undefined, value).dispose();
                vm._ownedHandles.delete(resolveHandle);
                resolveHandle.dispose();
            },
            reject(value) {
                vm.callFunctionRaw(rejectHandle, vm.undefined, value).dispose();
                vm._ownedHandles.delete(rejectHandle);
                rejectHandle.dispose();
            },
        };
    }
    /**
     * Resolve a promise handle. Returns a host-side Promise that resolves
     * with the settled value/error of the QuickJS promise.
     *
     * If the handle is not a promise, it is treated as an already-fulfilled value.
     *
     * The returned host Promise resolves to `{ value: JSValueHandle }` on
     * fulfillment or `{ error: JSValueHandle }` on rejection.
     */
    resolvePromise(promiseHandle) {
        this.assertNotDisposed();
        // If the handle is not a promise, treat it as a fulfilled value
        if (!this.exports.qjs_is_promise(promiseHandle.ptr)) {
            return Promise.resolve({ value: promiseHandle.dup() });
        }
        // Check if already settled
        const state = this.exports.qjs_promise_state(promiseHandle.ptr);
        if (state === 1) {
            // fulfilled
            return Promise.resolve({ value: new JSValueHandle(this, this.exports.qjs_promise_result(promiseHandle.ptr)) });
        }
        else if (state === 2) {
            // rejected
            return Promise.resolve({ error: new JSValueHandle(this, this.exports.qjs_promise_result(promiseHandle.ptr)) });
        }
        // Pending: attach a .then/.catch to get notified
        return new Promise((hostResolve) => {
            const id = this.nextInternalId++;
            const fulfilledName = `__onFulfilled:${id}`;
            const rejectedName = `__onRejected:${id}`;
            const onFulfilled = this.newInternalFunction(fulfilledName, (...args) => {
                const val = args[0]?.dup() ?? this.undefined;
                this.hostCallbacks.delete(fulfilledName);
                this.hostCallbacks.delete(rejectedName);
                hostResolve({ value: val });
                return this.undefined;
            });
            const onRejected = this.newInternalFunction(rejectedName, (...args) => {
                const val = args[0]?.dup() ?? this.undefined;
                this.hostCallbacks.delete(fulfilledName);
                this.hostCallbacks.delete(rejectedName);
                hostResolve({ error: val });
                return this.undefined;
            });
            // Subscribe via the engine-level primitive: JS_PromiseThen does not
            // consult Promise.prototype.then or Symbol.species, so guest code
            // that patches either cannot intercept the subscription (or run at
            // all during it).
            this.promiseThenRaw(promiseHandle, onFulfilled, onRejected).dispose();
            onFulfilled.dispose();
            onRejected.dispose();
        });
    }
    /**
     * Subscribe to a promise without executing guest code, via quickjs-ng's
     * JS_PromiseThen: no Promise.prototype.then lookup, no Symbol.species.
     * Returns the chained promise. Handler handles are borrowed (caller
     * still owns and disposes them).
     * @internal
     */
    promiseThenRaw(promise, onFulfilled, onRejected) {
        return new JSValueHandle(this, this.exports.qjs_promise_then(promise.ptr, onFulfilled.ptr, onRejected.ptr));
    }
    /**
     * Mark a promise as handled: an eventual (or already-recorded) rejection
     * will not be reported to `onUnhandledRejection`. Useful when the host
     * observes a rejection through other means (e.g. `resolvePromise()`) and
     * wants to suppress the unhandled-rejection callback for it.
     *
     * No-op if the handle is not a promise.
     */
    markPromiseHandled(promise) {
        this.assertNotDisposed();
        this.exports.qjs_promise_mark_as_handled(promise.ptr);
    }
    /**
     * Call a QuickJS function. If the function throws, a `JSException`
     * is thrown on the host side.
     */
    callFunction(func, thisVal, ...args) {
        return this.throwIfException(this.callFunctionRaw(func, thisVal, ...args));
    }
    /**
     * Invoke a QuickJS constructor with `new`, i.e. `new ctor(...args)`.
     * If the constructor throws (including when `ctor` is not a constructor),
     * a `JSException` is thrown on the host side.
     *
     * This is the counterpart to `callFunction` for building values inside
     * the VM from the host, e.g. `new Date(iso)` on a constructor captured
     * before any user code ran.
     */
    construct(ctor, ...args) {
        this.assertNotDisposed();
        const argc = args.length;
        let argvPtr = 0;
        if (argc > 0) {
            argvPtr = this.exports.wasm_malloc(argc * 4);
            const view = new DataView(this.exports.memory.buffer);
            for (let i = 0; i < argc; i++) {
                view.setUint32(argvPtr + i * 4, args[i].ptr, true);
            }
        }
        const resultPtr = this.exports.qjs_call_constructor(ctor.ptr, argc, argvPtr);
        if (argvPtr)
            this.exports.wasm_free(argvPtr);
        return this.throwIfException(new JSValueHandle(this, resultPtr));
    }
    /**
     * Internal: call a QuickJS function without throwing on exception.
     * Used by promise plumbing where exceptions are handled differently.
     */
    callFunctionRaw(func, thisVal, ...args) {
        this.assertNotDisposed();
        const argc = args.length;
        let argvPtr = 0;
        if (argc > 0) {
            argvPtr = this.exports.wasm_malloc(argc * 4);
            const view = new DataView(this.exports.memory.buffer);
            for (let i = 0; i < argc; i++) {
                view.setUint32(argvPtr + i * 4, args[i].ptr, true);
            }
        }
        const resultPtr = this.exports.qjs_call(func.ptr, thisVal.ptr, argc, argvPtr);
        if (argvPtr)
            this.exports.wasm_free(argvPtr);
        return new JSValueHandle(this, resultPtr);
    }
    /**
     * Set a property on an object. Accepts string or JSValueHandle as key.
     * JSValueHandle keys support symbols (including `Symbol.for()`).
     */
    setProp(obj, key, value) {
        this.assertNotDisposed();
        if (typeof key === 'string') {
            const { ptr: namePtr } = this.writeString(key);
            this.exports.qjs_set_prop_string(obj.ptr, namePtr, value.ptr);
            this.exports.wasm_free(namePtr);
        }
        else {
            this.exports.qjs_set_prop_value(obj.ptr, key.ptr, value.ptr);
        }
    }
    /**
     * Define a property on an object with explicit property descriptor flags.
     * Unlike `setProp`, this allows controlling `writable`, `enumerable`, and
     * `configurable` attributes, matching `Object.defineProperty()` semantics.
     * Accepts string or JSValueHandle as key (JSValueHandle keys support symbols).
     *
     * All flags default to `false` when not specified.
     */
    defineProp(obj, key, value, descriptor) {
        this.assertNotDisposed();
        let flags = 0;
        if (descriptor?.configurable)
            flags |= 1; // JS_PROP_CONFIGURABLE
        if (descriptor?.writable)
            flags |= 2; // JS_PROP_WRITABLE
        if (descriptor?.enumerable)
            flags |= 4; // JS_PROP_ENUMERABLE
        if (typeof key === 'string') {
            const { ptr: namePtr } = this.writeString(key);
            this.exports.qjs_define_prop_string(obj.ptr, namePtr, value.ptr, flags);
            this.exports.wasm_free(namePtr);
        }
        else {
            this.exports.qjs_define_prop_value(obj.ptr, key.ptr, value.ptr, flags);
        }
    }
    /**
     * Get a property from an object using a JSValueHandle key.
     * Supports symbol keys (including `Symbol.for()`).
     */
    getProp(obj, key) {
        this.assertNotDisposed();
        return new JSValueHandle(this, this.exports.qjs_get_prop_value(obj.ptr, key.ptr));
    }
    /**
     * Get the current exception, if any.
     */
    getException() {
        this.assertNotDisposed();
        return new JSValueHandle(this, this.exports.qjs_get_exception());
    }
    /**
     * Create a new QuickJS Error object.
     * Accepts a string message or a native Error object.
     */
    newError(messageOrError) {
        this.assertNotDisposed();
        const errPtr = this.exports.qjs_new_error();
        const errHandle = new JSValueHandle(this, errPtr);
        if (typeof messageOrError === 'string') {
            const msgHandle = this.newString(messageOrError);
            errHandle.setProp('message', msgHandle);
            msgHandle.dispose();
        }
        else {
            const msgHandle = this.newString(messageOrError.message);
            errHandle.setProp('message', msgHandle);
            msgHandle.dispose();
            if (messageOrError.name) {
                const nameHandle = this.newString(messageOrError.name);
                errHandle.setProp('name', nameHandle);
                nameHandle.dispose();
            }
            if (messageOrError.stack) {
                const stackHandle = this.newString(messageOrError.stack);
                errHandle.setProp('stack', stackHandle);
                stackHandle.dispose();
            }
        }
        return errHandle;
    }
    /**
     * Get the typeof a handle as a string.
     */
    typeof(handle) {
        this.assertNotDisposed();
        const e = this.exports;
        if (e.qjs_is_undefined(handle.ptr))
            return 'undefined';
        if (e.qjs_is_null(handle.ptr))
            return 'object'; // typeof null === 'object'
        if (e.qjs_is_bool(handle.ptr))
            return 'boolean';
        if (e.qjs_is_number(handle.ptr))
            return 'number';
        if (e.qjs_is_big_int(handle.ptr))
            return 'bigint';
        if (e.qjs_is_string(handle.ptr))
            return 'string';
        if (e.qjs_is_symbol(handle.ptr))
            return 'symbol';
        if (e.qjs_is_function(handle.ptr))
            return 'function';
        if (e.qjs_is_object(handle.ptr))
            return 'object';
        return 'unknown';
    }
    /**
     * Convert a QuickJS handle to a host JavaScript value.
     * Handles strings, numbers, booleans, null, undefined, bigint, arrays,
     * errors, functions, and plain objects. Circular references in objects
     * are returned as `undefined`.
     */
    dump(handle) {
        this.assertNotDisposed();
        return this._dump(handle, new Map());
    }
    _dump(handle, visited) {
        const e = this.exports;
        if (e.qjs_is_undefined(handle.ptr))
            return undefined;
        if (e.qjs_is_null(handle.ptr))
            return null;
        if (e.qjs_is_bool(handle.ptr))
            return e.qjs_get_bool(handle.ptr) !== 0;
        if (e.qjs_is_number(handle.ptr))
            return e.qjs_get_float64(handle.ptr);
        if (e.qjs_is_string(handle.ptr))
            return handle.toString();
        if (e.qjs_is_big_int(handle.ptr))
            return handle.toBigInt();
        if (e.qjs_is_symbol(handle.ptr)) {
            const descOutPtr = e.wasm_malloc(4);
            const kind = e.qjs_get_symbol_description(handle.ptr, descOutPtr);
            const view = new DataView(e.memory.buffer);
            const descPtr = view.getUint32(descOutPtr, true);
            e.wasm_free(descOutPtr);
            if (kind === 1) {
                // Global symbol: reconstruct as Symbol.for(description)
                const descHandle = new JSValueHandle(this, descPtr);
                const description = descHandle.toString();
                descHandle.dispose();
                return Symbol.for(description);
            }
            else if (kind === 2) {
                // Local (anonymous) symbol: can't be reconstructed on host
                const descHandle = new JSValueHandle(this, descPtr);
                descHandle.dispose();
                return undefined;
            }
            return undefined;
        }
        if (e.qjs_is_array_buffer(handle.ptr))
            return handle.toArrayBuffer();
        if (e.qjs_is_exception(handle.ptr)) {
            const exc = this.getException();
            const msg = exc.toString();
            exc.dispose();
            return new Error(msg);
        }
        // Functions cannot be meaningfully serialized
        if (e.qjs_is_function(handle.ptr))
            return undefined;
        // Detect circular references using the underlying JS object pointer.
        // If we've already visited this object, return the same host object
        // (preserving the circular structure on the host side).
        if (e.qjs_is_object(handle.ptr)) {
            const objPtr = e.qjs_get_value_ptr(handle.ptr);
            if (objPtr) {
                const existing = visited.get(objPtr);
                if (existing !== undefined)
                    return existing;
            }
        }
        // Check for typed arrays (before the regular array check; typed arrays are not Array.isArray)
        if (e.qjs_is_object(handle.ptr)) {
            const byteOffsetPtr = e.wasm_malloc(4);
            const byteLengthPtr = e.wasm_malloc(4);
            const bytesPerElemPtr = e.wasm_malloc(4);
            const abPtr = e.qjs_get_typed_array_buffer(handle.ptr, byteOffsetPtr, byteLengthPtr, bytesPerElemPtr);
            const abHandle = new JSValueHandle(this, abPtr);
            if (e.qjs_is_exception(abHandle.ptr) === 0) {
                const view = new DataView(e.memory.buffer);
                const byteOffset = view.getUint32(byteOffsetPtr, true);
                const byteLength = view.getUint32(byteLengthPtr, true);
                const bytesPerElement = view.getUint32(bytesPerElemPtr, true);
                e.wasm_free(byteOffsetPtr);
                e.wasm_free(byteLengthPtr);
                e.wasm_free(bytesPerElemPtr);
                const abLenPtr = e.wasm_malloc(4);
                const abDataPtr = e.qjs_get_array_buffer(abHandle.ptr, abLenPtr);
                e.wasm_free(abLenPtr);
                abHandle.dispose();
                if (abDataPtr !== 0) {
                    const rawBytes = new Uint8Array(e.memory.buffer, abDataPtr + byteOffset, byteLength).slice();
                    switch (bytesPerElement) {
                        case 1: return rawBytes;
                        case 2: return new Uint16Array(rawBytes.buffer);
                        case 4: return new Uint32Array(rawBytes.buffer);
                        case 8: return new Float64Array(rawBytes.buffer);
                        default: return rawBytes;
                    }
                }
            }
            else {
                abHandle.dispose();
                e.wasm_free(byteOffsetPtr);
                e.wasm_free(byteLengthPtr);
                e.wasm_free(bytesPerElemPtr);
            }
        }
        if (e.qjs_is_array(handle.ptr)) {
            const lenHandle = handle.getProp('length');
            const len = e.qjs_get_float64(lenHandle.ptr);
            lenHandle.dispose();
            const arr = [];
            // Register the array in the visited map BEFORE populating it,
            // so circular references within the array resolve to this same array.
            const objPtr = e.qjs_get_value_ptr(handle.ptr);
            if (objPtr)
                visited.set(objPtr, arr);
            for (let i = 0; i < len; i++) {
                const elemPtr = e.qjs_get_prop_uint32(handle.ptr, i);
                const elemHandle = new JSValueHandle(this, elemPtr);
                arr.push(this._dump(elemHandle, visited));
                elemHandle.dispose();
            }
            return arr;
        }
        if (e.qjs_is_error(handle.ptr)) {
            const nameHandle = handle.getProp('name');
            const msgHandle = handle.getProp('message');
            const stackHandle = handle.getProp('stack');
            const name = nameHandle.isUndefined ? 'Error' : nameHandle.toString();
            const message = msgHandle.isUndefined ? '' : msgHandle.toString();
            const stack = stackHandle.isUndefined ? undefined : stackHandle.toString();
            nameHandle.dispose();
            msgHandle.dispose();
            stackHandle.dispose();
            const err = new Error(message);
            err.name = name;
            if (stack !== undefined) {
                err.stack = stack;
            }
            return err;
        }
        if (e.qjs_is_object(handle.ptr)) {
            const keysPtr = e.qjs_get_own_property_names(handle.ptr);
            const keysHandle = new JSValueHandle(this, keysPtr);
            if (e.qjs_is_exception(keysHandle.ptr) !== 0) {
                keysHandle.dispose();
                return {};
            }
            const lenHandle = keysHandle.getProp('length');
            const len = e.qjs_get_float64(lenHandle.ptr);
            lenHandle.dispose();
            const obj = {};
            // Register the object in the visited map BEFORE populating it,
            // so circular references resolve to this same object.
            const objPtr = e.qjs_get_value_ptr(handle.ptr);
            if (objPtr)
                visited.set(objPtr, obj);
            for (let i = 0; i < len; i++) {
                const keyPtr = e.qjs_get_prop_uint32(keysHandle.ptr, i);
                const keyHandle = new JSValueHandle(this, keyPtr);
                const key = keyHandle.toString();
                keyHandle.dispose();
                const valHandle = handle.getProp(key);
                obj[key] = this._dump(valHandle, visited);
                valHandle.dispose();
            }
            keysHandle.dispose();
            return obj;
        }
        return undefined;
    }
    /**
     * Convert a host JavaScript value to a QuickJS handle.
     */
    hostToHandle(value) {
        this.assertNotDisposed();
        if (value === undefined)
            return this.undefined;
        if (value === null)
            return this.null;
        if (value === true)
            return this.true;
        if (value === false)
            return this.false;
        if (typeof value === 'number')
            return this.newNumber(value);
        if (typeof value === 'string')
            return this.newString(value);
        if (typeof value === 'bigint')
            return this.newBigInt(value);
        if (typeof value === 'symbol') {
            const key = Symbol.keyFor(value);
            if (key !== undefined) {
                return this.newSymbolFor(key);
            }
            // Local symbols can't be transferred to QuickJS
            throw new Error(`Cannot convert local symbol to QuickJS handle. Use Symbol.for() for cross-boundary symbols.`);
        }
        if (value instanceof Promise) {
            const deferred = this.newPromise();
            value.then((r) => {
                deferred.resolve(this.hostToHandle(r));
                this.executePendingJobs();
            }, (err) => {
                deferred.reject(this.hostToHandle(err));
                this.executePendingJobs();
            });
            return deferred.handle;
        }
        if (value instanceof Error) {
            return this.newError(value);
        }
        if (value instanceof ArrayBuffer) {
            return this.newArrayBuffer(value);
        }
        if (value instanceof Uint8Array) {
            return this.newUint8Array(value);
        }
        if (ArrayBuffer.isView(value)) {
            // Other typed arrays: convert via Uint8Array view of the underlying buffer
            return this.newArrayBuffer(new Uint8Array(value.buffer, value.byteOffset, value.byteLength));
        }
        if (Array.isArray(value)) {
            const arr = this.newArray();
            for (let i = 0; i < value.length; i++) {
                const elemHandle = this.hostToHandle(value[i]);
                this.exports.qjs_set_prop_uint32(arr.ptr, i, elemHandle.ptr);
                elemHandle.dispose();
            }
            return arr;
        }
        if (typeof value === 'object' && value !== null) {
            const obj = this.newObject();
            for (const [key, val] of Object.entries(value)) {
                const valHandle = this.hostToHandle(val);
                obj.setProp(key, valHandle);
                valHandle.dispose();
            }
            return obj;
        }
        return this.undefined;
    }
    // ---- Snapshot / Restore ----
    /**
     * Snapshot the entire VM state.
     *
     * Returns a snapshot containing the full WASM linear memory. Use
     * `QuickJS.serializeSnapshot()` to convert to a versioned binary
     * buffer for persistent storage.
     */
    snapshot() {
        this.assertNotDisposed();
        return {
            memory: new Uint8Array(this.exports.memory.buffer).slice(),
            stackPointer: this.exports.__stack_pointer.value,
            runtimePtr: this.exports.qjs_get_runtime_ptr(),
            contextPtr: this.exports.qjs_get_context_ptr(),
            extensions: this.loadedExtensions.map((ext) => ({
                name: ext.name,
                memoryBase: ext.memoryBase,
                tableBase: ext.tableBase,
                initFn: ext.initFn,
            })),
        };
    }
    /**
     * Re-register a host callback after restoring from a snapshot.
     * The name must match the name passed to `newFunction()` before the snapshot.
     */
    registerHostCallback(name, fn) {
        this.hostCallbacks.set(name, fn);
    }
    /**
     * Dispose the VM, releasing all references to the WASM instance
     * so it can be garbage collected by the host JS engine.
     */
    dispose() {
        if (!this.disposed) {
            this.disposed = true;
            // Release references so the WASM instance and its linear memory
            // can be garbage collected even if someone holds onto this QuickJS object.
            this._global = null;
            this._undefined = null;
            this._null = null;
            this._true = null;
            this._false = null;
            this._ownedHandles.clear();
            this.hostCallbacks.clear();
            this._activeScope = null;
            this.exports = null;
            this.instance = null;
            this.module = null;
        }
    }
    /**
     * Support for `using` declarations (Explicit Resource Management).
     * Automatically disposes the VM when it goes out of scope.
     *
     * ```typescript
     * using vm = await QuickJS.create(wasmBytes);
     * vm.evalCode('1 + 2');
     * // vm is automatically disposed here
     * ```
     */
    [Symbol.dispose]() {
        this.dispose();
    }
    assertNotDisposed() {
        if (this.disposed) {
            throw new Error('QuickJS instance has been disposed');
        }
    }
    // ---- Internal accessors for JSValueHandle ----
    /** @internal */
    _getExports() {
        return this.exports;
    }
    /** @internal */
    _getMemory() {
        return this.exports.memory;
    }
    /** @internal */
    _writeString(str) {
        return this.writeString(str);
    }
    /** @internal */
    _readCString(ptr) {
        return this.readCString(ptr);
    }
}
// ---- lossless string helpers ----
/**
 * Whether a string-typed property key survives the NUL-terminated
 * C-string key APIs: embedded U+0000 truncates the key, and an UNPAIRED
 * surrogate cannot be UTF-8 encoded (paired surrogates, such as those
 * that encode emoji, are fine). Keys that don't survive are routed through length-aware
 * guest string values instead.
 */
function stringKeyNeedsValuePath(key) {
    return key.includes('\u0000') || LONE_SURROGATE_RE.test(key);
}
const wtf8Decoder = new TextDecoder();
const wtf8Encoder = new TextEncoder();
const LONE_SURROGATE_RE = /(?:[\uD800-\uDBFF](?![\uDC00-\uDFFF]))|(?:(?<![\uD800-\uDBFF])[\uDC00-\uDFFF])/;
/**
 * Encode a JS string to WTF-8 bytes. Well-formed strings (including
 * paired surrogates, such as emoji) take the native TextEncoder; strings with
 * LONE surrogates take a manual encode that writes each unpaired
 * surrogate as the 3-byte sequence quickjs's tolerant UTF-8 decoder
 * accepts; TextEncoder would replace them with U+FFFD, silently
 * corrupting every host→guest string (sources, property keys,
 * newString values).
 */
function encodeWtf8(str) {
    if (!LONE_SURROGATE_RE.test(str))
        return wtf8Encoder.encode(str);
    const bytes = [];
    for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        if (code < 0x80) {
            bytes.push(code);
        }
        else if (code < 0x800) {
            bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
        }
        else if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
            const next = str.charCodeAt(i + 1);
            if (next >= 0xdc00 && next <= 0xdfff) {
                // Well-formed pair: 4-byte UTF-8.
                const cp = 0x10000 + ((code - 0xd800) << 10) + (next - 0xdc00);
                bytes.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
                i++;
                continue;
            }
            // Lone high surrogate: 3-byte WTF-8.
            bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        }
        else {
            // BMP char or lone (low / trailing high) surrogate: 3-byte form.
            bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        }
    }
    return new Uint8Array(bytes);
}
/**
 * Decode WTF-8 bytes to a JS string. WTF-8 is UTF-8 extended with 3-byte
 * sequences for surrogate code points (0xED 0xA0-0xBF 0x80-0xBF), which
 * is how quickjs's JS_ToCStringLen2 encodes lone surrogates ("keep
 * unmatched surrogate code points"). TextDecoder replaces those
 * sequences with U+FFFD, so they are detected first and the rare strings
 * containing them take a manual decode; everything else (the
 * overwhelming majority) uses the native decoder.
 */
function decodeWtf8(bytes) {
    let hasSurrogateSequence = false;
    for (let i = 0; i < bytes.length - 1; i++) {
        if (bytes[i] === 0xed && bytes[i + 1] >= 0xa0 && bytes[i + 1] <= 0xbf) {
            hasSurrogateSequence = true;
            break;
        }
    }
    if (!hasSurrogateSequence)
        return wtf8Decoder.decode(bytes);
    let out = '';
    let i = 0;
    while (i < bytes.length) {
        const b0 = bytes[i];
        if (b0 < 0x80) {
            out += String.fromCharCode(b0);
            i += 1;
        }
        else if (b0 < 0xe0) {
            out += String.fromCharCode(((b0 & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
            i += 2;
        }
        else if (b0 < 0xf0) {
            // 3-byte sequence: may decode into the surrogate range, which is
            // exactly the WTF-8 extension: emit the code unit as-is.
            out += String.fromCharCode(((b0 & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f));
            i += 3;
        }
        else {
            const cp = ((b0 & 0x07) << 18) |
                ((bytes[i + 1] & 0x3f) << 12) |
                ((bytes[i + 2] & 0x3f) << 6) |
                (bytes[i + 3] & 0x3f);
            out += String.fromCodePoint(cp);
            i += 4;
        }
    }
    return out;
}
// ---- JSException ----
/**
 * An exception thrown from QuickJS code. Extends `Error` so it works with
 * standard error handling (`instanceof Error`, `.message`, `.stack`), and
 * also exposes a `handle` property, a live `JSValueHandle` to the QuickJS
 * exception value, allowing direct inspection of custom properties.
 *
 * The `handle` must be disposed when you're done with it (or use `using`).
 * If the error propagates uncaught, the handle will be cleaned up when the
 * VM is disposed.
 */
class JSException extends Error {
    /**
     * A live handle to the QuickJS exception value. You can read custom
     * properties, call methods, etc. Must be disposed when done.
     */
    handle;
    // Cached values so they survive handle disposal / VM teardown.
    // Using # fields keeps them out of console.log / Object.keys output.
    #name;
    #message;
    #stack;
    /** @internal */
    constructor(handle) {
        const env_1 = { stack: [], error: void 0, hasError: false };
        try {
            super();
            this.handle = handle;
            // V8 installs a lazy `stack` accessor on Error instances that shadows
            // our prototype getter. Delete it so our getter takes effect.
            delete this.stack;
            // Read error properties eagerly and cache them.
            const msgHandle = __addDisposableResource(env_1, handle.getProp('message'), false);
            this.#name = handle.getProp('name').consume(h => h.isUndefined ? 'Error' : h.toString());
            this.#message = msgHandle.isUndefined ? handle.toString() : msgHandle.toString();
            this.#stack = handle.getProp('stack').consume(h => h.isUndefined ? undefined : h.toString());
        }
        catch (e_1) {
            env_1.error = e_1;
            env_1.hasError = true;
        }
        finally {
            __disposeResources(env_1);
        }
    }
    get name() {
        return this.#name;
    }
    set name(v) {
        this.#name = v;
    }
    get message() {
        return this.#message;
    }
    set message(v) {
        this.#message = v;
    }
    get stack() {
        return this.#stack;
    }
    set stack(v) {
        this.#stack = v;
    }
    dispose() {
        this.handle.dispose();
    }
    [Symbol.dispose]() {
        this.handle.dispose();
    }
}
// ---- JSValue Handle ----
/**
 * A handle to a JSValue inside the QuickJS WASM instance.
 */
class JSValueHandle {
    /** The QuickJS VM instance this handle belongs to. */
    vm;
    /** @internal */
    ptr;
    disposed_ = false;
    /**
     * When true, this handle is a cached singleton (e.g. `undefined`, `null`,
     * `true`, `false`, the global object) and `dispose()` is a no-op. This
     * prevents code that routinely disposes handles (such as the object/array
     * branches of `hostToHandle`) from freeing the shared heap `JSValue*` that
     * the cached singleton still references, which would corrupt later reads.
     * @internal
     */
    singleton;
    /**
     * When true, this handle wraps a `JSValue*` OWNED BY THE C CALLER: the
     * `this`/argument handles the host-call trampoline passes to a host
     * callback (`handleHostCall`). The C side frees those values after the
     * call returns, so `dispose()` is a no-op and the handle is never
     * registered with an active `withScope()` (either would double-free
     * the guest value and corrupt the heap). A callback that needs to
     * retain an argument past its own invocation must `dup()` it; the
     * duplicate takes a fresh reference and behaves like any owned handle.
     * @internal
     */
    borrowed;
    /**
     * Extra cleanup to run when this handle is disposed. Used by
     * `newEphemeralFunction()` to unregister its host callback.
     * @internal
     */
    _onDispose;
    constructor(vm, ptr, singleton = false, borrowed = false) {
        this.vm = vm;
        this.ptr = ptr;
        this.singleton = singleton;
        this.borrowed = borrowed;
        // Singletons are shared and outlive any scope; borrowed handles wrap
        // C-owned pointers that a scope must never free.
        if (!singleton && !borrowed)
            vm._activeScope?.add(this);
    }
    /**
     * Whether this handle wraps a C-owned pointer (host-callback
     * `this`/arguments). Borrowed handles must never be exported as
     * snapshot tokens: the trampoline frees their boxes after the
     * callback returns. @internal
     */
    get _isBorrowed() {
        return this.borrowed;
    }
    /**
     * Whether `dispose()` has been called on this handle.
     *
     * Note that handle methods do not currently guard against use after
     * disposal: reading from a disposed handle reads freed memory. Check this
     * when a handle's lifetime is managed elsewhere (e.g. by `withScope()`).
     */
    get disposed() {
        // singletons are never freed, so they are never "disposed"
        return this.disposed_;
    }
    get isUndefined() {
        return this.vm._getExports().qjs_is_undefined(this.ptr) !== 0;
    }
    get isNull() {
        return this.vm._getExports().qjs_is_null(this.ptr) !== 0;
    }
    /**
     * Get the promise state: 0 = pending, 1 = fulfilled, 2 = rejected
     */
    get isBool() {
        return this.vm._getExports().qjs_is_bool(this.ptr) !== 0;
    }
    get isNumber() {
        return this.vm._getExports().qjs_is_number(this.ptr) !== 0;
    }
    get isString() {
        return this.vm._getExports().qjs_is_string(this.ptr) !== 0;
    }
    get isSymbol() {
        return this.vm._getExports().qjs_is_symbol(this.ptr) !== 0;
    }
    get isBigInt() {
        return this.vm._getExports().qjs_is_big_int(this.ptr) !== 0;
    }
    get isObject() {
        return this.vm._getExports().qjs_is_object(this.ptr) !== 0;
    }
    get isArray() {
        return this.vm._getExports().qjs_is_array(this.ptr) !== 0;
    }
    get isFunction() {
        return this.vm._getExports().qjs_is_function(this.ptr) !== 0;
    }
    get isError() {
        return this.vm._getExports().qjs_is_error(this.ptr) !== 0;
    }
    get isPromise() {
        return this.vm._getExports().qjs_is_promise(this.ptr) !== 0;
    }
    get isArrayBuffer() {
        return this.vm._getExports().qjs_is_array_buffer(this.ptr) !== 0;
    }
    /**
     * Whether this value is a Proxy exotic object.
     *
     * This is an engine-level check: it never fires proxy traps and cannot
     * be determined (or spoofed) from within guest JavaScript. Use
     * {@link getProxyTarget} / {@link getProxyHandler} to introspect a
     * detected proxy without executing guest code.
     */
    get isProxy() {
        return this.vm._getExports().qjs_is_proxy(this.ptr) !== 0;
    }
    /**
     * Whether this value is a Map (engine brand check: trap-free,
     * spoof-proof, and unaffected by prototype/constructor mutation).
     * A Proxy wrapping a Map returns false.
     */
    get isMap() {
        return this.vm._getExports().qjs_is_map(this.ptr) !== 0;
    }
    /**
     * Whether this value is a Set (engine brand check: trap-free,
     * spoof-proof, and unaffected by prototype/constructor mutation).
     * A Proxy wrapping a Set returns false.
     */
    get isSet() {
        return this.vm._getExports().qjs_is_set(this.ptr) !== 0;
    }
    /**
     * Whether this value is a Date (engine brand check: trap-free,
     * spoof-proof, and unaffected by prototype/constructor mutation).
     * A Proxy wrapping a Date returns false.
     */
    get isDate() {
        return this.vm._getExports().qjs_is_date(this.ptr) !== 0;
    }
    /**
     * Whether this value is a RegExp (engine brand check: trap-free,
     * spoof-proof, and unaffected by prototype/constructor mutation).
     * A Proxy wrapping a RegExp returns false.
     */
    get isRegExp() {
        return this.vm._getExports().qjs_is_regexp(this.ptr) !== 0;
    }
    /** Whether this value is a WeakRef (engine brand check). */
    get isWeakRef() {
        return this.vm._getExports().qjs_is_weak_ref(this.ptr) !== 0;
    }
    /** Whether this value is a WeakMap (engine brand check). */
    get isWeakMap() {
        return this.vm._getExports().qjs_is_weak_map(this.ptr) !== 0;
    }
    /** Whether this value is a WeakSet (engine brand check). */
    get isWeakSet() {
        return this.vm._getExports().qjs_is_weak_set(this.ptr) !== 0;
    }
    /** Whether this value is a DataView (engine brand check). */
    get isDataView() {
        return this.vm._getExports().qjs_is_data_view(this.ptr) !== 0;
    }
    /**
     * A numeric identity for the underlying heap value, or 0 for values that
     * are not heap-allocated (numbers, booleans, `null`, `undefined`).
     *
     * Two handles to the same underlying object always report the same
     * identity, and two live handles to different objects always report
     * different identities, so this is the value to key a `Map` on when
     * deduplicating or detecting cycles across handles (`dump()` uses it for
     * exactly that).
     *
     * The identity is only meaningful while the value is alive; it is an
     * address, so it may be reused after every handle to the value has been
     * disposed. Do not persist it, and do not treat it as unforgeable: a
     * number read out of the guest can trivially collide with one.
     */
    get identity() {
        return this.vm._getExports().qjs_get_value_ptr(this.ptr);
    }
    /**
     * Extract the value as a boolean, applying JavaScript truthiness
     * (equivalent to `!!value` inside the VM).
     */
    toBoolean() {
        return this.vm._getExports().qjs_get_bool(this.ptr) !== 0;
    }
    /**
     * The internal QuickJS class ID of this value, or 0 for non-objects.
     * Useful as a generic engine-level brand when no dedicated `is*`
     * getter exists. Class IDs are stable within a VM instance but are an
     * engine implementation detail, so prefer the dedicated getters.
     */
    get classId() {
        return this.vm._getExports().qjs_get_class_id(this.ptr);
    }
    /**
     * The engine-level class name of this value, e.g. `"Object"`, `"Map"`,
     * `"Date"`, `"RegExp"`, or the registered name of an extension-defined
     * class like `"URL"`, or `undefined` for non-objects and unnamed
     * internal classes.
     *
     * Unlike `constructorName` (which reads the `constructor` and `name`
     * properties and can therefore fire getters/proxy traps and be spoofed),
     * this is trap-free: it reads the engine's class table directly, never
     * executes guest code, and cannot be forged by reassigning prototypes or
     * constructors. Note that the engine registers the Proxy class under the
     * name `"Object"` (mirroring `Object.prototype.toString`), so use `isProxy`
     * to detect proxies and `getProxyTarget()` to read the target's brand.
     */
    get className() {
        const h = new JSValueHandle(this.vm, this.vm._getExports().qjs_get_class_name(this.ptr));
        // qjs_get_class_name can return JS_EXCEPTION (e.g. OOM while
        // materializing the name atom as a string); surface it instead of
        // stringifying the exception sentinel and leaving the real error
        // pending on the context.
        if (this.vm._getExports().qjs_is_exception(h.ptr) !== 0) {
            h.dispose();
            throw new JSException(this.vm.getException());
        }
        try {
            return h.isUndefined ? undefined : h.toString();
        }
        finally {
            h.dispose();
        }
    }
    get promiseState() {
        return this.vm._getExports().qjs_promise_state(this.ptr);
    }
    /**
     * Get the typeof this value as a string.
     * Returns the same values as the native `typeof` operator.
     */
    get typeof() {
        return this.vm.typeof(this);
    }
    /**
     * Get the length property of this value (for arrays, strings, etc.).
     */
    get length() {
        const h = this.getProp('length');
        const n = h.toNumber();
        h.dispose();
        return n;
    }
    /**
     * Get the constructor name of this object, or undefined if unavailable.
     */
    get constructorName() {
        const ctor = this.getProp('constructor');
        if (ctor.isUndefined || ctor.isNull) {
            ctor.dispose();
            return undefined;
        }
        const name = ctor.getProp('name');
        ctor.dispose();
        if (name.isUndefined || name.isNull) {
            name.dispose();
            return undefined;
        }
        const result = name.toString();
        name.dispose();
        return result;
    }
    /**
     * Get the own enumerable string property names (equivalent to Object.keys()).
     */
    keys() {
        const e = this.vm._getExports();
        const keysPtr = e.qjs_get_own_property_names(this.ptr);
        const keysHandle = new JSValueHandle(this.vm, keysPtr);
        if (e.qjs_is_exception(keysHandle.ptr) !== 0) {
            keysHandle.dispose();
            return [];
        }
        const lenHandle = keysHandle.getProp('length');
        const len = e.qjs_get_float64(lenHandle.ptr);
        lenHandle.dispose();
        const result = [];
        for (let i = 0; i < len; i++) {
            const keyPtr = e.qjs_get_prop_uint32(keysHandle.ptr, i);
            const keyHandle = new JSValueHandle(this.vm, keyPtr);
            result.push(keyHandle.toString());
            keyHandle.dispose();
        }
        keysHandle.dispose();
        return result;
    }
    /**
     * Get all own property names including non-enumerable ones
     * (equivalent to Object.getOwnPropertyNames()).
     */
    getOwnPropertyNames() {
        const e = this.vm._getExports();
        const keysPtr = e.qjs_get_own_property_names_all(this.ptr);
        const keysHandle = new JSValueHandle(this.vm, keysPtr);
        if (e.qjs_is_exception(keysHandle.ptr) !== 0) {
            keysHandle.dispose();
            return [];
        }
        const lenHandle = keysHandle.getProp('length');
        const len = e.qjs_get_float64(lenHandle.ptr);
        lenHandle.dispose();
        const result = [];
        for (let i = 0; i < len; i++) {
            const keyPtr = e.qjs_get_prop_uint32(keysHandle.ptr, i);
            const keyHandle = new JSValueHandle(this.vm, keyPtr);
            result.push(keyHandle.toString());
            keyHandle.dispose();
        }
        keysHandle.dispose();
        return result;
    }
    /**
     * Get ALL own property keys (strings and symbols), including
     * non-enumerable (equivalent to Reflect.ownKeys()).
     *
     * String keys are returned as strings; symbol keys are returned as
     * JSValueHandles which the caller must dispose.
     *
     * Trap-free for ordinary objects; fires the `ownKeys` trap for a
     * Proxy (check {@link isProxy} first if that matters).
     */
    getOwnPropertyKeys() {
        const e = this.vm._getExports();
        const keysPtr = e.qjs_get_own_property_keys(this.ptr);
        const keysHandle = new JSValueHandle(this.vm, keysPtr);
        if (e.qjs_is_exception(keysHandle.ptr) !== 0) {
            keysHandle.dispose();
            return [];
        }
        const lenHandle = keysHandle.getProp('length');
        const len = e.qjs_get_float64(lenHandle.ptr);
        lenHandle.dispose();
        const result = [];
        for (let i = 0; i < len; i++) {
            const keyPtr = e.qjs_get_prop_uint32(keysHandle.ptr, i);
            const keyHandle = new JSValueHandle(this.vm, keyPtr);
            if (keyHandle.isSymbol) {
                result.push(keyHandle);
            }
            else {
                result.push(keyHandle.toString());
                keyHandle.dispose();
            }
        }
        keysHandle.dispose();
        return result;
    }
    /**
     * Get the own property descriptor for a key WITHOUT invoking getters
     * (equivalent to Object.getOwnPropertyDescriptor()).
     *
     * This is the safe way to inspect a property that may be an accessor:
     * a data property yields `{ value, writable, enumerable, configurable }`,
     * an accessor property yields `{ get, set, enumerable, configurable }`
     * where `get`/`set` are handles to the accessor functions themselves
     * (never invoked). Returns undefined if there is no such own property.
     *
     * The `value`/`get`/`set` handles are owned by the caller and must be
     * disposed.
     *
     * Trap-free for ordinary objects; fires the `getOwnPropertyDescriptor`
     * trap for a Proxy (check {@link isProxy} first if that matters).
     */
    getOwnPropertyDescriptor(key) {
        const env_2 = { stack: [], error: void 0, hasError: false };
        try {
            const e = this.vm._getExports();
            let keyHandle;
            let keyPtr;
            if (typeof key === 'string') {
                keyHandle = this.vm.newString(key);
                keyPtr = keyHandle.ptr;
            }
            else {
                keyPtr = key.ptr;
            }
            const descPtr = e.qjs_get_own_property_descriptor(this.ptr, keyPtr);
            keyHandle?.dispose();
            if (descPtr === 0)
                return undefined; /* no such own property */
            const descHandle = __addDisposableResource(env_2, new JSValueHandle(this.vm, descPtr), false);
            if (e.qjs_is_exception(descHandle.ptr) !== 0) {
                throw new JSException(this.vm.getException());
            }
            const enumerable = descHandle.getProp('enumerable').consume(h => e.qjs_get_bool(h.ptr) !== 0);
            const configurable = descHandle.getProp('configurable').consume(h => e.qjs_get_bool(h.ptr) !== 0);
            if (descHandle.hasOwnProperty('value')) {
                return {
                    value: descHandle.getProp('value'),
                    writable: descHandle.getProp('writable').consume(h => e.qjs_get_bool(h.ptr) !== 0),
                    enumerable,
                    configurable,
                };
            }
            return {
                get: descHandle.getProp('get'),
                set: descHandle.getProp('set'),
                enumerable,
                configurable,
            };
        }
        catch (e_2) {
            env_2.error = e_2;
            env_2.hasError = true;
        }
        finally {
            __disposeResources(env_2);
        }
    }
    /**
     * Check if a property is an own property (equivalent to Object.prototype.hasOwnProperty).
     */
    hasOwnProperty(name) {
        if (stringKeyNeedsValuePath(name)) {
            const env_3 = { stack: [], error: void 0, hasError: false };
            try {
                const keyHandle = __addDisposableResource(env_3, this.vm.newString(name), false);
                return (this.vm._getExports().qjs_has_own_property_value(this.ptr, keyHandle.ptr) === 1);
            }
            catch (e_3) {
                env_3.error = e_3;
                env_3.hasError = true;
            }
            finally {
                __disposeResources(env_3);
            }
        }
        const { ptr: namePtr } = this.vm._writeString(name);
        const result = this.vm._getExports().qjs_has_own_property(this.ptr, namePtr);
        this.vm._getExports().wasm_free(namePtr);
        return result === 1;
    }
    /**
     * Check if a property is enumerable (equivalent to Object.prototype.propertyIsEnumerable).
     */
    propertyIsEnumerable(name) {
        if (stringKeyNeedsValuePath(name)) {
            const env_4 = { stack: [], error: void 0, hasError: false };
            try {
                const keyHandle = __addDisposableResource(env_4, this.vm.newString(name), false);
                return (this.vm._getExports().qjs_property_is_enumerable_value(this.ptr, keyHandle.ptr) === 1);
            }
            catch (e_4) {
                env_4.error = e_4;
                env_4.hasError = true;
            }
            finally {
                __disposeResources(env_4);
            }
        }
        const { ptr: namePtr } = this.vm._writeString(name);
        const result = this.vm._getExports().qjs_property_is_enumerable(this.ptr, namePtr);
        this.vm._getExports().wasm_free(namePtr);
        return result === 1;
    }
    /**
     * Get the prototype of this object (equivalent to Object.getPrototypeOf()).
     */
    getPrototypeOf() {
        const protoPtr = this.vm._getExports().qjs_get_prototype_of(this.ptr);
        return new JSValueHandle(this.vm, protoPtr);
    }
    /**
     * Get the `[[ProxyTarget]]` of this Proxy without firing any traps.
     * Throws {@link JSException} if this value is not a Proxy; check
     * {@link isProxy} first. Note the target may itself be a Proxy.
     */
    getProxyTarget() {
        const ptr = this.vm._getExports().qjs_get_proxy_target(this.ptr);
        const handle = new JSValueHandle(this.vm, ptr);
        if (this.vm._getExports().qjs_is_exception(handle.ptr) !== 0) {
            handle.dispose();
            throw new JSException(this.vm.getException());
        }
        return handle;
    }
    /**
     * Get the `[[ProxyHandler]]` of this Proxy without firing any traps.
     * Throws {@link JSException} if this value is not a Proxy; check
     * {@link isProxy} first.
     */
    getProxyHandler() {
        const ptr = this.vm._getExports().qjs_get_proxy_handler(this.ptr);
        const handle = new JSValueHandle(this.vm, ptr);
        if (this.vm._getExports().qjs_is_exception(handle.ptr) !== 0) {
            handle.dispose();
            throw new JSException(this.vm.getException());
        }
        return handle;
    }
    /**
     * Get a property by name.
     */
    getProp(name) {
        if (stringKeyNeedsValuePath(name)) {
            const env_5 = { stack: [], error: void 0, hasError: false };
            try {
                // A NUL or lone surrogate in the key cannot cross the C-string
                // API; go through a length-aware guest string key instead.
                const keyHandle = __addDisposableResource(env_5, this.vm.newString(name), false);
                return this.vm.getProp(this, keyHandle);
            }
            catch (e_5) {
                env_5.error = e_5;
                env_5.hasError = true;
            }
            finally {
                __disposeResources(env_5);
            }
        }
        const { ptr: namePtr } = this.vm._writeString(name);
        const resultPtr = this.vm._getExports().qjs_get_prop_string(this.ptr, namePtr);
        this.vm._getExports().wasm_free(namePtr);
        return new JSValueHandle(this.vm, resultPtr);
    }
    /**
     * Set a property by name.
     */
    setProp(name, value) {
        if (stringKeyNeedsValuePath(name)) {
            const env_6 = { stack: [], error: void 0, hasError: false };
            try {
                const keyHandle = __addDisposableResource(env_6, this.vm.newString(name), false);
                this.vm.setProp(this, keyHandle, value);
                return;
            }
            catch (e_6) {
                env_6.error = e_6;
                env_6.hasError = true;
            }
            finally {
                __disposeResources(env_6);
            }
        }
        const { ptr: namePtr } = this.vm._writeString(name);
        this.vm._getExports().qjs_set_prop_string(this.ptr, namePtr, value.ptr);
        this.vm._getExports().wasm_free(namePtr);
    }
    /**
     * Define a property with explicit property descriptor flags.
     * Unlike `setProp`, this allows controlling `writable`, `enumerable`, and
     * `configurable` attributes, matching `Object.defineProperty()` semantics.
     * Accepts string or JSValueHandle as key (JSValueHandle keys support symbols).
     *
     * All flags default to `false` when not specified.
     */
    defineProp(key, value, descriptor) {
        let flags = 0;
        if (descriptor?.configurable)
            flags |= 1; // JS_PROP_CONFIGURABLE
        if (descriptor?.writable)
            flags |= 2; // JS_PROP_WRITABLE
        if (descriptor?.enumerable)
            flags |= 4; // JS_PROP_ENUMERABLE
        if (typeof key === 'string') {
            if (stringKeyNeedsValuePath(key)) {
                const env_7 = { stack: [], error: void 0, hasError: false };
                try {
                    const keyHandle = __addDisposableResource(env_7, this.vm.newString(key), false);
                    this.vm._getExports().qjs_define_prop_value(this.ptr, keyHandle.ptr, value.ptr, flags);
                    return;
                }
                catch (e_7) {
                    env_7.error = e_7;
                    env_7.hasError = true;
                }
                finally {
                    __disposeResources(env_7);
                }
            }
            const { ptr: namePtr } = this.vm._writeString(key);
            this.vm._getExports().qjs_define_prop_string(this.ptr, namePtr, value.ptr, flags);
            this.vm._getExports().wasm_free(namePtr);
        }
        else {
            this.vm._getExports().qjs_define_prop_value(this.ptr, key.ptr, value.ptr, flags);
        }
    }
    /**
     * Extract the value as a number.
     */
    toNumber() {
        return this.vm._getExports().qjs_get_float64(this.ptr);
    }
    /**
     * Extract the value as a BigInt.
     */
    toBigInt() {
        const e = this.vm._getExports();
        const loPtr = e.wasm_malloc(4);
        const hiPtr = e.wasm_malloc(4);
        const ret = e.qjs_get_big_int64(this.ptr, loPtr, hiPtr);
        if (ret !== 0) {
            e.wasm_free(loPtr);
            e.wasm_free(hiPtr);
            throw new Error('Failed to convert value to BigInt');
        }
        const view = new DataView(e.memory.buffer);
        const lo = view.getUint32(loPtr, true);
        const hi = view.getInt32(hiPtr, true); // signed for the high word
        e.wasm_free(loPtr);
        e.wasm_free(hiPtr);
        return (BigInt(hi) << 32n) | BigInt(lo);
    }
    /**
     * Extract the value as an ArrayBuffer (copies from WASM memory).
     * Works on ArrayBuffer values. For typed arrays, gets the underlying buffer.
     */
    toArrayBuffer() {
        const e = this.vm._getExports();
        const lenOutPtr = e.wasm_malloc(4);
        if (e.qjs_is_array_buffer(this.ptr)) {
            const dataPtr = e.qjs_get_array_buffer(this.ptr, lenOutPtr);
            if (dataPtr === 0) {
                e.wasm_free(lenOutPtr);
                throw new Error('Failed to get ArrayBuffer data');
            }
            const view = new DataView(e.memory.buffer);
            const len = view.getUint32(lenOutPtr, true);
            e.wasm_free(lenOutPtr);
            // Copy out of WASM memory
            return new Uint8Array(e.memory.buffer, dataPtr, len).slice().buffer;
        }
        // Try typed array → underlying ArrayBuffer
        e.wasm_free(lenOutPtr);
        const byteOffsetPtr = e.wasm_malloc(4);
        const byteLengthPtr = e.wasm_malloc(4);
        const bytesPerElemPtr = e.wasm_malloc(4);
        const abPtr = e.qjs_get_typed_array_buffer(this.ptr, byteOffsetPtr, byteLengthPtr, bytesPerElemPtr);
        const abHandle = new JSValueHandle(this.vm, abPtr);
        if (this.vm._getExports().qjs_is_exception(abHandle.ptr) !== 0) {
            abHandle.dispose();
            e.wasm_free(byteOffsetPtr);
            e.wasm_free(byteLengthPtr);
            e.wasm_free(bytesPerElemPtr);
            throw new Error('Value is not an ArrayBuffer or typed array');
        }
        const view = new DataView(e.memory.buffer);
        const byteOffset = view.getUint32(byteOffsetPtr, true);
        const byteLength = view.getUint32(byteLengthPtr, true);
        e.wasm_free(byteOffsetPtr);
        e.wasm_free(byteLengthPtr);
        e.wasm_free(bytesPerElemPtr);
        // Get the raw data from the underlying ArrayBuffer
        const abLenPtr = e.wasm_malloc(4);
        const abDataPtr = e.qjs_get_array_buffer(abHandle.ptr, abLenPtr);
        e.wasm_free(abLenPtr);
        abHandle.dispose();
        if (abDataPtr === 0) {
            throw new Error('Failed to get ArrayBuffer data from typed array');
        }
        // Copy the relevant slice out of WASM memory
        return new Uint8Array(e.memory.buffer, abDataPtr + byteOffset, byteLength).slice().buffer;
    }
    /**
     * Extract the value as a Uint8Array (copies from WASM memory).
     * Works on Uint8Array, ArrayBuffer, and other typed array values.
     */
    toUint8Array() {
        return new Uint8Array(this.toArrayBuffer());
    }
    /**
     * Extract the value as a string. Works on any value.
     *
     * For values that are not already strings this performs a JavaScript
     * string conversion, which **executes guest code**: `toString()` /
     * `valueOf()` / `Symbol.toPrimitive` on the value or its prototype chain,
     * and proxy traps. Guard with `isString` when the caller must not run guest
     * code, and call a captured intrinsic (e.g. `URL.prototype.toString` via
     * `vm.callFunction`) when a specific conversion is wanted.
     */
    toString() {
        // Length-aware + WTF-8 (qjs_get_string_len): embedded U+0000 code
        // units survive (the byte length is explicit, not NUL-scanned) and
        // lone surrogates survive (quickjs encodes unmatched surrogate code
        // points as 3-byte WTF-8 sequences, decoded back to their original
        // code units). The previous JS_ToCString/NUL-terminated read
        // silently truncated at the first NUL and replaced lone surrogates
        // with U+FFFD, and the two corruptions could cancel each other's
        // length changes, defeating length-based detection downstream.
        const e = this.vm._getExports();
        const lenPtr = e.wasm_malloc(4);
        // Same failure check as writeString(): a 0 return would make
        // qjs_get_string_len write the length to address 0 and the DataView
        // read below read from it: silent corruption instead of an error.
        if (lenPtr === 0)
            throw new Error('wasm_malloc failed');
        try {
            const cstrPtr = e.qjs_get_string_len(this.ptr, lenPtr);
            if (cstrPtr === 0)
                return '<null>';
            const len = new DataView(e.memory.buffer).getUint32(lenPtr, true);
            const bytes = new Uint8Array(e.memory.buffer, cstrPtr, len);
            const str = decodeWtf8(bytes);
            e.qjs_free_cstring(cstrPtr);
            return str;
        }
        finally {
            e.wasm_free(lenPtr);
        }
    }
    /**
     * Use this handle, then dispose it. Returns the callback's return value.
     */
    consume(fn) {
        try {
            return fn(this);
        }
        finally {
            this.dispose();
        }
    }
    /**
     * Duplicate this handle (increment refcount).
     */
    dup() {
        return new JSValueHandle(this.vm, this.vm._getExports().qjs_dup_value(this.ptr));
    }
    /**
     * Dispose this handle, freeing the heap-allocated JSValue.
     * Safe to call after the VM has been disposed (becomes a no-op).
     */
    dispose() {
        // Cached singleton handles (undefined/null/true/false/global) share a
        // single heap-allocated JSValue that the VM keeps referencing. Freeing it
        // here would leave the cached handle pointing at freed memory, so disposing
        // a singleton is intentionally a no-op. Borrowed handles (host-callback
        // `this`/arguments) wrap pointers owned by the C caller, which frees them
        // itself after the call returns; freeing here would double-free.
        if (this.singleton || this.borrowed)
            return;
        if (!this.disposed_) {
            this.disposed_ = true;
            this._onDispose?.();
            this._onDispose = undefined;
            // If the VM is already disposed, the WASM instance is gone;
            // no need to (and we can't) call qjs_free_value.
            const exports = this.vm._getExports();
            if (exports) {
                exports.qjs_free_value(this.ptr);
            }
        }
    }
    /**
     * Support for `using` declarations (Explicit Resource Management).
     * Automatically disposes the handle when it goes out of scope.
     *
     * ```typescript
     * using result = vm.evalCode('1 + 2');
     * console.log(result.toNumber()); // 3
     * // result is automatically disposed here
     * ```
     */
    [Symbol.dispose]() {
        this.dispose();
    }
}

/**
 * JavaScript evaluated inside the QuickJS VM before the script runs.
 *
 * The VM is its own wasm instance, so nothing here guards a realm boundary.
 * The prelude keeps the host bridge in a closure so the script cannot call it
 * directly, and builds `tools`, `ALL_TOOLS`, the output helpers (`text`, `image`,
 * `exit`, `console`), and globals on top of it. Tool arguments and results cross
 * as JSON strings and are parsed on this side.
 *
 * Output helpers: `text(value)` appends a text item (non-strings are
 * JSON-stringified), `image(urlOrItem)` appends an image from a base64 `data:` URL, an
 * `{ image_url }` object, or an image block `{ type: "image", data, mimeType }`, and `exit()` ends the script
 * successfully. `console.*` appends text items marked as console output.
 *
 * `store(key, value)` and `load(key)` are synchronous: they work on a snapshot of
 * JSON text passed in as `storeJson`, and the keys the script wrote are reported
 * with a successful "done".
 *
 * Evaluates to a function `(bridge, toolsJson, globalsJson, storeJson) => { settle, run, stalled }`.
 * `settle(id, ok, payload, propertiesJson)` settles call `id`; a rejection's `Error` gets the own properties of the
 * `propertiesJson` object, except `name`, `message`, and `stack`.
 * `toolsJson` lists `{ name, jsName, description }`: `tools[jsName]` and `tools[name]` call the
 * tool, and `ALL_TOOLS` lists `{ name: jsName, description }`.
 * `stalled()` reports a script that has not finished while no host call is pending: with no timers
 * or I/O in the VM, nothing can ever resume it.
 * `globalsJson` lists `{ name, spread }`; `a.b` names are grouped into a frozen `a` object.
 * `bridge(kind, a, b, c)` with kind "call" or "global" (id, name, argsJson),
 * "output" ("text" or "console", text) or ("image", data, mimeType), or "done" (ok, valueJsonOrErrorJson, writesJson).
 *
 * Before anything else the prelude freezes the built-ins and makes the built-in globals read-only.
 * The prelude shares them with the script, so a script that patched one (for example
 * `Array.prototype.toJSON`) could otherwise corrupt what the prelude reports to the host.
 */
const MAX_STORE_VALUE_CHARS = 256 * 1024;
const MAX_STORE_TOTAL_CHARS = 1024 * 1024;
/**
 * Output one script may produce with `text()`, `image()`, and `console.*`: characters of text and
 * base64 image data, and items. The host keeps all output until the script ends, so without a
 * limit a script that prints in a loop grows the host's memory until it crashes. The item limit
 * covers loops that print empty strings.
 */
const MAX_OUTPUT_CHARS = 16 * 1024 * 1024;
const MAX_OUTPUT_ITEMS = 100_000;
const IMAGE_HELPER_EXPECTS = 'image expects a non-empty image URL string, an object with image_url, or an image block { type: "image", data, mimeType }';
const PRELUDE_SOURCE = `(function (bridge, toolsJson, globalsJson, storeJson) {
	"use strict";

	// Freeze every object reachable from the built-in globals, plus the intrinsics that are only
	// reachable from instances (iterator and generator prototypes, %TypedArray%).
	//
	// Freezing alone breaks ordinary code through the "override mistake": a data property that is
	// read-only on a prototype cannot be assigned on an instance either, so
	// this.name = "MyError" in an Error subclass would throw. Commonly overridden properties
	// become accessors whose setter defines an own property on the instance instead.
	(function lockdown() {
		const OVERRIDABLE = new Set(["constructor", "name", "message", "toString", "toLocaleString", "valueOf", "toJSON"]);
		const seen = new Set([globalThis]);
		const queue = [];
		const add = (value) => {
			if ((typeof value === "object" && value !== null) || typeof value === "function") {
				if (!seen.has(value)) {
					seen.add(value);
					queue.push(value);
				}
			}
		};

		// Accessors from an object literal have no own prototype object, unlike function expressions,
		// whose prototype.constructor would be converted again without end.
		function allowOverride(object, key, value, enumerable) {
			const { get, set } = Object.getOwnPropertyDescriptor(
				{
					get accessor() {
						return value;
					},
					set accessor(next) {
						if (this === object) {
							throw new TypeError("Cannot assign to read only property '" + String(key) + "' of a built-in");
						}
						if ((typeof this !== "object" || this === null) && typeof this !== "function") return;
						Object.defineProperty(this, key, { value: next, writable: true, enumerable: true, configurable: true });
					},
				},
				"accessor",
			);
			Object.defineProperty(object, key, { get, set, enumerable, configurable: false });
			add(get);
			add(set);
		}

		for (const key of Reflect.ownKeys(globalThis)) {
			const descriptor = Object.getOwnPropertyDescriptor(globalThis, key);
			add(descriptor.value);
			add(descriptor.get);
			add(descriptor.set);
			if ("value" in descriptor && descriptor.configurable) {
				Object.defineProperty(globalThis, key, { writable: false, configurable: false });
			}
		}
		add(Object.getPrototypeOf(function* () {}));
		add(Object.getPrototypeOf(async function () {}));
		add(Object.getPrototypeOf(async function* () {}));
		add(Object.getPrototypeOf(Int8Array));
		add(Object.getPrototypeOf([][Symbol.iterator]()));
		add(Object.getPrototypeOf(new Map()[Symbol.iterator]()));
		add(Object.getPrototypeOf(new Set()[Symbol.iterator]()));
		add(Object.getPrototypeOf(""[Symbol.iterator]()));
		add(Object.getPrototypeOf(/a/[Symbol.matchAll]("")));
		if (typeof Iterator === "function") {
			if (typeof Iterator.prototype.map === "function") add(Object.getPrototypeOf([].values().map((x) => x)));
			if (typeof Iterator.from === "function") add(Object.getPrototypeOf(Iterator.from({ next() {} })));
		}

		while (queue.length > 0) {
			const object = queue.pop();
			add(Object.getPrototypeOf(object));
			const descriptors = Object.getOwnPropertyDescriptors(object);
			for (const key of Reflect.ownKeys(descriptors)) {
				const descriptor = descriptors[key];
				if ("value" in descriptor) {
					add(descriptor.value);
					if (
						descriptor.writable &&
						descriptor.configurable &&
						(object === Object.prototype || OVERRIDABLE.has(key))
					) {
						allowOverride(object, key, descriptor.value, descriptor.enumerable);
					}
				} else {
					add(descriptor.get);
					add(descriptor.set);
				}
			}
			Object.freeze(object);
		}
	})();
	const stringify = JSON.stringify;
	const parse = JSON.parse;
	const promiseThen = Promise.prototype.then;
	const ErrorCtor = Error;
	const TypeErrorCtor = TypeError;
	const RangeErrorCtor = RangeError;
	const pending = new Map();
	let nextId = 1;
	let finished = false;
	// Thrown by exit() to unwind the script after it already reported success.
	const EXIT = Object.freeze({});

	function done(ok, payload, writes) {
		if (finished) return;
		finished = true;
		bridge("done", ok, payload, writes);
	}

	function serialize(value) {
		return value === undefined ? undefined : stringify(value);
	}

	// QuickJS stacks list frames only. Prefix "Name: message" like V8 so the
	// text reads the same as a Node error, and drop this prelude's frames.
	function errorText(error) {
		const head = error.message ? error.name + ": " + error.message : String(error.name);
		const frames =
			typeof error.stack === "string"
				? error.stack.split("\\n").filter((line) => line.trim() && !line.includes("codemode-prelude.js"))
				: [];
		return [head, ...frames].join("\\n");
	}

	function format(value) {
		if (typeof value === "string") return value;
		if (value instanceof ErrorCtor) return errorText(value);
		try {
			const json = stringify(value);
			return json === undefined ? String(value) : json;
		} catch {
			return String(value);
		}
	}

	// The host requires string fields. A script can set an error's name or message to anything, so
	// they are coerced, and a value whose coercion throws gets a placeholder.
	function describeError(error) {
		try {
			if (error instanceof ErrorCtor) {
				return stringify({ name: String(error.name), message: String(error.message), stack: errorText(error) });
			}
			return stringify({ message: String(format(error)) });
		} catch {
			return stringify({ message: "The script threw a value that cannot be described" });
		}
	}

	function caller(kind, name, spread) {
		return (...args) =>
			new Promise((resolve, reject) => {
				let json;
				try {
					json = serialize(spread ? args : args[0]);
				} catch (error) {
					reject(error);
					return;
				}
				const id = nextId++;
				pending.set(id, { resolve, reject });
				bridge(kind, id, name, json);
			});
	}

	const tools = Object.create(null);
	const allTools = [];
	for (const { name, jsName, description } of parse(toolsJson)) {
		const fn = caller("call", name);
		// The first tool wins when two names normalize to the same identifier.
		if (!(jsName in tools)) {
			tools[jsName] = fn;
			allTools.push(Object.freeze({ name: jsName, description }));
		}
		if (!(name in tools)) tools[name] = fn;
	}
	Object.freeze(tools);
	Object.freeze(allTools);

	// Reading a member that does not exist throws an error that names the close matches, instead of
	// a later "not a function". \`in\` checks still work.
	const comparable = (name) => name.toLowerCase().replace(/[^a-z0-9]/g, "");
	function guard(target, label, names, hint) {
		return new Proxy(target, {
			get(object, property, receiver) {
				if (typeof property !== "string" || property in object || property in Object.prototype || property === "then" || property === "toJSON") {
					return Reflect.get(object, property, receiver);
				}
				const wanted = comparable(property);
				const exact = names.filter((name) => comparable(name) === wanted);
				const close = exact.length > 0 ? exact : names.filter((name) => wanted && (comparable(name).includes(wanted) || wanted.includes(comparable(name))));
				let message = label + "." + property + " does not exist.";
				if (close.length > 0) message += " Did you mean " + close.slice(0, 5).map((name) => label + "." + name).join(", ") + "?";
				else if (names.length <= 20) message += " Available: " + names.join(", ") + ".";
				if (hint) message += " " + hint;
				message += ' Check for a member with "' + property + '" in ' + label + ".";
				throw new TypeErrorCtor(message);
			},
		});
	}
	const toolsProxy = guard(
		tools,
		"tools",
		allTools.map((tool) => tool.name),
		"ALL_TOOLS lists every tool; searchTools(query) finds tools by topic.",
	);

	const namespaces = new Map();
	for (const { name, spread } of parse(globalsJson)) {
		const fn = caller("global", name, spread);
		const dot = name.indexOf(".");
		if (dot === -1) {
			Object.defineProperty(globalThis, name, { value: fn, enumerable: true });
			continue;
		}
		const namespace = name.slice(0, dot);
		if (!namespaces.has(namespace)) namespaces.set(namespace, Object.create(null));
		namespaces.get(namespace)[name.slice(dot + 1)] = fn;
	}
	for (const [namespace, members] of namespaces) {
		Object.freeze(members);
		const value = guard(members, namespace, Object.keys(members));
		Object.defineProperty(globalThis, namespace, { value, enumerable: true });
	}

	// key -> JSON text. Sizes count key and JSON characters.
	const stored = new Map(Object.entries(parse(storeJson)));
	const writes = new Map();
	let storedChars = 0;
	for (const [key, json] of stored) storedChars += key.length + json.length;

	const STORE_HINT =
		"store() is for small state such as IDs or summaries. Show images with image(), keep large data in variables, or write it to a file with a tool.";

	function checkKey(name, key) {
		if (typeof key !== "string") throw new TypeError(name + "() key must be a string");
	}

	function store(key, value) {
		checkKey("store", key);
		const previous = stored.has(key) ? key.length + stored.get(key).length : 0;
		if (value === undefined) {
			stored.delete(key);
			storedChars -= previous;
			writes.set(key, undefined);
			return;
		}
		let json;
		try {
			json = stringify(value);
		} catch (error) {
			throw new TypeError("store(" + stringify(key) + ") value is not JSON-serializable: " + format(error));
		}
		if (json === undefined) {
			throw new TypeError("store(" + stringify(key) + ") value is not JSON-serializable");
		}
		if (json.length > ${MAX_STORE_VALUE_CHARS}) {
			throw new RangeError(
				"store(" + stringify(key) + ") value has " + json.length + " characters of JSON, more than the limit of ${MAX_STORE_VALUE_CHARS}. " +
					STORE_HINT,
			);
		}
		const next = storedChars - previous + key.length + json.length;
		if (next > ${MAX_STORE_TOTAL_CHARS}) {
			throw new RangeError(
				"store is full: stored values would exceed ${MAX_STORE_TOTAL_CHARS} characters of JSON. Delete keys with store(key, undefined). " +
					STORE_HINT,
			);
		}
		stored.set(key, json);
		storedChars = next;
		writes.set(key, json);
	}

	function load(key) {
		checkKey("load", key);
		const json = stored.get(key);
		return json === undefined ? undefined : parse(json);
	}

	function serializeWrites() {
		const entries = [];
		for (const [key, json] of writes) entries.push(json === undefined ? [key] : [key, json]);
		return stringify(entries);
	}

	Object.defineProperty(globalThis, "store", { value: store, enumerable: true });
	Object.defineProperty(globalThis, "load", { value: load, enumerable: true });

	let outputChars = 0;
	let outputItems = 0;

	// Past the output limits the script fails: done() reports the error, so catching it does not
	// resume output, and the host ends the script.
	function output(kind, data, mimeType) {
		if (finished) return;
		outputChars += data.length;
		outputItems++;
		if (outputChars > ${MAX_OUTPUT_CHARS} || outputItems > ${MAX_OUTPUT_ITEMS}) {
			const error = new RangeErrorCtor(
				"script output exceeded the limit of ${MAX_OUTPUT_CHARS} characters or ${MAX_OUTPUT_ITEMS} text(), image(), and console calls. " +
					"Print a summary instead, or write large data to a file with a tool.",
			);
			done(false, describeError(error));
			throw error;
		}
		bridge("output", kind, data, mimeType);
	}

	// Primitives become their string form, everything else JSON.
	function outputText(value) {
		if (value === undefined || value === null || typeof value !== "object" && typeof value !== "function") {
			return String(value);
		}
		const json = stringify(value);
		return json === undefined ? String(value) : json;
	}

	function text(value) {
		let rendered;
		try {
			rendered = outputText(value);
		} catch (error) {
			throw new TypeErrorCtor(error instanceof ErrorCtor ? error.message : String(error));
		}
		output("text", rendered);
	}

	function imageUrl(value) {
		if (typeof value === "string") return value;
		if (typeof value !== "object" || value === null || Array.isArray(value)) {
			throw new TypeErrorCtor(${JSON.stringify(IMAGE_HELPER_EXPECTS)});
		}
		if (value.image_url !== undefined) {
			if (typeof value.image_url !== "string") throw new TypeErrorCtor(${JSON.stringify(IMAGE_HELPER_EXPECTS)});
			return value.image_url;
		}
		if (typeof value.type !== "string") throw new TypeErrorCtor(${JSON.stringify(IMAGE_HELPER_EXPECTS)});
		if (value.type !== "image") {
			throw new TypeErrorCtor('image only accepts image blocks, got "' + value.type + '"');
		}
		if (typeof value.data !== "string" || value.data === "") throw new TypeErrorCtor("image expected image block data");
		if (value.data.toLowerCase().startsWith("data:")) return value.data;
		return "data:;base64," + value.data;
	}

	// Base64 of the signatures of the formats providers accept inline (PNG, JPEG except
	// JPEG-LS, GIF, "RIFF....WEBP"). Signatures start at byte 0, so their encodings are prefixes.
	const IMAGE_SIGNATURES = [
		["image/png", /^iVBORw0KGg/],
		["image/jpeg", /^[/]9j[/](?!9)/],
		["image/gif", /^R0lGOD[dl]h/],
		["image/webp", /^UklG.{8}RUJQ/],
	];

	function image(value) {
		const url = imageUrl(value);
		if (url === "") throw new TypeErrorCtor(${JSON.stringify(IMAGE_HELPER_EXPECTS)});
		const colon = url.indexOf(":");
		const scheme = colon === -1 ? "" : url.slice(0, colon).toLowerCase();
		if (scheme === "http" || scheme === "https") {
			throw new TypeErrorCtor("remote image URLs are not supported in tool outputs. Pass a base64 data URI instead");
		}
		const comma = url.indexOf(",");
		const header = comma === -1 ? [] : url.slice(colon + 1, comma).split(";");
		if (scheme !== "data" || comma === -1 || header.slice(1).every((part) => part.toLowerCase() !== "base64")) {
			throw new TypeErrorCtor("invalid image output. Pass a base64 data URI instead");
		}
		// Providers reject the whole request on a bad image, and a persisted image block would be
		// resent on every later turn. Line breaks from wrapped base64 are dropped. The declared type
		// is ignored in favor of the detected one, as providers also reject mismatches.
		const data = url.slice(comma + 1).replace(/\\s+/g, "");
		if (data.length % 4 !== 0 || !/^[A-Za-z0-9+/]+={0,2}$/.test(data)) {
			throw new TypeErrorCtor("invalid image output. The image data is not valid base64 (truncated or corrupted?)");
		}
		const head = data.slice(0, 16);
		const signature = IMAGE_SIGNATURES.find(([, pattern]) => pattern.test(head));
		if (!signature) {
			throw new TypeErrorCtor("invalid image output. The image data is not a PNG, JPEG, GIF, or WebP image");
		}
		output("image", data, signature[0]);
	}

	function exit() {
		let writesJson;
		try {
			writesJson = serializeWrites();
		} catch (error) {
			done(false, describeError(error));
			throw EXIT;
		}
		done(true, undefined, writesJson);
		throw EXIT;
	}

	const console = {};
	for (const level of ["log", "info", "warn", "error", "debug"]) {
		console[level] = (...args) => {
			output("console", args.map(format).join(" "));
		};
	}
	Object.freeze(console);

	Object.defineProperty(globalThis, "tools", { value: toolsProxy, enumerable: true });
	Object.defineProperty(globalThis, "ALL_TOOLS", { value: allTools, enumerable: true });
	Object.defineProperty(globalThis, "console", { value: console, enumerable: true });
	Object.defineProperty(globalThis, "text", { value: text, enumerable: true });
	Object.defineProperty(globalThis, "image", { value: image, enumerable: true });
	Object.defineProperty(globalThis, "exit", { value: exit, enumerable: true });

	return {
		settle(id, ok, payload, propertiesJson) {
			const entry = pending.get(id);
			if (!entry) return;
			pending.delete(id);
			if (!ok) {
				const error = new ErrorCtor(payload);
				if (propertiesJson !== undefined) {
					const properties = parse(propertiesJson);
					for (const key of Object.keys(properties)) {
						if (key === "name" || key === "message" || key === "stack") continue;
						Object.defineProperty(error, key, { value: properties[key], writable: true, enumerable: true, configurable: true });
					}
				}
				entry.reject(error);
				return;
			}
			let value;
			try {
				value = payload === undefined ? undefined : parse(payload);
			} catch (error) {
				entry.reject(error);
				return;
			}
			entry.resolve(value);
		},
		run(fn) {
			let promise;
			try {
				promise = fn(toolsProxy, console);
			} catch (error) {
				done(false, describeError(error));
				return;
			}
			promiseThen.call(
				promise,
				(value) => {
					let json;
					try {
						json = serialize(value);
					} catch (error) {
						done(false, describeError(error));
						return;
					}
					done(true, json, serializeWrites());
				},
				(error) => {
					done(false, describeError(error));
				},
			);
		},
		stalled() {
			if (finished || pending.size > 0) return false;
			done(
				false,
				stringify({
					name: "Error",
					message:
						"The script is waiting on a promise that can never settle: no tool call is pending, and timers do not exist here.",
				}),
			);
			return true;
		},
	};
})`;

/**
 * Drives one QuickJS VM through one script, independent of the transport that connects it to the
 * host. The worker thread, the in-thread launcher, and the remote server all run the VM through
 * this module, so the bridge between prelude and host exists once.
 *
 * Contract with the caller:
 * - `post` receives every message for the host, synchronously from inside VM callbacks. The
 *   caller must not re-enter the VM from `post` (no `deliver`, no `dispose`); a worker posts to
 *   another thread, and the in-thread launcher defers delivery to a microtask.
 * - `deliver` hands the VM a tool result and runs the script until it waits again. It must only be
 *   called while the VM is idle, which holds for any caller that never re-enters from `post`.
 * - `shouldInterrupt` is polled by QuickJS while the script runs, and here between batches of
 *   promise jobs. Returning true throws an uncatchable error in the script; the VM then reports
 *   `crash` or a failed `done`. The job batches matter for a script such as `while (true) await
 *   null`: every iteration is a separate job that executes only a few opcodes, so QuickJS's own
 *   polling, which counts opcodes, would let it run for a long time between polls.
 * - The VM never decides on its own when it is finished: after `done` or `crash` it stays alive
 *   until the caller disposes it (or terminates the worker that hosts it).
 *
 * Failures after the VM exists are reported as a `crash` message; `startVm` only rejects when the
 * VM cannot be created at all.
 *
 * Deterministic mode (`data.deterministic`, used by `CodemodeSandboxBase.start()`): a script must make the same
 * calls with the same arguments every time it runs with the same results, so a host can replay it after a restart.
 * The VM is otherwise deterministic, because it only runs when the host delivers something and has no timers.
 * What remains is fixed here:
 * - Time: every WASI clock reads virtual time, `startedAt` and then the `now` of the result being processed, never going backwards.
 *   While the context is created, the realtime clock reads a value derived from the seed instead, because QuickJS
 *   seeds `Math.random()` from the first clock read, and which read comes first is the engine's business.
 * - Randomness: `random_get` draws from a PRNG over the seed.
 * - Timezone: UTC, not the host's.
 * - Garbage collection: `WeakRef` and `FinalizationRegistry` are not available; collection timing is not.
 * - Delivery order: results carry a `seq` and are applied strictly in that order, buffering early ones, because a
 *   transport (RPC replies) may deliver them in another order than the host sent them.
 * The VM reports `started` with its fingerprint before the script runs, and `idle` with the number of calls issued
 * after each drain, so the host can check a replay step by step.
 */
/**
 * Bumped whenever this module or the prelude changes what a deterministic script observes, beyond what the
 * fingerprint's other parts (engine versions, prelude hash, limits) already capture.
 */
const DETERMINISTIC_VERSION = 1;
/** FNV-1a over UTF-16 code units, as 8 hex digits: identifies the prelude in the fingerprint. */
function fnv1a(text) {
    let hash = 0x811c9dc5;
    for (let index = 0; index < text.length; index++) {
        hash ^= text.charCodeAt(index);
        hash = Math.imul(hash, 0x01000193);
    }
    return (hash >>> 0).toString(16).padStart(8, "0");
}
const PRELUDE_HASH = fnv1a(PRELUDE_SOURCE);
/** mulberry32: a small, fast PRNG; one 32-bit draw per call. */
function prng(seed) {
    let state = seed >>> 0;
    return () => {
        state = (state + 0x6d2b79f5) >>> 0;
        let value = Math.imul(state ^ (state >>> 15), 1 | state);
        value = (value + Math.imul(value ^ (value >>> 7), 61 | value)) ^ value;
        return (value ^ (value >>> 14)) >>> 0;
    };
}
/** WASI clock and random functions for deterministic mode, on top of {@link discardOutput}. */
function deterministicWasi(clock) {
    const random = prng(clock.seed ^ 0x9e3779b9);
    return (memory) => ({
        ...discardOutput(memory),
        clock_time_get(clockId, _precision, resultPtr) {
            let nanoseconds;
            // QuickJS seeds Math.random() from this reading in microseconds and turns 0 into 1, so seed s reads s + 1.
            if (clock.creating)
                nanoseconds = clockId === 0 ? BigInt(clock.seed + 1) * 1000n : 0n;
            else if (clockId === 0)
                nanoseconds = BigInt(Math.round(clock.now)) * 1000000n;
            else
                nanoseconds = BigInt(Math.round(clock.now - clock.startedAt)) * 1000000n;
            new DataView(memory.buffer).setBigUint64(resultPtr, nanoseconds, true);
            return 0;
        },
        random_get(bufPtr, bufLen) {
            const bytes = new Uint8Array(memory.buffer, bufPtr, bufLen);
            for (let index = 0; index < bufLen; index += 4) {
                const value = random();
                for (let byte = 0; byte < 4 && index + byte < bufLen; byte++)
                    bytes[index + byte] = value >>> (byte * 8);
            }
            return 0;
        },
    });
}
/**
 * QuickJS writes engine diagnostics to fd 1 and 2, which the default shim
 * forwards to the host's stdout and stderr. That output belongs to the host
 * application (for example a TUI), so it is discarded. Reporting every byte as
 * written keeps libc from retrying.
 */
function discardOutput(memory) {
    return {
        fd_write(_fd, iovsPtr, iovsLen, nwrittenPtr) {
            const view = new DataView(memory.buffer);
            let written = 0;
            for (let i = 0; i < iovsLen; i++) {
                written += view.getUint32(iovsPtr + i * 8 + 4, true);
            }
            view.setUint32(nwrittenPtr, written, true);
            return 0;
        },
    };
}
function describeException(error) {
    const head = error.message ? `${error.name}: ${error.message}` : error.name;
    const stack = error.stack?.trimEnd();
    return JSON.stringify({ name: error.name, message: error.message, stack: stack ? `${head}\n${stack}` : head });
}
/** Promise jobs run between two `shouldInterrupt` polls while draining the job queue. */
const JOBS_PER_POLL = 50;
function crashMessage(error) {
    return { type: "crash", message: error instanceof Error ? `${error.name}: ${error.message}` : String(error) };
}
async function startVm(options) {
    const { data, post } = options;
    const maxStackSize = options.maxStackSize ?? MAX_STACK_SIZE;
    const deterministic = data.deterministic;
    const clock = deterministic && {
        creating: true,
        startedAt: deterministic.startedAt,
        now: deterministic.startedAt,
        seed: deterministic.seed >>> 0,
    };
    const vm = await QuickJS.create({
        wasm: options.wasm,
        memoryLimit: data.memoryLimitBytes,
        // Without a guard, deep recursion overflows the wasm stack and traps instead of throwing a
        // catchable RangeError.
        maxStackSize,
        interruptHandler: options.shouldInterrupt,
        wasi: clock ? deterministicWasi(clock) : discardOutput,
        ...(clock ? { timezoneOffset: 0, intrinsics: Intrinsics.ALL & -513 } : {}),
    });
    if (clock)
        clock.creating = false;
    let disposed = false;
    /** Calls the script has issued, tools and globals; reported with every `idle`. */
    let issued = 0;
    /** Deterministic mode: the next result to apply, and results that arrived before it. */
    let nextSeq = 1;
    /** The result being processed, 0 during the script's first run; reported with `done`. */
    let current = 0;
    const early = new Map();
    const apply = (message) => {
        vm.withScope(() => {
            vm.callFunction(settle, api, vm.newNumber(message.id), message.ok ? vm.true : vm.false, message.payload === undefined ? vm.undefined : vm.newString(message.payload), message.properties === undefined ? vm.undefined : vm.newString(message.properties));
        });
        drain();
    };
    const session = {
        deliver(message) {
            if (disposed)
                return;
            try {
                if (!clock) {
                    apply(message);
                    return;
                }
                const { seq } = message;
                if (seq === undefined || !Number.isInteger(seq) || seq < nextSeq || early.has(seq)) {
                    throw new Error(`Result ${message.id} has sequence number ${seq}, expected ${nextSeq} or later, once`);
                }
                early.set(seq, message);
                for (let next = early.get(nextSeq); next !== undefined; next = early.get(nextSeq)) {
                    early.delete(nextSeq);
                    // Never backwards: a resumed host's clock may be behind the one that started the run.
                    if (next.now !== undefined && Number.isFinite(next.now))
                        clock.now = Math.max(clock.now, next.now);
                    current = nextSeq;
                    apply(next);
                    post({ type: "idle", seq: nextSeq, issued });
                    nextSeq++;
                }
            }
            catch (error) {
                post(crashMessage(error));
            }
        },
        dispose() {
            if (disposed)
                return;
            disposed = true;
            vm.dispose();
        },
    };
    let api;
    let settle;
    let stalled;
    // `executePendingJobs()` runs the queue to empty without a chance to interrupt, so jobs run one at a
    // time through the (internal, but public) exports; quickjs-wasi is pinned to an exact version.
    const exports = vm._getExports();
    /** Run queued jobs, then fail a script that waits on nothing that can ever resume it. */
    const drain = () => {
        let jobs = 0;
        while (exports.qjs_is_job_pending()) {
            // A job only fails for uncatchable errors, such as an interrupt.
            if (exports.qjs_execute_pending_job() < 0)
                throw new Error("Promise job failed");
            if (++jobs % JOBS_PER_POLL === 0 && options.shouldInterrupt())
                throw new Error("Execution interrupted");
        }
        vm.callFunction(stalled, api).dispose();
    };
    try {
        // Called from the prelude with primitives only.
        const bridge = vm.newFunction("bridge", (kind, a, b, c) => {
            switch (kind.toString()) {
                case "call":
                case "global":
                    issued++;
                    post({
                        type: "call",
                        id: a.toNumber(),
                        target: kind.toString() === "call" ? "tool" : "global",
                        name: b.toString(),
                        args: c === undefined || c.isUndefined ? undefined : c.toString(),
                    });
                    break;
                case "output":
                    post({
                        type: "output",
                        item: a.toString() === "image"
                            ? { type: "image", data: b.toString(), mimeType: c.toString() }
                            : a.toString() === "console"
                                ? { type: "text", text: b.toString(), console: true }
                                : { type: "text", text: b.toString() },
                    });
                    break;
                case "done": {
                    // The host stops the VM on `done`, so the `idle` of this drain never arrives: report its numbers here.
                    const during = clock ? { during: { seq: current, issued } } : {};
                    if (a.toBoolean()) {
                        post({
                            type: "done",
                            ok: true,
                            value: b === undefined || b.isUndefined ? undefined : b.toString(),
                            writes: c.toString(),
                            ...during,
                        });
                    }
                    else {
                        post({ type: "done", ok: false, error: b.toString(), ...during });
                    }
                    break;
                }
            }
            return vm.undefined;
        });
        // These handles live as long as the VM, which the caller disposes as a whole.
        api = vm.withScope((scope) => scope.escape(vm.callFunction(vm.evalCode(PRELUDE_SOURCE, "codemode-prelude.js"), vm.undefined, bridge, vm.newString(JSON.stringify(data.tools)), vm.newString(JSON.stringify(data.globals)), vm.newString(JSON.stringify(data.store)))));
        settle = api.getProp("settle");
        const run = api.getProp("run");
        stalled = api.getProp("stalled");
        if (clock) {
            const versions = vm.versions;
            const budget = options.interruptBudget ?? "none";
            post({
                type: "started",
                fingerprint: `quickjs-wasi ${versions["quickjs-wasi"]}, quickjs ${versions.quickjs}, prelude ${PRELUDE_HASH}, deterministic ${DETERMINISTIC_VERSION}, stack ${maxStackSize}, heap ${data.memoryLimitBytes ?? "none"}, budget ${budget}`,
            });
        }
        // The prefix shares the first line with the script so reported line numbers
        // match the script as written.
        let fn;
        try {
            fn = vm.evalCode(`(async (tools, console) => {${data.code}\n})`, "codemode.js");
        }
        catch (error) {
            if (!(error instanceof JSException))
                throw error;
            post({ type: "done", ok: false, error: describeException(error) });
            return session;
        }
        vm.callFunction(run, api, fn).dispose();
        fn.dispose();
        drain();
        if (clock)
            post({ type: "idle", seq: 0, issued });
    }
    catch (error) {
        post(crashMessage(error));
    }
    return session;
}

/**
 * Worker thread entry. One worker runs one script inside a fresh QuickJS VM
 * (a separate wasm instance), relays tool calls and output to the host, and
 * reports the result. The host terminates the worker when the script settles,
 * times out, or is aborted; the worker exists so that a spinning script never
 * blocks the host thread.
 *
 * Importing this module starts the worker. Hosts that bundle their code (for
 * example a Bun compiled executable) add a file that imports
 * `@earendil-works/pi-codemode/worker` as a separate entrypoint and pass its URL
 * or embedded-module string specifier as `workerUrl`.
 */
function post(message) {
    node_worker_threads.parentPort?.postMessage(message);
}
async function main(data) {
    const interrupt = new Int32Array(data.interrupt);
    // The VM lives until the host terminates the worker, so the session is never disposed.
    const session = await startVm({
        data,
        wasm: data.wasm,
        post,
        shouldInterrupt: () => Atomics.load(interrupt, 0) !== 0,
    });
    node_worker_threads.parentPort?.on("message", (message) => {
        if (isHostToWorkerMessage(message))
            session.deliver(message);
    });
}
if (node_worker_threads.parentPort) {
    main(node_worker_threads.workerData).catch((error) => {
        post({ type: "crash", message: error instanceof Error ? `${error.name}: ${error.message}` : String(error) });
    });
}
