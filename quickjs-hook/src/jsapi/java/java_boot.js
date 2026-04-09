// Java.use() API — Frida-compatible syntax for Java method hooking
// Evaluated at engine init after C-level Java.hook/unhook/_methods/_fieldMeta/_readField/_writeField are registered.
(function() {
    "use strict";
    var _hook = Java.hook;
    var _unhook = Java.unhook;
    var _methods = Java._methods;
    var _invokeStaticMethod = Java._invokeStaticMethod;
    var _newObject = Java._newObject;
    var _fieldMeta = Java._fieldMeta;
    var _readField = Java._readField;
    var _writeField = Java._writeField;
    var _classLoaders = Java._classLoaders;
    var _findClassWithLoader = Java._findClassWithLoader;
    var _setClassLoader = Java._setClassLoader;
    delete Java.hook;
    delete Java.unhook;
    delete Java._methods;
    delete Java._invokeStaticMethod;
    delete Java._newObject;
    delete Java._fieldMeta;
    delete Java._readField;
    delete Java._writeField;
    delete Java._classLoaders;
    delete Java._findClassWithLoader;
    delete Java._setClassLoader;

    function _argsFrom(argsLike, start) {
        var args = [];
        for (var i = start || 0; i < argsLike.length; i++) {
            args.push(argsLike[i]);
        }
        return args;
    }

    function _isWrappedJavaObject(value) {
        return value !== null && typeof value === "object"
            && value.__jptr !== undefined;
    }

    function _wrapJavaReturn(value) {
        if (_isWrappedJavaObject(value)) {
            return _wrapJavaObj(value.__jptr, value.__jclass);
        }
        return value;
    }

    function _invokeJavaMethod(jptr, jcls, name, sig, args) {
        return _wrapJavaReturn(
            Java._invokeMethod.apply(Java, [jptr, jcls, name, sig].concat(args))
        );
    }

    function _invokeJavaStaticMethod(jcls, name, sig, args) {
        return _wrapJavaReturn(
            _invokeStaticMethod.apply(Java, [jcls, name, sig].concat(args))
        );
    }

    // 简单的 JNI 签名解析，将 "(IILjava/lang/String;)V" → ["I","I","Ljava/lang/String;"]
    function _parseJniParams(jniSig) {
        var res = [];
        var start = jniSig.indexOf('(') + 1;
        var i = start;
        while (i < jniSig.length && jniSig[i] !== ')') {
            var end = i + 1;
            if (jniSig[i] === 'L') {
                while (end < jniSig.length && jniSig[end] !== ';') end++;
                end++;
            } else if (jniSig[i] === '[') {
                while (end < jniSig.length && jniSig[end] === '[') end++;
                if (end < jniSig.length && jniSig[end] === 'L') {
                    end++;
                    while (end < jniSig.length && jniSig[end] !== ';') end++;
                    end++;
                } else {
                    end++;
                }
            }
            res.push(jniSig.slice(i, end));
            i = end;
        }
        return res;
    }

    function _isJsValueCompatible(jsVal, jniType) {
        var t0 = jniType.charAt(0);
        if (jsVal === null || jsVal === undefined) {
            return t0 === 'L' || t0 === '[';
        }
        var jsType = typeof jsVal;
        if (t0 === 'Z') {
            return jsType === "boolean" || jsType === "number";
        }
        if (t0 === 'B' || t0 === 'S' || t0 === 'I'
            || t0 === 'F' || t0 === 'D') {
            return jsType === "number";
        }
        if (t0 === 'J') {
            return jsType === "bigint" || jsType === "number";
        }
        if (t0 === 'L') {
            if (jsType === "string") {
                return jniType === "Ljava/lang/String;";
            }
            return jsType === "object";
        }
        if (t0 === '[') {
            return Array.isArray(jsVal) || jsType === "object";
        }
        return false;
    }

    function _scoreOverload(methodInfo, jsArgs) {
        var paramTypes = _parseJniParams(methodInfo.sig);
        if (paramTypes.length !== jsArgs.length) {
            return -1;
        }

        var score = 0;
        for (var i = 0; i < paramTypes.length; i++) {
            if (!_isJsValueCompatible(jsArgs[i], paramTypes[i])) {
                return -1;
            }
            score += /^[L[]/.test(paramTypes[i]) ? 1 : 2;
        }
        return score;
    }

    function _resolveInstanceMethodSig(jcls, name, jsArgs) {
        var methods = _methods(jcls);
        var best = null;
        var bestScore = -1;

        for (var i = 0; i < methods.length; i++) {
            var methodInfo = methods[i];
            if (methodInfo.name !== name || methodInfo.static) {
                continue;
            }
            var score = _scoreOverload(methodInfo, jsArgs);
            if (score > bestScore) {
                best = methodInfo;
                bestScore = score;
            }
        }

        if (!best) {
            throw new Error("No instance method found: " + jcls + "." + name);
        }
        if (bestScore < 0) {
            throw new Error("No matching overload for " + jcls + "." + name
                + " with " + jsArgs.length + " argument(s)");
        }
        return best.sig;
    }

    function _resolveStaticMethodSig(jcls, name, jsArgs) {
        var methods = _methods(jcls);
        var best = null;
        var bestScore = -1;

        for (var i = 0; i < methods.length; i++) {
            var methodInfo = methods[i];
            if (methodInfo.name !== name || !methodInfo.static) {
                continue;
            }
            var score = _scoreOverload(methodInfo, jsArgs);
            if (score > bestScore) {
                best = methodInfo;
                bestScore = score;
            }
        }

        if (!best) {
            throw new Error("No static method found: " + jcls + "." + name);
        }
        if (bestScore < 0) {
            throw new Error("No matching static overload for " + jcls + "." + name
                + " with " + jsArgs.length + " argument(s)");
        }
        return best.sig;
    }

    function _resolveConstructorSig(jcls, jsArgs) {
        var methods = _methods(jcls);
        var best = null;
        var bestScore = -1;

        for (var i = 0; i < methods.length; i++) {
            var methodInfo = methods[i];
            if (methodInfo.name !== "<init>") {
                continue;
            }
            var score = _scoreOverload(methodInfo, jsArgs);
            if (score > bestScore) {
                best = methodInfo;
                bestScore = score;
            }
        }

        if (!best) {
            throw new Error("No constructor found: " + jcls);
        }
        if (bestScore < 0) {
            throw new Error("No matching constructor for " + jcls
                + " with " + jsArgs.length + " argument(s)");
        }
        return best.sig;
    }

    function _makeInstanceMethodInvoker(target, name) {
        return function() {
            var args = _argsFrom(arguments);
            var sig = typeof args[0] === "string" && args[0].charAt(0) === '('
                ? args.shift()
                : _resolveInstanceMethodSig(target.__jclass, name, args);

            return _invokeJavaMethod(
                target.__jptr,
                target.__jclass,
                name,
                sig,
                args
            );
        };
    }

    // ========================================================================
    // Frida-style FieldWrapper: obj.field 返回 FieldWrapper，通过 .value 读写
    //   obj.field.value        — 读（每次 JNI GetField，无 FIELD_CACHE 锁）
    //   obj.field.value = x    — 写（每次 JNI SetField，无 FIELD_CACHE 锁）
    // ========================================================================

    // 每个类的字段元数据缓存: cls → { prop → meta{id,sig,st,cls} | null }
    // null 表示已探测过但不是字段（即方法），避免重复 C 调用
    var _classFieldMeta = {};

    function _resolveFieldMeta(cls, prop, objPtr) {
        var cache = _classFieldMeta[cls];
        if (!cache) {
            cache = {};
            _classFieldMeta[cls] = cache;
        }
        if (prop in cache) return cache[prop];
        // 一次性 C 调用：解析 field_id/sig/isStatic，带 runtime class fallback
        var meta = _fieldMeta(cls, prop, objPtr);
        cache[prop] = (meta !== undefined) ? meta : null;
        return cache[prop];
    }

    function FieldWrapper(target, meta) {
        this._t = target;  // Proxy 的 backing {__jptr, __jclass}
        this._m = meta;     // {id: BigUint64, sig: string, st: boolean, cls: string}
    }

    Object.defineProperty(FieldWrapper.prototype, "value", {
        get: function() {
            var m = this._m;
            return _wrapJavaReturn(
                _readField(this._t.__jptr, m.id, m.sig, m.st, m.cls)
            );
        },
        set: function(v) {
            var m = this._m;
            _writeField(this._t.__jptr, m.id, m.sig, m.st, m.cls, v);
        },
        enumerable: true,
        configurable: true
    });

    FieldWrapper.prototype.toString = function() {
        try {
            var v = this.value;
            return String(v);
        } catch(e) {
            return "[FieldWrapper]";
        }
    };

    // ========================================================================
    // 方法名缓存 + hybrid wrapper（处理字段/方法同名冲突）
    // Java 允许同名字段和方法共存，JS 只有一个属性槽。
    // 同名时返回 hybrid：可调用（方法） + .value（字段）
    // ========================================================================

    var _classMethodNames = {};
    function _hasMethod(cls, name) {
        var set = _classMethodNames[cls];
        if (!set) {
            set = {};
            var ms = _methods(cls);
            for (var i = 0; i < ms.length; i++) set[ms[i].name] = true;
            _classMethodNames[cls] = set;
        }
        return !!set[name];
    }

    // 给函数对象挂 .value getter/setter（字段读写）
    function _decorateWithFieldValue(fn, target, meta) {
        Object.defineProperty(fn, "value", {
            get: function() {
                return _wrapJavaReturn(
                    _readField(target.__jptr, meta.id, meta.sig, meta.st, meta.cls)
                );
            },
            set: function(v) {
                _writeField(target.__jptr, meta.id, meta.sig, meta.st, meta.cls, v);
            },
            enumerable: true,
            configurable: true
        });
        return fn;
    }

    // Wrap a raw Java object pointer as a Proxy (Frida-compatible)
    // - 字段访问:   obj.fieldName          → FieldWrapper
    //              obj.fieldName.value     → 读取真实 JVM 值
    //              obj.fieldName.value = x → 写入 JVM 字段
    // - 同名冲突:   obj.name(args)         → 调用方法
    //              obj.name.value          → 读写字段
    // - 方法调用:
    //     1) 显式签名: obj.method("(Ljava/lang/String;)V", "arg")
    //     2) 自动匹配: obj.method("arg")
    // - 快捷调用:   obj.$call("methodName", "(sig)", ...args)
    function _wrapJavaObj(ptr, cls) {
        var target = {__jptr: ptr, __jclass: cls};
        var fieldWrappers = {};  // per-instance FieldWrapper 缓存

        var handler = {
            get: function(target, prop) {
                if (prop === "__jptr") return target.__jptr;
                if (prop === "__jclass") return target.__jclass;
                // Rust 内部属性穿透（__origJobject 用于 hook 返回值 round-trip）
                if (prop === "__origJobject") return target.__origJobject;
                if (prop === Symbol.toPrimitive) return function(hint) {
                    if (hint === "string" || hint === "default") {
                        try {
                            return String(_invokeJavaMethod(target.__jptr, target.__jclass, "toString", "()Ljava/lang/String;", []));
                        } catch(e) {}
                    }
                    return "[JavaObject:" + target.__jclass + "@" + target.__jptr + "]";
                };
                if (typeof prop !== "string") return undefined;
                if (prop === "toString") return function() {
                    try {
                        return _invokeJavaMethod(target.__jptr, target.__jclass, "toString", "()Ljava/lang/String;", []);
                    } catch(e) {
                        return "[JavaObject:" + target.__jclass + "]";
                    }
                };
                if (prop === "valueOf") return function() {
                    return "[JavaObject:" + target.__jclass + "@" + target.__jptr + "]";
                };
                if (prop === "$className") return target.__jclass;
                if (prop === "$call") {
                    return function(name, sig) {
                        if (typeof name !== "string" || typeof sig !== "string") {
                            throw new Error("obj.$call(name, sig, ...args) requires (string, string, ...)");
                        }
                        return _invokeJavaMethod(
                            target.__jptr,
                            target.__jclass,
                            name,
                            sig,
                            _argsFrom(arguments, 2)
                        );
                    };
                }

                // 已缓存 — 直接返回（FieldWrapper 或 hybrid 函数）
                if (fieldWrappers[prop]) return fieldWrappers[prop];

                // 解析字段元数据（per-class 缓存，首次走 C，后续纯 JS 查找）
                var meta = _resolveFieldMeta(target.__jclass, prop, target.__jptr);
                if (meta) {
                    var fw;
                    if (_hasMethod(target.__jclass, prop)) {
                        // 同名冲突：hybrid（可调用 + .value）
                        fw = _decorateWithFieldValue(
                            _makeInstanceMethodInvoker(target, prop), target, meta
                        );
                    } else {
                        fw = new FieldWrapper(target, meta);
                    }
                    fieldWrappers[prop] = fw;
                    return fw;
                }

                // 不是字段 → 方法
                return _makeInstanceMethodInvoker(target, prop);
            }
        };
        return new Proxy(target, handler);
    }

    function MethodWrapper(cls, method, sig, cache) {
        this._c = cls;
        this._m = method;
        this._s = sig || null;
        this._cache = cache || null;
    }

    // Convert Java type name to JNI type descriptor (mirrors Rust java_type_to_jni)
    function _jniType(t) {
        switch(t) {
            case "void": case "V": return "V";
            case "boolean": case "Z": return "Z";
            case "byte": case "B": return "B";
            case "char": case "C": return "C";
            case "short": case "S": return "S";
            case "int": case "I": return "I";
            case "long": case "J": return "J";
            case "float": case "F": return "F";
            case "double": case "D": return "D";
            default:
                if (t.charAt(0) === '[') return t.replace(/\./g, "/");
                return "L" + t.replace(/\./g, "/") + ";";
        }
    }

    // 获取方法列表（带缓存）
    function _getMethods(wrapper) {
        if (wrapper._cache && wrapper._cache.methods) return wrapper._cache.methods;
        var ms = _methods(wrapper._c);
        if (wrapper._cache) wrapper._cache.methods = ms;
        return ms;
    }

    // 根据参数签名前缀查找匹配的方法
    function _findOverload(ms, name, paramSig) {
        for (var i = 0; i < ms.length; i++) {
            if (ms[i].name === name && ms[i].sig.indexOf(paramSig) === 0) {
                return ms[i].sig;
            }
        }
        return null;
    }

    // Frida-compatible overload: accepts Java type names as arguments
    // e.g. .overload("java.lang.String", "int") → matches JNI sig "(Ljava/lang/String;I)..."
    // Also accepts raw JNI signature: .overload("(Ljava/lang/String;)I")
    // Also accepts arrays for multiple overloads: .overload(["int","int"], ["java.lang.String"])
    MethodWrapper.prototype.overload = function() {
        // Case 1: 数组语法，选择多个overload
        // .overload(["int", "int"], ["java.lang.String"])
        if (arguments.length >= 1 && Array.isArray(arguments[0])) {
            var ms = _getMethods(this);
            var name = this._m === "$init" ? "<init>" : this._m;
            var sigs = [];
            for (var a = 0; a < arguments.length; a++) {
                var params = arguments[a];
                var paramSig = "(";
                for (var i = 0; i < params.length; i++) {
                    paramSig += _jniType(params[i]);
                }
                paramSig += ")";
                var sig = _findOverload(ms, name, paramSig);
                if (!sig) {
                    throw new Error("No matching overload: " + this._c + "." + this._m + paramSig);
                }
                sigs.push(sig);
            }
            return new MethodWrapper(this._c, this._m, sigs, this._cache);
        }
        // Case 2: 原始JNI签名
        if (arguments.length === 1 && typeof arguments[0] === "string"
            && arguments[0].charAt(0) === '(') {
            return new MethodWrapper(this._c, this._m, arguments[0], this._cache);
        }
        // Case 3: Java类型名（现有行为）
        var paramSig = "(";
        for (var i = 0; i < arguments.length; i++) {
            paramSig += _jniType(arguments[i]);
        }
        paramSig += ")";
        var ms = _getMethods(this);
        var name = this._m === "$init" ? "<init>" : this._m;
        var sig = _findOverload(ms, name, paramSig);
        if (!sig) {
            throw new Error("No matching overload: " + this._c + "." + this._m + paramSig);
        }
        return new MethodWrapper(this._c, this._m, sig, this._cache);
    };

    Object.defineProperty(MethodWrapper.prototype, "impl", {
        get: function() { return this._fn || null; },
        set: function(fn) {
            var name = this._m === "$init" ? "<init>" : this._m;
            var cls = this._c;

            // 确定要hook的签名列表
            var sigs;
            if (this._s === null) {
                // 未指定overload：hook所有overload
                var ms = _getMethods(this);
                var match = [];
                for (var i = 0; i < ms.length; i++) {
                    if (ms[i].name === name) match.push(ms[i]);
                }
                if (match.length === 0)
                    throw new Error("Method not found: " + cls + "." + this._m);
                sigs = match.map(function(m) { return m.sig; });
            } else if (Array.isArray(this._s)) {
                // 通过数组语法指定的多个overload
                sigs = this._s;
            } else {
                // 单个overload
                sigs = [this._s];
            }

            if (fn === null || fn === undefined) {
                for (var i = 0; i < sigs.length; i++) {
                    _unhook(cls, name, sigs[i]);
                }
                this._fn = null;
            } else {
                var userFn = fn;
                var wrapCallback = function(ctx) {
                    if (ctx.thisObj !== undefined) {
                        ctx.thisObj = _wrapJavaObj(ctx.thisObj, cls);
                    }
                    if (ctx.args) {
                        for (var i = 0; i < ctx.args.length; i++) {
                            var a = ctx.args[i];
                            if (a !== null && typeof a === "object"
                                && a.__jptr !== undefined) {
                                ctx.args[i] = _wrapJavaObj(a.__jptr, a.__jclass);
                            }
                        }
                    }
                    // Wrap orig so returned objects auto-convert to JS Proxy
                    var origCallOriginal = ctx.orig;
                    ctx.orig = function() {
                        var ret = origCallOriginal.apply(ctx, arguments);
                        if (ret !== null && typeof ret === "object"
                            && ret.__jptr !== undefined) {
                            return _wrapJavaObj(ret.__jptr, ret.__jclass);
                        }
                        return ret;
                    };
                    return userFn(ctx);
                };
                for (var i = 0; i < sigs.length; i++) {
                    _hook(cls, name, sigs[i], wrapCallback);
                }
                this._fn = fn;
            }
        }
    });

    function _invokeStaticWrapper(wrapper, argsLike) {
        var args = _argsFrom(argsLike);
        var sig;

        if (wrapper._s === null) {
            sig = typeof args[0] === "string" && args[0].charAt(0) === '('
                ? args.shift()
                : _resolveStaticMethodSig(wrapper._c, wrapper._m, args);
        } else if (Array.isArray(wrapper._s)) {
            throw new Error("Cannot invoke multiple overloads at once: "
                + wrapper._c + "." + wrapper._m);
        } else {
            sig = wrapper._s;
        }

        return _invokeJavaStaticMethod(
            wrapper._c,
            wrapper._m === "$init" ? "<init>" : wrapper._m,
            sig,
            args
        );
    }

    function _invokeConstructorWrapper(wrapper, argsLike) {
        var args = _argsFrom(argsLike);
        var sig;

        if (wrapper._s === null) {
            sig = typeof args[0] === "string" && args[0].charAt(0) === '('
                ? args.shift()
                : _resolveConstructorSig(wrapper._c, args);
        } else if (Array.isArray(wrapper._s)) {
            throw new Error("Cannot invoke multiple constructor overloads at once: "
                + wrapper._c + "." + wrapper._m);
        } else {
            sig = wrapper._s;
        }

        return _wrapJavaReturn(
            _newObject.apply(Java, [wrapper._c, sig].concat(args))
        );
    }

    function _bindMethodWrapper(wrapper) {
        var callable = function() {
            if (wrapper._m === "$init") {
                return _invokeConstructorWrapper(wrapper, arguments);
            }
            return _invokeStaticWrapper(wrapper, arguments);
        };

        callable.overload = function() {
            return _bindMethodWrapper(MethodWrapper.prototype.overload.apply(wrapper, arguments));
        };

        Object.defineProperty(callable, "impl", {
            get: function() {
                return wrapper.impl;
            },
            set: function(fn) {
                wrapper.impl = fn;
            },
            enumerable: true,
            configurable: true
        });

        return callable;
    }

    Java.use = function(cls) {
        var cache = {};
        var wrappers = {};
        var staticFieldWrappers = {};
        // 静态字段用虚拟 target（_readField/isStatic=true 时 objPtr 被忽略）
        var staticTarget = {__jptr: 0, __jclass: cls};
        return new Proxy({}, {
            get: function(_, prop) {
                if (typeof prop !== "string") return undefined;
                if (prop === "$new") {
                    if (!cache._new) {
                        cache._new = function() {
                            var args = _argsFrom(arguments);
                            var sig = typeof args[0] === "string" && args[0].charAt(0) === '('
                                ? args.shift()
                                : _resolveConstructorSig(cls, args);
                            return _wrapJavaReturn(
                                _newObject.apply(Java, [cls, sig].concat(args))
                            );
                        };
                    }
                    return cache._new;
                }
                // 静态字段检查（per-class 缓存，仅首次走 C 调用）
                if (staticFieldWrappers[prop]) return staticFieldWrappers[prop];
                var meta = _resolveFieldMeta(cls, prop, 0);
                if (meta && meta.st) {
                    var fw;
                    if (_hasMethod(cls, prop)) {
                        // 同名冲突：方法可调用 + .value 读写静态字段
                        if (!wrappers[prop]) {
                            wrappers[prop] = _bindMethodWrapper(new MethodWrapper(cls, prop, null, cache));
                        }
                        fw = _decorateWithFieldValue(wrappers[prop], staticTarget, meta);
                    } else {
                        fw = new FieldWrapper(staticTarget, meta);
                    }
                    staticFieldWrappers[prop] = fw;
                    return fw;
                }
                // 方法
                if (!wrappers[prop]) {
                    wrappers[prop] = _bindMethodWrapper(new MethodWrapper(cls, prop, null, cache));
                }
                return wrappers[prop];
            },
            ownKeys: function(_) {
                if (cache._ownKeys) return cache._ownKeys;
                var ms = _methods(cls);
                var seen = {};
                var keys = [];
                keys.push("$new");
                for (var i = 0; i < ms.length; i++) {
                    var n = ms[i].name === "<init>" ? "$init" : ms[i].name;
                    if (!seen[n]) { seen[n] = true; keys.push(n); }
                }
                cache._ownKeys = keys;
                return keys;
            },
            getOwnPropertyDescriptor: function(_, prop) {
                if (typeof prop !== "string") return undefined;
                return {enumerable: true, configurable: true};
            }
        });
    };

    // ========================================================================
    // Java.ready(fn) — 延迟到 app dex 加载后执行
    //
    // spawn 模式下脚本在 setArgV0 阶段加载，此时 app ClassLoader 还未创建，
    // FindClass 只能找到 framework 类。Java.ready() 通过 hook 框架类
    // Instrumentation.newApplication (ClassLoader 作为第一个参数传入) 来检测
    // dex 加载完成，在 Application.attachBaseContext 之前触发用户回调。
    //
    // 非 spawn 模式（attach 已运行的进程）时 ClassLoader 已就绪，立即执行。
    // ========================================================================
    var _readyCallbacks = [];
    var _readyFired = false;
    var _readyGateSig = "(Ljava/lang/ClassLoader;Ljava/lang/String;Landroid/content/Context;)Landroid/app/Application;";

    Java.ready = function(fn) {
        if (typeof fn !== "function") {
            throw new Error("Java.ready() requires a function argument");
        }

        // ClassLoader 已就绪（非 spawn / 已触发过），立即执行
        if (_readyFired || Java._isClassLoaderReady()) {
            _readyFired = true;
            fn();
            return;
        }

        // 首个注册：安装 gate hook
        if (_readyCallbacks.length === 0) {
            _hook("android/app/Instrumentation", "newApplication", _readyGateSig, function(ctx) {
                // 先执行原始 newApplication。stealth2/recomp 下如果在编译方法入口
                // offset 0 就触发 FindClass/WalkStack，ART 可能在 GetDexPc/StackMap
                // 路径上看到当前 quick frame native_pc=0 并 abort。
                // 将 ClassLoader 更新和 ready 回调后置，避开“当前被 hook 编译帧”
                // 仍停在入口 PC 的窗口。
                var app = ctx.orig();

                // 从第一个参数获取 ClassLoader 并更新缓存
                if (ctx.args && ctx.args[0] !== null && ctx.args[0] !== undefined) {
                    var clPtr = ctx.args[0];
                    if (typeof clPtr === "object" && clPtr.__jptr !== undefined) {
                        clPtr = clPtr.__jptr;
                    }
                    Java._updateClassLoader(clPtr);
                }

                // 执行所有排队的回调 — 用户可在此安装 hook
                // 注意：用户可能重新 hook newApplication，所以先保存 orig 引用
                _readyFired = true;
                var cbs = _readyCallbacks;
                _readyCallbacks = [];
                for (var i = 0; i < cbs.length; i++) {
                    try {
                        cbs[i]();
                    } catch(e) {
                        console.log("[Java.ready] callback #" + i + " error: " + e);
                    }
                }

                return app;
            });
        }

        _readyCallbacks.push(fn);
    };

    Java.classLoaders = function() {
        return _classLoaders();
    };

    function _normalizeLoaderArg(loader) {
        if (loader !== null && typeof loader === "object") {
            if (loader.ptr !== undefined) {
                return loader.ptr;
            }
            if (loader.__jptr !== undefined) {
                return loader.__jptr;
            }
        }
        return loader;
    }

    Java.findClassWithLoader = function(loader, className) {
        if (typeof className !== "string") {
            throw new Error("Java.findClassWithLoader(loader, className) requires a string className");
        }
        return _findClassWithLoader(_normalizeLoaderArg(loader), className);
    };

    Java.setClassLoader = function(loader) {
        return _setClassLoader(_normalizeLoaderArg(loader));
    };
})();
