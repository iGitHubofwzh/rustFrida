// ============================================================================
// Hook registry
// ============================================================================

/// Hook 类型：统一 Clone+Replace 策略
/// 所有回调统一 JNI 调用约定: x0=JNIEnv*, x1=this/jclass, x2+=args
#[derive(Debug)]
pub(super) enum HookType {
    /// Unified replacement hook (art_router swaps ArtMethod*)
    /// - replacement_addr: heap-allocated replacement ArtMethod (native, jniCode=thunk)
    /// - per_method_hook_target: Some(quickCode) for compiled methods (Layer 3 router hook),
    ///   None for shared stub methods (routed via Layer 1/2)
    Replaced {
        replacement_addr: usize,
        per_method_hook_target: Option<u64>,
    },
}

pub(super) struct JavaHookData {
    pub(super) art_method: u64,
    // Frida-style original method state（unhook 时恢复全部字段）
    pub(super) original_access_flags: u32,
    pub(super) original_entry_point: u64, // quickCode / entry_point_
    pub(super) original_data: u64,        // data_ / jniCode
    // Hook 路径类型
    pub(super) hook_type: HookType,
    // Backup clone for callOriginal (heap, 原始状态副本)
    pub(super) clone_addr: u64,
    // JNI global ref to jclass (for JNI CallNonvirtual/Static calls)
    pub(super) class_global_ref: usize,
    // Return type char from JNI signature: b'V', b'I', b'J', b'Z', b'L', etc.
    pub(super) return_type: u8,
    // Full return type descriptor from signature (e.g. "V", "I", "Ljava/lang/String;", "[B")
    pub(super) return_type_sig: String,
    // JS callback info
    pub(super) ctx: usize,
    pub(super) callback_bytes: [u8; 16],
    pub(super) method_key: String, // "class.method.sig" for lookup
    pub(super) is_static: bool,
    pub(super) param_count: usize,
    // Per-parameter JNI type descriptors (e.g. ["I", "Ljava/lang/String;", "[B"])
    pub(super) param_types: Vec<String>,
    // Hooked class name (dot notation, for wrapping object args)
    #[allow(dead_code)]
    pub(super) class_name: String,
    /// Layer 3 art_router trampoline 地址 (quickCode 原始指令 + jump back)。
    /// callback skip fallback 用它直接调原始方法，避免走 JNI re-entry 路径。
    /// 0 = 无 trampoline（非 compiled 方法，走 Layer 1/2 路由）。
    pub(super) quick_trampoline: u64,
}

unsafe impl Send for JavaHookData {}
unsafe impl Sync for JavaHookData {}

/// Global Java hook registry keyed by art_method address
pub(super) static JAVA_HOOK_REGISTRY: Mutex<Option<HashMap<u64, JavaHookData>>> = Mutex::new(None);

/// Thunk 在途计数的真实存储在 C 侧 `g_thunk_in_flight`，由 art_router prologue/
/// epilogue 的 LDADDAL 汇编指令原子增减。Rust 侧只做读取和轮询。
///
/// 原来的 `IN_FLIGHT_JAVA_HOOK_CALLBACKS` 是在 JS callback dispatch 首尾做 Rust 侧
/// Mutex inc/dec——覆盖范围是"JS callback 执行期间"，不包含 thunk prologue/scan/
/// restore/BR 等汇编段。改为 thunk 汇编自身计数后，drain==0 意味着"没有任何线程
/// 的 PC 还在 thunk 内，也没有任何栈帧保存了 thunk 内的返回地址"（用户要求的语义）。
///
/// 历史占位: 汇编侧 LDADDAL 直接管理 g_thunk_in_flight, Rust 侧此 guard 为空壳,
/// 保留是为了避免一次性改动所有 callback 调用点。enter/drop 均为 NO-OP。
pub(super) struct InFlightJavaHookGuard;

impl InFlightJavaHookGuard {
    pub(super) fn enter() -> Self {
        Self
    }
}

impl Drop for InFlightJavaHookGuard {
    fn drop(&mut self) {}
}

/// 读 C 全局 `g_thunk_in_flight`。
pub(super) fn in_flight_java_hook_callbacks() -> usize {
    unsafe {
        std::ptr::read_volatile(&crate::ffi::hook::g_thunk_in_flight) as usize
    }
}

/// 轮询 g_thunk_in_flight 至 0。粒度 20ms，真实归零后额外再等 BR_SETTLE_MS
/// 让 LDADDAL(dec) 之后的 "ldr x16, target; br x16" 两条指令彻底离开 thunk。
pub(super) fn wait_for_in_flight_java_hook_callbacks(timeout: std::time::Duration) -> bool {
    const POLL_MS: u64 = 20;
    const BR_SETTLE_MS: u64 = 50; // 等 dec 之后 ldr+br 窗口真正执行完
    let start = std::time::Instant::now();
    loop {
        let cnt = in_flight_java_hook_callbacks();
        if cnt == 0 {
            std::thread::sleep(std::time::Duration::from_millis(BR_SETTLE_MS));
            // 再次确认（万一 settle 期间又有线程混进来：此时 hooks 已 unpatch，
            // 理论上不会，但稳妥起见再读一次）
            if in_flight_java_hook_callbacks() == 0 {
                return true;
            }
        }
        if start.elapsed() >= timeout {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(POLL_MS));
    }
}

/// Parse JNI signature to extract the return type character.
/// "(II)V" → b'V', "(Ljava/lang/String;)Ljava/lang/Object;" → b'L'
pub(super) fn get_return_type_from_sig(sig: &str) -> u8 {
    if let Some(pos) = sig.rfind(')') {
        let ret = &sig[pos + 1..];
        match ret.as_bytes().first() {
            Some(&c) => c,
            None => b'V',
        }
    } else {
        b'V'
    }
}

/// Extract the full return type descriptor from a JNI method signature.
/// "(II)V" → "V", "(I)Ljava/lang/String;" → "Ljava/lang/String;", "()[B" → "[B"
pub(super) fn get_return_type_sig(sig: &str) -> String {
    if let Some(pos) = sig.rfind(')') {
        sig[pos + 1..].to_string()
    } else {
        "V".to_string()
    }
}

pub(super) fn init_java_registry() {
    ensure_registry_initialized(&JAVA_HOOK_REGISTRY);
}

/// Build a unique key string for method lookup
pub(super) fn method_key(class: &str, method: &str, sig: &str) -> String {
    format!("{}.{}{}", class, method, sig)
}
