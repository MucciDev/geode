[HIGH] - PATCH_UNBOUNDED_READ  
* **CWE Category:** CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer  
* **Vulnerability/Crash Type:** Out-of-bounds read / segmentation fault  
* **Specific File & Line:** `loader/src/loader/PatchImpl.cpp`:26-32  
* **The Chain of Failure:** A mod invokes `Patch::Impl::create` with an address/size that points into an unmapped or guard page. `readMemory` performs raw pointer arithmetic and dereferences `address + i` for `amount` bytes with no validation or page protection checks. If the requested region crosses an unmapped boundary, the process faults while the patch is being created, crashing the game before any safety checks run.  
* **Impact:** A malicious or buggy mod can crash the host process by requesting a patch over invalid memory, preventing gameplay and potentially corrupting state mid-initialization.  
* **Remediation Snippet:**  
```cpp
static Result<ByteVector> safeReadMemory(void* address, size_t amount) {
    if (amount == 0 || address == nullptr) {
        return Err("Invalid patch region");
    }
    std::byte const* ptr = static_cast<std::byte const*>(address);
    ByteVector ret;
    ret.reserve(amount);
    for (size_t i = 0; i < amount; i++) {
        auto current = ptr + i;
        if (!tulip::hook::isReadable(current, 1)) { // requires helper that checks page protection
            return Err("Patch source crosses unreadable memory");
        }
        ret.push_back(std::to_integer<uint8_t>(*current));
    }
    return Ok(std::move(ret));
}
```  

[HIGH] - PATCH_THREAD_UNSAFE_VECTOR  
* **CWE Category:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization  
* **Vulnerability/Crash Type:** Data race / heap corruption  
* **Specific File & Line:** `loader/src/loader/PatchImpl.cpp`:44-47, 54-92  
* **The Chain of Failure:** `Patch::Impl::allEnabled` returns a static `std::vector` mutated in `enable()`/`disable()` without any locking. If two threads enable/disable patches concurrently (possible during parallel mod load), simultaneous `push_back`/`erase` corrupts the vector, causing heap corruption and undefined behavior when hooks execute.  
* **Impact:** Multi-threaded patch toggling can crash the game or corrupt executable code, leading to unpredictable behavior or exploitation.  
* **Remediation Snippet:**  
```cpp
static std::vector<Patch::Impl*>& allEnabled() {
    static std::vector<Patch::Impl*> vec;
    static std::mutex vecMutex;
    return vec;
}

Result<> Patch::Impl::enable() {
    std::scoped_lock lock(allEnabledMutex());
    // existing overlap checks ...
    GEODE_UNWRAP(tulip::hook::writeMemory(m_address, m_patch.data(), m_patch.size()));
    allEnabled().push_back(this);
    m_enabled = true;
    return Ok();
}
```  

[HIGH] - HANDLER_REFCOUNT_RACE  
* **CWE Category:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization  
* **Vulnerability/Crash Type:** Use-after-free / double free of hook handlers  
* **Specific File & Line:** `loader/src/loader/LoaderImpl.cpp`:1196-1225  
* **The Chain of Failure:** Handler reference counts in `m_handlerHandles[address].second` are incremented/decremented without any mutex or atomic protection. If two threads simultaneously call `getOrCreateHandler` and `getAndDecreaseHandler`, the count can underflow to zero prematurely, leading `removeHandlerIfNeeded` to delete a handler still in use by another thread.  
* **Impact:** Premature handler removal results in dangling function pointers invoked by TulipHook, causing crashes or arbitrary code execution.  
* **Remediation Snippet:**  
```cpp
std::mutex m_handlerMutex;

Result<tulip::hook::HandlerHandle> Loader::Impl::getOrCreateHandler(...){
    std::scoped_lock lock(m_handlerMutex);
    // existing logic
}

Result<tulip::hook::HandlerHandle> Loader::Impl::getAndDecreaseHandler(void* address){
    std::scoped_lock lock(m_handlerMutex);
    // decrement with bounds check
}

Result<> Loader::Impl::removeHandlerIfNeeded(void* address){
    std::scoped_lock lock(m_handlerMutex);
    // remove only after protected check
}
```  

[HIGH] - MODS_MAP_UNGUARDED  
* **CWE Category:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization  
* **Vulnerability/Crash Type:** Data race / iterator invalidation  
* **Specific File & Line:** `loader/src/loader/LoaderImpl.hpp`:29-38; `loader/src/loader/LoaderImpl.cpp`:235-465  
* **The Chain of Failure:** The shared `m_mods` map is mutated (`populateModList`, `buildModGraph`) and read (`getInstalledMod`, `getLoadedMod`, `getAllMods`) without holding `m_mutex`. Concurrent refresh of the mod list while another thread queries it can invalidate iterators or expose partially constructed Mod pointers.  
* **Impact:** Crashes during mod refresh or stale/dangling pointers passed to hooks/UI, leading to use-after-free or logic corruption.  
* **Remediation Snippet:**  
```cpp
Mod* Loader::Impl::getLoadedMod(std::string_view id) const {
    std::scoped_lock lock(m_mutex);
    if (!m_mods.contains(id)) return nullptr;
    return m_mods.at(id);
}

void Loader::Impl::populateModList(...) {
    std::scoped_lock lock(m_mutex);
    // mutate m_mods exclusively while locked
}
```  

[MEDIUM] - PATCH_OVERLAP_CONTAINMENT_GAP  
* **CWE Category:** CWE-672: Operation on a Resource after Expiration or Release  
* **Vulnerability/Crash Type:** Patch overwrite / code corruption  
* **Specific File & Line:** `loader/src/loader/PatchImpl.cpp`:54-67  
* **The Chain of Failure:** Overlap detection only checks if this patch’s start or end falls within another patch. A patch that fully contains an existing patch (`thisMin < otherMin && thisMax > otherMax`) is not detected and will overwrite the other patch’s bytes.  
* **Impact:** Previously installed patches are silently corrupted, leading to unpredictable instruction streams and possible crashes when the code executes.  
* **Remediation Snippet:**  
```cpp
bool intersects = !(thisMax < otherMin || thisMin > otherMax);
if (intersects) {
    return Err("Failed to enable patch: overlaps patch at {}", otherMin);
}
```  

[MEDIUM] - DEPENDANTS_DANGLING_POINTERS  
* **CWE Category:** CWE-415: Double Free / CWE-416: Use After Free  
* **Vulnerability/Crash Type:** Dangling pointer dereference  
* **Specific File & Line:** `loader/src/loader/ModImpl.hpp`:43-48; `loader/src/loader/LoaderImpl.cpp`:436-465  
* **The Chain of Failure:** `m_dependants` stores raw `Mod*` without lifetime management. When a dependent mod unloads, its pointer remains in the vector; later iteration assumes validity, potentially calling into freed memory when toggling dependencies.  
* **Impact:** Use-after-free during dependency propagation can crash the game or execute freed memory.  
* **Remediation Snippet:**  
```cpp
std::vector<std::weak_ptr<Mod>> m_dependants;
// when iterating
for (auto it = m_dependants.begin(); it != m_dependants.end();) {
    if (auto dep = it->lock()) {
        // safe use
        ++it;
    } else {
        it = m_dependants.erase(it); // prune expired
    }
}
```  

[MEDIUM] - ZIP_CANONICAL_TRAVERSAL_GAP  
* **CWE Category:** CWE-22: Path Traversal  
* **Vulnerability/Crash Type:** Arbitrary file overwrite  
* **Specific File & Line:** `loader/src/utils/file.cpp`:493-551 (check at 524-547)  
* **The Chain of Failure:** Extraction uses `std::filesystem::relative(dir / filePath, dir)` to decide containment but does not canonicalize paths. Crafted entries with symlinks or mixed `..`/`.` segments can resolve outside `dir`, allowing overwrite of files such as the loader binary or user data.  
* **Impact:** Malicious mod can write outside the mods directory, potentially clobbering executables or injecting files for later load.  
* **Remediation Snippet:**  
```cpp
auto target = std::filesystem::weakly_canonical(dir / filePath, ec);
auto base   = std::filesystem::weakly_canonical(dir, ec);
if (ec || target.native().compare(0, base.native().size(), base.native()) != 0) {
    return Err("Zip entry escapes extraction root");
}
```  

[MEDIUM] - MODJSON_UNBOUNDED_PARSE  
* **CWE Category:** CWE-400: Uncontrolled Resource Consumption  
* **Vulnerability/Crash Type:** OOM / denial of service  
* **Specific File & Line:** `loader/src/loader/ModMetadataImpl.cpp`:837-844  
* **The Chain of Failure:** `matjson::parse` is invoked on an unbounded `std::string` built from the entire `mod.json` entry with no size checks. A malicious `.geode` containing a multi-gigabyte JSON will be fully loaded into memory, exhausting resources before validation.  
* **Impact:** Loader crashes or stalls during package parsing, preventing game start.  
* **Remediation Snippet:**  
```cpp
constexpr size_t kMaxModJsonBytes = 1 * 1024 * 1024; // 1 MB cap
if (modJsonData.size() > kMaxModJsonBytes) {
    return Impl::createInvalidMetadata(path, "mod.json too large", guessedID);
}
matjson::ParseOptions opts;
opts.max_depth = 256;
auto modJsonRes = matjson::parse(modJsonData, opts)...
```  

[MEDIUM] - NEXTMOD_LOCK_LEAK  
* **CWE Category:** CWE-667: Improper Locking  
* **Vulnerability/Crash Type:** Deadlock  
* **Specific File & Line:** `loader/src/loader/LoaderImpl.hpp`:49-53; `loader/src/loader/LoaderImpl.cpp`:1107-1122  
* **The Chain of Failure:** `m_nextModLock` is constructed with `std::defer_lock` and manually locked/unlocked. If `provideNextMod` throws or early-returns, the lock may never be released, blocking other threads waiting for the condition variable and deadlocking mod loading.  
* **Impact:** Loader hangs, preventing mods from initializing; may stall game startup.  
* **Remediation Snippet:**  
```cpp
void Loader::Impl::provideNextMod(Mod* mod) {
    std::scoped_lock lock(m_nextModMutex);
    m_nextMod = mod;
    m_nextModCV.notify_all();
}
```  

[LOW-MEDIUM] - DOWNLOAD_NO_TIMEOUT  
* **CWE Category:** CWE-400: Uncontrolled Resource Consumption  
* **Vulnerability/Crash Type:** Denial of service via hung network call  
* **Specific File & Line:** `loader/src/server/DownloadManager.cpp`:176-189  
* **The Chain of Failure:** Downloads are initiated with `req.get(downloadURL)` without specifying timeouts. A stalled TCP connection leaves the request hanging indefinitely, blocking UI awaiting completion and consuming threads/resources.  
* **Impact:** The UI can freeze while waiting for a download that never completes, degrading gameplay and blocking updates.  
* **Remediation Snippet:**  
```cpp
req.setTimeout(std::chrono::seconds(15));
req.setConnectTimeout(std::chrono::seconds(5));
m_downloadListener.spawn(
    req.get(std::move(downloadURL)),
    ...
);
```  
