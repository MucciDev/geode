## [HIGH][VULN-001] PATCH_UNBOUNDED_READ  
* **CWE Category:** CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer  
* **Vulnerability/Crash Type:** Out-of-bounds read / segmentation fault  
* **Specific File & Line:** `loader/src/loader/PatchImpl.cpp`:26-32  
* **The Chain of Failure:**  
  - A mod calls `Patch::Impl::create` with an arbitrary address/size.  
  - `readMemory` dereferences `address + i` for `amount` bytes without validating page readability.  
  - If the region crosses an unmapped/guard page, the process faults during patch creation, crashing before any guard rails execute.  
* **Impact:** A malicious or buggy mod can crash the host by requesting a patch over invalid memory, aborting initialization and risking partial state writes.  
* **Remediation Snippet:**  
```cpp
// Helper must validate OS page protections (e.g., via VirtualQuery/ mprotect checks).
static Result<ByteVector> safeReadMemory(void* address, size_t amount) {
    if (address == nullptr || amount == 0) {
        return Err("Invalid patch region");
    }
    std::byte const* ptr = static_cast<std::byte const*>(address);
    ByteVector ret;
    ret.reserve(amount);
    for (size_t i = 0; i < amount; i++) {
        auto current = ptr + i;
        if (!tulip::hook::isReadable(current, 1)) { // implement page-check helper if missing
            return Err("Patch source crosses unreadable memory");
        }
        ret.push_back(std::to_integer<uint8_t>(*current));
    }
    return Ok(std::move(ret));
}
```  

## [HIGH][VULN-002] PATCH_THREAD_UNSAFE_VECTOR  
* **CWE Category:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization  
* **Vulnerability/Crash Type:** Data race / heap corruption  
* **Specific File & Line:** `loader/src/loader/PatchImpl.cpp`:44-47, 54-92  
* **The Chain of Failure:**  
  - `Patch::Impl::allEnabled` returns a static `std::vector` shared across threads.  
  - `enable()` and `disable()` mutate the vector with no locking.  
  - Concurrent enable/disable operations can corrupt the vector’s internal state, leading to invalid pointers when hooks fire.  
* **Impact:** Multi-threaded patch toggling can crash the game or corrupt executable code paths, producing undefined behavior.  
* **Remediation Snippet:**  
```cpp
static std::vector<Patch::Impl*>& allEnabled() {
    static std::vector<Patch::Impl*> vec;
    return vec;
}
static std::mutex& allEnabledMutex() {
    static std::mutex m;
    return m;
}

Result<> Patch::Impl::enable() {
    std::scoped_lock lock(allEnabledMutex());
    // overlap checks ...
    GEODE_UNWRAP(tulip::hook::writeMemory(m_address, m_patch.data(), m_patch.size()));
    allEnabled().push_back(this);
    m_enabled = true;
    return Ok();
}
```  

## [HIGH][VULN-003] HANDLER_REFCOUNT_RACE  
* **CWE Category:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization  
* **Vulnerability/Crash Type:** Use-after-free / double free of hook handlers  
* **Specific File & Line:** `loader/src/loader/LoaderImpl.cpp`:1196-1225  
* **The Chain of Failure:**  
  - Handler reference counts in `m_handlerHandles[address].second` are mutated without atomic or mutex protection.  
  - Two threads can simultaneously increment/decrement, causing the count to hit zero while a handler is still live.  
  - `removeHandlerIfNeeded` then destroys the handler, leaving other threads with dangling function pointers.  
* **Impact:** Premature handler removal can crash TulipHook dispatch or enable arbitrary code execution through stale pointers.  
* **Remediation Snippet:**  
```cpp
mutable std::mutex m_handlerMutex;

Result<tulip::hook::HandlerHandle> Loader::Impl::getOrCreateHandler(...){
    std::scoped_lock lock(m_handlerMutex);
    // existing logic with guarded refcount changes
}

Result<tulip::hook::HandlerHandle> Loader::Impl::getAndDecreaseHandler(void* address){
    std::scoped_lock lock(m_handlerMutex);
    // decrement with underflow check
}

Result<> Loader::Impl::removeHandlerIfNeeded(void* address){
    std::scoped_lock lock(m_handlerMutex);
    // remove only after protected zero-check
}
```  

## [HIGH][VULN-004] MODS_MAP_UNGUARDED  
* **CWE Category:** CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization  
* **Vulnerability/Crash Type:** Data race / iterator invalidation  
* **Specific File & Line:** `loader/src/loader/LoaderImpl.hpp`:29-38; `loader/src/loader/LoaderImpl.cpp`:235-465  
* **The Chain of Failure:**  
  - `m_mods` is read in `getInstalledMod`/`getLoadedMod`/`getAllMods` while being mutated in `populateModList`/`buildModGraph`.  
  - No locks guard these accesses even though `m_mutex` exists.  
  - Concurrent refresh can expose partially constructed entries or invalidate iterators used by other threads.  
* **Impact:** Crashes during mod refresh, stale pointers handed to hooks/UI, and possible use-after-free on mods.  
* **Remediation Snippet:**  
```cpp
Mod* Loader::Impl::getLoadedMod(std::string_view id) const {
    std::scoped_lock lock(m_mutex);
    auto it = m_mods.find(id);
    return it == m_mods.end() ? nullptr : it->second;
}

void Loader::Impl::populateModList(...) {
    std::scoped_lock lock(m_mutex);
    // perform all insert/erase operations while holding the lock
}
```  

## [MEDIUM][VULN-005] PATCH_OVERLAP_CONTAINMENT_GAP  
* **CWE Category:** CWE-672: Operation on a Resource after Expiration or Release  
* **Vulnerability/Crash Type:** Patch overwrite / code corruption  
* **Specific File & Line:** `loader/src/loader/PatchImpl.cpp`:54-67  
* **The Chain of Failure:**  
  - Overlap detection only checks if this patch’s start or end falls inside another patch.  
  - A patch that fully contains an existing patch (`thisMin < otherMin && thisMax > otherMax`) is missed.  
  - The new patch overwrites bytes from the prior patch, silently corrupting the instruction stream.  
* **Impact:** Previously installed patches are clobbered, leading to unpredictable execution or crashes when the code path runs.  
* **Remediation Snippet:**  
```cpp
bool intersects = !(thisMax < otherMin || thisMin > otherMax);
if (intersects) {
    return Err("Failed to enable patch: overlaps patch at {}", otherMin);
}
```  

## [MEDIUM][VULN-006] DEPENDANTS_DANGLING_POINTERS  
* **CWE Category:** CWE-415/416: Double Free / Use After Free  
* **Vulnerability/Crash Type:** Dangling pointer dereference  
* **Specific File & Line:** `loader/src/loader/ModImpl.hpp`:43-48; `loader/src/loader/LoaderImpl.cpp`:436-465  
* **The Chain of Failure:**  
  - `m_dependants` stores raw `Mod*` without lifetime control.  
  - When a dependent mod unloads, the pointer remains in the vector.  
  - Later dependency toggling iterates the vector and may call into freed memory.  
* **Impact:** Use-after-free during dependency propagation can crash the game or jump into reclaimed memory.  
* **Remediation Snippet:**  
```cpp
std::vector<std::weak_ptr<Mod>> m_dependants;
for (auto it = m_dependants.begin(); it != m_dependants.end();) {
    if (auto dep = it->lock()) {
        // safe use of dep
        ++it;
    } else {
        it = m_dependants.erase(it); // prune expired
    }
}
```  

## [MEDIUM][VULN-007] ZIP_CANONICAL_TRAVERSAL_GAP  
* **CWE Category:** CWE-22: Path Traversal  
* **Vulnerability/Crash Type:** Arbitrary file overwrite  
* **Specific File & Line:** `loader/src/utils/file.cpp`:493-551 (check at 524-547)  
* **The Chain of Failure:**  
  - Extraction relies on `std::filesystem::relative(dir / filePath, dir)` without canonicalizing.  
  - Crafted entries using symlinks or mixed `..` segments can resolve outside `dir` after extraction.  
  - Files may be written to arbitrary locations before detection.  
* **Impact:** Malicious mods can overwrite files outside the mods directory, including binaries or user data.  
* **Remediation Snippet:**  
```cpp
auto target = std::filesystem::weakly_canonical(dir / filePath, ec);
auto base   = std::filesystem::weakly_canonical(dir, ec);
if (ec || target.native().compare(0, base.native().size(), base.native()) != 0) {
    return Err("Zip entry escapes extraction root");
}
```  

## [MEDIUM][VULN-008] MODJSON_UNBOUNDED_PARSE  
* **CWE Category:** CWE-400: Uncontrolled Resource Consumption  
* **Vulnerability/Crash Type:** OOM / denial of service  
* **Specific File & Line:** `loader/src/loader/ModMetadataImpl.cpp`:837-844  
* **The Chain of Failure:**  
  - `matjson::parse` consumes the entire `mod.json` entry with no size or depth guard.  
  - A crafted `.geode` can ship a multi-gigabyte JSON that is fully loaded into memory.  
  - Parsing exhausts memory before validation, crashing or stalling the loader.  
* **Impact:** Loader crashes during package parsing, preventing the game from launching.  
* **Remediation Snippet:**  
```cpp
constexpr size_t kMaxModJsonBytes = 1 * 1024 * 1024; // chosen to stay well above typical <100KB metadata; make configurable.
if (modJsonData.size() > kMaxModJsonBytes) {
    return Impl::createInvalidMetadata(path, "mod.json too large", guessedID);
}
matjson::ParseOptions opts;
opts.max_depth = 256;
auto modJsonRes = matjson::parse(modJsonData, opts)...
```  

## [MEDIUM][VULN-009] NEXTMOD_LOCK_LEAK  
* **CWE Category:** CWE-667: Improper Locking  
* **Vulnerability/Crash Type:** Deadlock  
* **Specific File & Line:** `loader/src/loader/LoaderImpl.hpp`:49-53; `loader/src/loader/LoaderImpl.cpp`:1107-1122  
* **The Chain of Failure:**  
  - `m_nextModLock` is manually managed with `std::defer_lock`.  
  - If `provideNextMod` throws/returns early, the lock may never be released.  
  - Waiting threads block on the condition variable forever, halting mod loading.  
* **Impact:** Loader hangs during initialization, preventing mods (and potentially the game UI) from progressing.  
* **Remediation Snippet:**  
```cpp
void Loader::Impl::provideNextMod(Mod* mod) {
    std::scoped_lock lock(m_nextModMutex);
    m_nextMod = mod;
    m_nextModCV.notify_all();
}
```  

## [LOW-MEDIUM][VULN-010] DOWNLOAD_NO_TIMEOUT  
* **CWE Category:** CWE-400: Uncontrolled Resource Consumption  
* **Vulnerability/Crash Type:** Denial of service via hung network call  
* **Specific File & Line:** `loader/src/server/DownloadManager.cpp`:176-189  
* **The Chain of Failure:**  
  - Downloads are issued with `req.get(downloadURL)` without timeouts.  
  - A stalled TCP connection leaves the request hanging indefinitely.  
  - UI threads waiting on completion can block, degrading gameplay and user experience.  
* **Impact:** The UI can freeze while awaiting a download that never completes, blocking updates.  
* **Remediation Snippet:**  
```cpp
req.setTimeout(std::chrono::seconds(15));
req.setConnectTimeout(std::chrono::seconds(5));
m_downloadListener.spawn(req.get(std::move(downloadURL)), ...);
```  
