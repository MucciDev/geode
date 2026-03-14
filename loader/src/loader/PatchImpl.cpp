#include "PatchImpl.hpp"

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <utility>
#include "LoaderImpl.hpp"

#ifdef GEODE_IS_WINDOWS
#include <Windows.h>
#elif defined(GEODE_IS_MACOS) || defined(GEODE_IS_IOS)
#include <mach/mach.h>
#else
#include <sys/uio.h>
#include <unistd.h>
#endif

namespace {
    size_t getPageSize() {
#ifdef GEODE_IS_WINDOWS
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        return info.dwPageSize;
#else
        auto const pageSize = sysconf(_SC_PAGESIZE);
        return pageSize > 0 ? static_cast<size_t>(pageSize) : 4096;
#endif
    }

    Result<> readMemoryWindow(std::byte const* source, uint8_t* destination, size_t amount) {
        if (amount == 0) {
            return Ok();
        }

#ifdef GEODE_IS_WINDOWS
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(
                GetCurrentProcess(),
                source,
                destination,
                amount,
                &bytesRead
            ) || bytesRead != amount) {
            return Err(
                "Patch source crosses unreadable memory at address 0x{:x}",
                reinterpret_cast<uintptr_t>(source)
            );
        }
#elif defined(GEODE_IS_MACOS) || defined(GEODE_IS_IOS)
        mach_vm_size_t bytesRead = 0;
        auto const result = mach_vm_read_overwrite(
            mach_task_self(),
            reinterpret_cast<mach_vm_address_t>(source),
            amount,
            reinterpret_cast<mach_vm_address_t>(destination),
            &bytesRead
        );
        if (result != KERN_SUCCESS || bytesRead != amount) {
            return Err(
                "Patch source crosses unreadable memory at address 0x{:x}",
                reinterpret_cast<uintptr_t>(source)
            );
        }
#else
        iovec local {
            .iov_base = destination,
            .iov_len = amount
        };
        iovec remote {
            .iov_base = const_cast<std::byte*>(source),
            .iov_len = amount
        };
        auto const bytesRead = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
        if (bytesRead < 0 || static_cast<size_t>(bytesRead) != amount) {
            return Err(
                "Patch source crosses unreadable memory at address 0x{:x}",
                reinterpret_cast<uintptr_t>(source)
            );
        }
#endif

        return Ok();
    }
}

Patch::Impl::Impl(void* address, ByteSpan original, ByteSpan patch) :
    m_address(address),
    m_original(original.begin(), original.end()),
    m_patch(patch.begin(), patch.end()) {}
Patch::Impl::~Impl() {
    if (m_enabled) {
        auto res = this->disable();
        if (!res) {
            log::error("Failed to disable patch: {}", res.unwrapErr());
        }
    }
    if (m_owner) {
        auto res = m_owner->disownPatch(m_self);
        if (!res) {
            log::error("Failed to disown patch: {}", res.unwrapErr());
        }
    }
}

static Result<ByteVector> readMemory(void* address, size_t amount) {
    if (address == nullptr) {
        return Err("Invalid patch source: null address");
    }

    ByteVector ret(amount);
    if (amount == 0) {
        return Ok(std::move(ret));
    }

    auto const* ptr = static_cast<std::byte const*>(address);
    auto const pageSize = getPageSize();
    size_t i = 0;

    while (i < amount) {
        auto const current = ptr + i;
        auto const offset = reinterpret_cast<uintptr_t>(current) % pageSize;
        auto const window = std::min(pageSize - offset, amount - i);
        GEODE_UNWRAP(readMemoryWindow(current, ret.data() + i, window));
        i += window;
    }

    return Ok(std::move(ret));
}

std::shared_ptr<Patch> Patch::Impl::create(void* address, ByteSpan patch) {
    auto vecRes = readMemory(address, patch.size());
    ByteVector originalBytes;
    std::optional<std::string> creationError;
    if (!vecRes) {
        creationError = vecRes.unwrapErr();
        log::error("Failed to create patch at {}: {}", address, creationError.value());
    } else {
        originalBytes = std::move(vecRes.unwrap());
    }
    auto impl = std::make_shared<Impl>(
        address, ByteSpan(originalBytes), patch
    );
    if (creationError) {
        impl->m_creationError = std::move(creationError.value());
    }
    return std::shared_ptr<Patch>(new Patch(std::move(impl)), [](Patch* patch) {
        delete patch;
    });
}

std::vector<Patch::Impl*>& Patch::Impl::allEnabled() {
    static std::vector<Patch::Impl*> vec;
    return vec;
}

std::mutex& Patch::Impl::allEnabledMutex() {
    static std::mutex mutex;
    return mutex;
}

Result<> Patch::Impl::enable() {
    if (m_creationError) {
        return Err("Failed to enable patch: {}", m_creationError.value());
    }
    if (m_patch.empty()) {
        return Err("Failed to enable patch: patch has no bytes");
    }
    if (m_enabled) {
        return Ok();
    }

    std::scoped_lock lock(allEnabledMutex());

    auto const thisMin = this->getAddress();
    auto const thisMax = this->getAddress() + this->m_patch.size() - 1;
    // TODO: this feels slow. can be faster
    for (const auto& other : allEnabled()) {
        auto const otherMin = other->getAddress();
        auto const otherMax = other->getAddress() + other->m_patch.size() - 1;
        bool intersects = !(thisMax < otherMin || thisMin > otherMax);
        if (!intersects)
            continue;
        return Err(
            "Failed to enable patch: overlaps patch at {} from {}",
            other->m_address, other->getOwner()->getID()
        );
    }
    auto res = tulip::hook::writeMemory(m_address, m_patch.data(), m_patch.size());
    if (!res) return Err("Failed to enable patch: {}", res.unwrapErr());
    m_enabled = true;
    allEnabled().push_back(this);
    return Ok();
}

Result<> Patch::Impl::disable() {
    if (!m_enabled) {
        return Ok();
    }

    std::scoped_lock lock(allEnabledMutex());

    auto res = tulip::hook::writeMemory(m_address, m_original.data(), m_original.size());
    if (!res) return Err("Failed to disable patch: {}", res.unwrapErr());

    m_enabled = false;
    auto it = std::find(allEnabled().begin(), allEnabled().end(), this);

    if (it == allEnabled().end()) {
        return Err("Failed to disable patch: patch is already disabled");
    }

    allEnabled().erase(it);
    return Ok();
}

Result<> Patch::Impl::toggle() {
    return this->toggle(!m_enabled);
}

Result<> Patch::Impl::toggle(bool enable) {
    if (enable) {
        return this->enable();
    }
    else {
        return this->disable();
    }
}

ByteVector const& Patch::Impl::getBytes() const {
    return m_patch;
}

Result<> Patch::Impl::updateBytes(ByteSpan bytes) {
    m_patch = {bytes.begin(), bytes.end()};

    if (m_enabled) {
        auto res = this->disable();
        if (!res) return Err("Failed to update patch: {}", res.unwrapErr());
        auto res2 = this->enable();
        if (!res2) return Err("Failed to update patch: {}", res2.unwrapErr());
    }

    return Ok();
}

uintptr_t Patch::Impl::getAddress() const {
    return reinterpret_cast<uintptr_t>(m_address);
}

matjson::Value Patch::Impl::getRuntimeInfo() const {
    auto json = matjson::Value::object();
    json["address"] = std::to_string(reinterpret_cast<uintptr_t>(m_address));
    json["original"] = m_original;
    json["patch"] = m_patch;
    json["enabled"] = m_enabled;
    return json;
}
