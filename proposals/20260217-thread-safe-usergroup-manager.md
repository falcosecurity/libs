# Proposal: Thread-Safe sinsp_usergroup_manager

## 1. Objective

Make **sinsp_usergroup_manager** safe for concurrent use when multiple threads call into it (e.g. event processing, filter/formatter evaluation, dump, and thread manager /proc lookup). The manager is shared via **m_usergroup_manager** (std::shared_ptr) between sinsp, thread_manager, and parsers; its internal tables are currently unsynchronized.

This work is part of the broader goal of **making Falco multithreaded** (see falcosecurity/falco PR 3751): once event processing, filtering, and other work can run concurrently, the usergroup manager will be accessed from multiple threads and must be safe under that usage.

## 2. Current state

### 2.1 Ownership and call sites

- **Held by:** sinsp (m_usergroup_manager), passed into thread_manager and parsers at construction.
- **Writes:** add_user, add_group, rm_user, rm_group, delete_container; m_import_users (bool) is written in sinsp.cpp and read in user.cpp and user.h.
- **Reads:** get_user, get_group, get_userlist, get_grouplist, dump_users_groups.

Call sites that can run on different threads (when sinsp is used concurrently):

| Call site | Operations |
|-----------|------------|
| thread_manager.cpp (get_thread proc path) | add_user, add_group |
| parsers.cpp (event handling) | add_user, add_group, rm_user, rm_group, delete_container |
| sinsp.cpp (init, proc scan) | add_user, add_group; m_import_users = ... |
| user.h user_group_updater destructor | add_user, add_group, delete_container; reads m_import_users |
| event.cpp (filter/formatter) | get_user, get_group |
| sinsp_filtercheck_user.cpp / sinsp_filtercheck_group.cpp | get_user, get_group |
| dumper.cpp | dump_users_groups |
| Tests | add_user, rm_user, get_user, etc. |

### 2.2 Internal state (user.h / user.cpp)

- **m_userlist** — `std::unordered_map<std::string, userinfo_map>` (container_id → uid → scap_userinfo).
- **m_grouplist** — `std::unordered_map<std::string, groupinfo_map>` (container_id → gid → scap_groupinfo).
- **m_import_users** — bool; read in add_user/add_group and in user_group_updater; written in sinsp.
- **m_fallback_user / m_fallback_grp** — used when m_import_users is false; written in add_user/add_group.
- **m_inspector, m_timestamper, m_host_root, m_ns_helper** — set at construction, effectively read-only.

No mutex or atomic is used today; concurrent read/write of the maps or m_import_users is a data race.

## 3. Proposed synchronization

### 3.1 Single shared_mutex (recommended)

- Add **mutable std::shared_mutex m_mutex** to sinsp_usergroup_manager.
- **Readers (shared lock):** get_user, get_group, get_userlist, get_grouplist, dump_users_groups. Hold the lock for the duration of the lookup. Return value must not expose references into the map after the lock is released (see API adjustments below).
- **Writers (unique lock):** add_user, add_group, rm_user, rm_group, delete_container. Take unique_lock for the whole operation.
- **m_import_users:** Make **std::atomic<bool>** so it can be read/written without holding the mutex, or protect reads/writes with the same mutex (shared for read, unique for write). Atomic is simpler and matches “config” usage.

### 3.2 API adjustments (to avoid holding the lock across caller code)

Today get_user/get_group return **raw pointers** into the map; get_userlist/get_grouplist return **const pointer to the map**. If we hold only a shared lock inside the method and then release it, the pointer can dangle as soon as another thread mutates the map. So we must not return pointers into the map that outlive the lock.

**Option A — Visitor pattern (recommended for get_user / get_group on the critical path):**

- **Avoid allocations in the hot path:** Returning a copy (e.g. std::optional&lt;scap_userinfo&gt;) can introduce allocations or a fixed-size copy on every call; on the event/formatter critical path, avoiding per-call allocations is desirable.
- **API:** Template visitor so callers get a **const reference** while the shared lock is held (no pointer escape, no copy; template avoids std::function allocation): **template&lt;typename V&gt; bool with_user(container_id, uid, V&amp;&amp; visitor);** and **with_group(...)** — if found, invoke visitor(entry), return true; else false. Callers read fields in the lambda and copy into their own storage. Lock held only during the visitor.
- **Internal use (add_user, add_group, rm_user, rm_group):** They hold the **unique** lock and need a pointer to modify or pass to notify_*. Do not call public with_user/with_group (deadlock). Keep a **private** lookup that assumes the mutex is held (e.g. get_user_assuming_lock_held(...)) and use it only from those four methods.
- **Option A' — Return a copy (fallback / tests):** Under shared lock, find and return a copy (e.g. std::optional&lt;scap_userinfo&gt; / optional&lt;scap_groupinfo&gt; or out-param). No shared buffer. Can be offered in addition to the visitor (e.g. for tests) as a thin wrapper that uses the visitor to fill an optional.

**Option B — Return shared_ptr to a copy of the per-container map:**

- **get_userlist(container_id):** Under shared lock, copy the userinfo_map for that container_id into a new std::unordered_map, return std::shared_ptr<const userinfo_map> (or return by value). Caller can iterate safely. Cost: one copy per call when the container exists.
- **get_grouplist(container_id):** Same for groupinfo_map.

**Option C — Keep pointer API but document “use immediately”:**

- Keep get_user/get_group returning raw pointers. Hold shared lock only while doing the lookup; return the pointer; release lock. Document that the pointer is **invalidated by any subsequent call** to add_user, add_group, rm_user, rm_group, delete_container (or any get that might resize), and that callers must not store the pointer or use it after any such call. This is brittle and not recommended for new code; only if we must avoid API churn.

**Recommendation:** Prefer **Option A (visitor)** for get_user/get_group on the critical path to avoid allocations and copies; offer **Option A' (return copy)** as an optional helper for tests or simpler call sites. Option B for get_userlist/get_grouplist (return a copy or shared_ptr to a copy of the requested container’s map). Option C only if we cannot change the public API.

**Impact of the visitor API (Option A):** Call sites are few and the change is localized. **event.cpp** (PT_UID / PT_GID): two places that today do get_user/get_group then copy name into a buffer; each becomes a single with_user/with_group call whose lambda does the same copy. **sinsp_filtercheck_user.cpp**: two get_user calls (user, loginuser) and a switch on fields — call with_user(uid, [&](const auto& u){ ... }) and with_user(loginuid, ...) and set m_strval (or fallbacks) inside the lambdas. **sinsp_filtercheck_group.cpp**: one get_group, use name — one with_group(..., [&](const auto& g){ m_name = g.name; }). **user.cpp** (add_user, add_group, rm_user, rm_group): no change to their logic; they use a **private** lookup that assumes the unique lock is held (get_user_assuming_lock_held / get_group_assuming_lock_held) instead of the public get_user/get_group. **Tests**: use the visitor with a lambda that ASSERTs on fields, or a small test helper that uses the visitor to fill an optional&lt;scap_userinfo&gt; for convenience. Overall the refactor is small and keeps the hot path allocation-free.

### 3.3 m_fallback_user / m_fallback_grp

When m_import_users is false, add_user/add_group write to m_fallback_user / m_fallback_grp and return &m_fallback_user or &m_fallback_grp. With concurrent callers, two threads could both do add_user and overwrite the fallback. Options: (1) protect fallback with the same mutex (add_user/add_group already take unique lock), and document that the returned pointer is to the manager’s internal fallback and is valid only until the next call; or (2) return a copy when using fallback. With (1), we still have the “pointer valid until next call” rule; with (2), we avoid exposing internal state. Prefer (2) for consistency with Option A: when m_import_users is false, return a copy (e.g. optional<scap_userinfo>) so no internal pointer is exposed.

### 3.4 dump_users_groups

Takes sinsp_dumper& and iterates m_userlist/m_grouplist. Under shared lock, either: (a) iterate and call dumper for each entry (lock held for full dump), or (b) take shared lock, copy the structures needed for the dump, release lock, then run the dump on the copy. (b) avoids holding the lock for a long time but uses more memory. Recommend (a) unless dumps are very large.

## 4. Summary table

| Item | Proposal |
|------|----------|
| **m_userlist / m_grouplist** | Protect with single **mutable std::shared_mutex m_mutex**. Readers: shared lock. Writers: unique lock. |
| **m_import_users** | **std::atomic<bool>** (or protect with same mutex). |
| **get_user / get_group** | **Visitor API** (with_user / with_group) on the critical path to avoid allocations; optional **return copy** (e.g. std::optional or out-param) for tests. Private lookup for add_* / rm_* under unique lock. |
| **get_userlist / get_grouplist** | Under shared lock, **return a copy** of the per-container map (or shared_ptr to copy) so callers do not hold references into the map. |
| **dump_users_groups** | Run under shared lock for the duration of the dump, or copy under lock and dump from copy. |
| **m_fallback_user / m_fallback_grp** | When m_import_users is false, return a copy from add_user/add_group (or protect with mutex and document pointer lifetime). |

## 5. Call site impact

- **event.cpp, sinsp_filtercheck_*.cpp:** Use with_user / with_group visitor; lambda copies needed fields (e.g. name) into existing buffers. Optional get_user/get_group that return a copy can be used for tests.
- **user.h user_group_updater:** Already calls add_user, add_group, delete_container; no change if signatures of add_* stay the same. m_import_users read: make it atomic so no change at call site.
- **dumper, tests:** get_userlist/get_grouplist returning a copy or shared_ptr may require call sites to hold the result (e.g. shared_ptr<const userinfo_map>) instead of const map*.

## 6. Out of scope

- Thread safety of **sinsp** or **parsers** beyond their use of m_usergroup_manager.
- Changing where m_usergroup_manager is stored (sinsp vs thread_manager); the proposal only makes the manager object itself thread-safe.

## 7. Testing

- Add or extend unit tests that call get_user/get_group (and optionally add_user/add_group, delete_container) from multiple threads under **TSAN**, with the same suppressions as thread_manager concurrent tests where applicable. No data races on m_userlist, m_grouplist, or m_import_users.

---

**Next step:** After your confirmation, implementation will: (1) add m_mutex and m_import_users as atomic or under mutex; (2) implement **with_user / with_group** (template visitor) and optional get_user/get_group that return a copy for tests; private get_user_assuming_lock_held / get_group_assuming_lock_held for add_* and rm_*; get_userlist/get_grouplist to return a copy or shared_ptr to a copy; (3) take shared/unique lock in all public methods as above; (4) update call sites (event.cpp, sinsp_filtercheck_*.cpp, user.cpp internal) and add/run concurrent tests under TSAN.
