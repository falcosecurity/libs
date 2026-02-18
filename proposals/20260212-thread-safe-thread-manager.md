# Proposal: Thread-Safe Thread Manager Using Folly ConcurrentHashMap

## 1. Objective

Make the sinsp thread manager **thread-safe for topology operations** (add thread, remove thread, lookup by TID, iteration over threads/processes) by replacing the current storage with **Folly’s ConcurrentHashMap** ([folly/concurrency/ConcurrentHashMap.h](https://github.com/facebook/folly/blob/main/folly/concurrency/ConcurrentHashMap.h)). The proposal keeps the change **focused and less intrusive**: the container handles concurrency internally (wait-free readers, sharded writers, hazard pointers for safe reclamation), and the API can remain **closer to the current one** than a visitation-only design—e.g. `get_thread` can return a **copy** of a `shared_ptr` (cheap) via Folly’s `at()` or `find()`. Internal synchronization of **sinsp_threadinfo** (in-place field updates) remains **out of scope** for this proposal.

---

## 2. Context and motivation

A previous proposal ([20251127-thread-safe-sinsp-thread-manager-implementation-plan.md](20251127-thread-safe-sinsp-thread-manager-implementation-plan.md)) aimed for a thread-safe thread manager using **RCU (Read-Copy-Update)** with custom intrusive lists and a pre-allocated table. That approach proved **challenging and intrusive**. Alternatives such as **boost::concurrent_flat_map** require a **visitation-only** API (no iterators), which would force a larger API rewrite (e.g. `with_thread`/`loop_threads` only, no direct `get_thread` returning a handle).

Using **Folly’s ConcurrentHashMap** instead:

- **Offloads concurrency** to a well-tested, production-grade container: wait-free readers, sharded writers, hazard pointers for safe reclamation after erase.
- **Supports iterator-based and copy-based access:** `find(k)` returns a **ConstIterator**; elements are valid while the iterator is held. `at(k)` and `operator[]` return a **copy** of the value (so with `ValueType = std::shared_ptr<sinsp_threadinfo>`, `at(tid)` is a cheap refcounted copy). **get_thread(tid)** / **find_thread(tid)** return a `shared_ptr` **by value** (copy from the map); no internal find cache is used, so lookups are thread-safe and callers may hold the result across other lookups.
- **Simultaneous iteration and erase() are safe:** the iterating thread may or may not see concurrent insertions/erasures; iterators hold hazard pointers so no use-after-free.
- **No custom RCU or retire logic:** Folly manages reclamation internally. `erase()`/`clear()` remove elements from the map immediately; actual destruction may be deferred until no hazard pointer references the object.
- **Lower migration cost:** existing code that expects `get_thread` → `shared_ptr` or iteration over threads can be preserved by building on `find()`/`at()` and `begin()`/`end()` (or a thin `loop_threads` wrapper that passes `shared_ptr` copies to a callback).

---

## 3. Scope

### 3.1 In scope

- **Thread-safe topology and container operations**
  - **Adding threads** to the table (e.g. on clone/fork, proc scan) from multiple threads.
  - **Removing threads** from the table (e.g. on exit, purging) from multiple threads.
  - **Lookup by TID** in a thread-safe way (via `find()` or `at()`).
  - **Iteration** over all threads in a thread-safe way (via `begin()`/`end()` or a wrapper that passes `shared_ptr` to a callback).
- **API evolution**
  - **Return `shared_ptr` by value** from `get_thread`/`find_thread` (and `add_thread`): caller receives a copy and holds a reference; no internal cache, so safe for concurrent use.
  - **No find cache**: the previous single-slot “last thread” / find-result cache is removed so that lookups are thread-safe and callers can hold the returned `shared_ptr` across other lookups.
  - **Minimal breaking change** where possible: keep `get_thread`/`find_thread` returning a `shared_ptr` (by value, copy from map); replace direct `get_threads()` table pointer with iteration API (`loop_threads` or explicit iteration over the map).
- **Data structure**
  - Replace current thread storage with **`folly::ConcurrentHashMap<int64_t, std::shared_ptr<sinsp_threadinfo>>`** (or equivalent). Topology (parent, group leader, children) stays inside sinsp_threadinfo or in auxiliary structures; add/remove and lookup/iteration are thread-safe via the container.
- **Tests**
  - **Test coverage** to validate that concurrent add/remove/lookup/iteration do not introduce data races or use-after-free (unit tests under **TSAN**, dedicated concurrency tests).

### 3.2 Out of scope (explicitly)

- **Internal synchronization of sinsp_threadinfo**  
  In-place updates to fields of an existing thread are **not** made thread-safe by this proposal. Callers that mutate a threadinfo are responsible for their own synchronization. The proposal only ensures that **container operations** (add, remove, find, iteration) are thread-safe.

- **FDTable thread-safety**  
  No changes to fd_table synchronization.

- **State table / plugin API**  
  Compatibility with existing plugin `get_entry` / `add_entry` / `erase_entry` is a requirement; the boundary can remain `shared_ptr`-based, implemented on top of the concurrent map.

---

## 4. Key design elements

### 4.1 Storage: Folly ConcurrentHashMap

- **Container:** `folly::ConcurrentHashMap<int64_t, std::shared_ptr<sinsp_threadinfo>>` (or `folly::ConcurrentHashMapSIMD<...>` for better cache behaviour when the map is large). Key = TID; value = `shared_ptr` so that:
  - **at(tid)** returns a **copy** of the `shared_ptr` (cheap; Folly’s API returns `const ValueType` by design to avoid exposing references that might outlive the container’s internal state).
  - **find(tid)** returns a **ConstIterator**; `it->second` is valid only while the iterator is held (hazard pointer keeps the element alive).
- **Operations (from Folly):**
  - **Insert:** `insert(tid, ptr)`, `try_emplace(tid, ...)`, or `emplace(...)` for add thread. Returns `std::pair<ConstIterator, bool>`.
  - **Erase:** `erase(tid)` or `erase(iterator)`. Elements are removed from the map immediately; actual destruction may be deferred (hazard pointers).
  - **Lookup:** `find(tid)` → ConstIterator (use while iterator valid); `at(tid)` → copy of value (throws if missing). **contains(tid)** is **deleted** in Folly to avoid TOCTOU; use `find(tid) != end()` instead.
  - **Iteration:** `begin()` / `end()`; ConstIterator holds a hazard pointer—element access only while iterator is valid. Simultaneous iteration and erase/insert are safe.
- **Semantics (from Folly docs):**
  - Readers are **wait-free**; writers are sharded (only part of the map is locked).
  - `size()` is a **rolling count** (not exact at any instant).
  - For atomic in-place update, Folly provides **assign_if_equal**, **assign_if**, **insert_or_assign**; mutation of threadinfo beyond the map’s API is out of scope here.

#### 4.1.1 threadinfo_map_t: no shared cache (return by value)

The storage abstraction used by the thread manager (`threadinfo_map_t`) must not use a **single-slot shared cache** for lookup or insert when built with Folly. A shared mutable cache (e.g. `get_ref(tid)` or `put(ptr)` returning a reference to a member that is overwritten on the next call) causes **data races** when multiple threads call `get_ref` or `put` concurrently, and allows a caller to see the wrong thread if it holds the returned reference across another lookup.

- **Required (Option 1 — return by value):** When using Folly, `get_ref(tid)` and `put(ptr)` must **return `ptr_t` by value** (a copy of the `shared_ptr`), not a reference to an internal cache. Copy from the iterator (or from the inserted element) and return; return an empty `ptr_t` when the key is not found (for `get_ref`). No `m_put_cache` / `m_get_ref_cache` (or equivalent) in the Folly path.
- **Call sites:** Callers that today store `const auto& ref = get_ref(tid)` and then use `ref` must instead store the result by value (e.g. `auto ptr = get_ref(tid)`); the existing pattern of immediately copying into a local `shared_ptr` (e.g. in `find_thread`, `remove_thread`) already supports this. `add_thread` and the state table already return `ptr_t` by value; the storage layer's `put` should return by value so that no reference to internal state is exposed.
- **Non-Folly path:** For consistency and to avoid two different APIs, the non-Folly backend can also use return-by-value for `get_ref` and `put` (return a copy of the map value or empty).

### 4.2 Lookup and get_thread / find_thread

- **Return by value:** Implement `get_thread(tid)` / `find_thread(tid)` by calling `find(tid)` and returning a **copy** of `it->second` (or empty `shared_ptr` if not found). Return type is `std::shared_ptr<sinsp_threadinfo>` **by value**. The caller holds a reference; no internal cache is used, so lookups are thread-safe and the returned handle remains valid regardless of later lookups or erases.
- **No find cache:** A single-slot “last thread” or find-result cache is **not** used, because it would be unsafe with concurrent callers and when callers hold the result across other `find_thread`/`get_thread` calls. Returning a copy avoids both issues.
- **Proc lookup / lookup_only / main_thread:** Semantics (e.g. when to dig into /proc) remain in the implementation; the storage layer only provides thread-safe map access.

### 4.3 Iteration and get_threads()

- **Current:** `get_threads()` returns a pointer to the table; callers use `loop()`, `get(tid)`, `size()`.
- **Proposed:** Remove direct table pointer. Provide one or both of:
  - **loop_threads(callback):** Iterate the map with `for (auto it = map.begin(); it != map.end(); ++it)` and invoke `callback(it->second)` (passing a copy of the `shared_ptr`). Callback must not re-enter the thread table (same as today with nested loop/get).
  - **Expose begin()/end()** of the concurrent map via a thin adapter, documenting that iterators must not be dereferenced after advancement or after any operation that might rehash. Prefer **loop_threads** to avoid exposing Folly types and iterator lifetime rules.
- **get_thread_count():** Implement via `map.size()`; document that it is approximate (rolling count) if that is acceptable for current use cases.

### 4.4 Add / remove

- **add_thread:** Call `insert(tid, std::move(ptr))` or `try_emplace` (or `insert_or_assign`). Return **by value**: return a copy of the inserted `shared_ptr` (e.g. via `find_thread(tid, true)` after insert). No internal cache; same thread-safe semantics as lookup.
- **remove_thread:** Call `erase(tid)`. No change in public signature.

### 4.5 Topology (parent, group, children)

- Same as in the Boost proposal: topology can live inside sinsp_threadinfo or in auxiliary structures. Add/remove and lookup/iteration are thread-safe via the container; in-place updates to topology (e.g. parent/child links) are done by the caller when holding a `shared_ptr` or inside a known single-threaded phase, and are out of scope for this proposal.

### 4.6 Handling APIs that return raw pointers

Several thread manager methods return **raw pointers** (`sinsp_threadinfo*`) to another thread in the table. Examples:

- **get_ancestor_process(tinfo, n)** — returns the n-th ancestor process (parent, grandparent, …), or `nullptr` if not found.
- **find_new_reaper(tinfo)** — returns the new reaper for a thread (e.g. when the thread is being removed), or `nullptr` if none.
- **get_oldest_matching_ancestor(tinfo, get_id, is_virtual)** — returns a raw pointer to an ancestor satisfying a predicate.

**Why this is bad for thread safety:** The returned pointer refers to an entry that is still in the concurrent map, but the caller holds no reference count. Another thread can call **remove_thread** (or erase that TID) immediately after the return. The first thread then uses a **dangling pointer** (use-after-free). Raw pointers also imply unclear ownership and lifetime.

**Proposed approaches:**

1. **Return `std::shared_ptr<sinsp_threadinfo>` (or `std::optional` of it) instead of raw pointer.**  
   The implementation performs the same traversal/lookup, but before returning it does a **find(tid)** (or `at(tid)`) to obtain a **shared_ptr** to the result and returns that. The caller then holds a reference; the thread cannot be destroyed while the shared_ptr is in use.  
   - **Pros:** Clear ownership, thread-safe as long as the table is the only owner of the entry and we return a copy of that shared_ptr.  
   - **Cons:** Slightly more work per call (extra lookup by TID after computing the result); call sites must switch from `sinsp_threadinfo*` to `shared_ptr` or `optional<shared_ptr>`.  
   - **Migration:** Call sites that today do `auto* p = get_ancestor_process(tinfo, 1); if (p) use(p);` become `auto p = get_ancestor_process(tinfo, 1); if (p) use(*p);` (or use `p.get()` where a raw pointer is required for a short-lived use).

2. **Return TID only (e.g. `std::optional<int64_t>`).**  
   The method computes the TID of the ancestor/reaper and returns it; the caller then does **find_thread(tid)** to get a `shared_ptr` if needed.  
   - **Pros:** No extended lifetime of the thread from the API; caller explicitly fetches a handle.  
   - **Cons:** Two lookups (one inside the method to resolve topology, one in the caller); API change for all call sites that need the threadinfo (they must call find_thread).

3. **“With” style: accept a callback that receives the result only while the table holds a reference.**  
   e.g. `with_ancestor_process(tinfo, n, [](const std::shared_ptr<sinsp_threadinfo>& ancestor) { ... });`  
   - **Pros:** No raw pointer or long-lived shared_ptr returned; safe by construction.  
   - **Cons:** More invasive API change; call sites that need to pass the result to other code or store it become harder (they must capture in the callback or copy TID and re-lookup).

4. **Keep raw pointer but document “unsafe”.**  
   Document that the pointer is valid only until the next call into the thread manager (or only while the caller holds a shared_ptr to the *starting* thread and no other thread removes the ancestor).  
   - **Cons:** Remains prone to use-after-free under concurrency; not recommended.

**Recommendation:** Prefer **option 1 (return `shared_ptr` or `optional<shared_ptr>`)** for **get_ancestor_process**, **find_new_reaper**, and **get_oldest_matching_ancestor**. It gives clear ownership, avoids use-after-free when another thread removes the thread, and keeps the call site change small (pointer → smart pointer). Option 2 (return TID) is a valid alternative where callers prefer to do their own find_thread. Option 3 is the safest but has the largest API impact.

**Implementation note:** Inside the method, the logic (e.g. walking parent pointers) may currently use raw pointers. The implementation can (a) walk using raw pointers to determine the result TID, then call `at(result_tid)` or `find(result_tid)` and return the copied `shared_ptr`; or (b) hold a Folly iterator or shared_ptrs along the path and return the last one. Care must be taken that the ancestor is still in the map when we do the lookup (another thread could remove it between “we decided it’s the ancestor” and “we called at(tid)”); in that case returning an empty optional or nullptr shared_ptr is correct.

### 4.7 State table and plugin API

- **get_entry(key):** Implement by `at(key)` (or find + copy); return that `shared_ptr` as the table entry. No change in contract.
- **add_entry / erase_entry:** Implement with `insert` / `erase` as above; unchanged contract.
- **foreach_entry:** Implement by iterating the map (e.g. loop_threads) and invoking the predicate on each entry; unchanged contract.

---

## 5. Draft API changes (thread_manager.h)

This section drafts the public API so that the changes can be validated. The design favours **minimal breakage**: keep `get_thread`/`find_thread` returning a `shared_ptr`, and replace `get_threads()` with an iteration API.

### 5.1 Storage type (internal)

- Replace `threadinfo_map_t m_threadtable` (or equivalent) with:
  - `folly::ConcurrentHashMap<int64_t, std::shared_ptr<sinsp_threadinfo>> m_threadtable;`
  - Or a type alias and the same value type. No change to public API types for threadinfo.

### 5.2 Lookup: get_thread / find_thread

**Current (pre–thread-safe):**

```cpp
const threadinfo_map_t::ptr_t& get_thread(int64_t tid, bool lookup_only = true, bool main_thread = false);
const threadinfo_map_t::ptr_t& find_thread(int64_t tid, bool lookup_only);
```

**Proposed (adopted):** Return **by value** so the caller holds a reference and no internal find cache is needed. Implementation uses Folly’s `find(tid)` and returns a copy of the `shared_ptr`, or an empty `shared_ptr` if not found.

```cpp
std::shared_ptr<sinsp_threadinfo> get_thread(int64_t tid, bool lookup_only = true, bool main_thread = false);
std::shared_ptr<sinsp_threadinfo> find_thread(int64_t tid, bool lookup_only);
```

- No internal cache: lookups are thread-safe and callers may hold the result across other lookups.
- Use **find(tid) != end()** (or equivalent) instead of any **contains(tid)** (Folly deletes `contains` to avoid TOCTOU).

### 5.3 Iteration: replace get_threads()

**Current:**

```cpp
threadinfo_map_t* get_threads() { return &m_threadtable; }
```

**Proposed:** Remove direct table pointer. Add iteration that passes `shared_ptr` to a callback (safe: we pass a copy of the value from the iterator).

```cpp
using thread_visitor_t = std::function<bool(const std::shared_ptr<sinsp_threadinfo>&)>;
bool loop_threads(thread_visitor_t callback) const;
```

- Implementation: `for (auto it = m_threadtable.begin(); it != m_threadtable.end(); ++it) { if (!callback(it->second)) return false; } return true;`
- **get_thread_count():** `return (uint32_t)m_threadtable.size();` — document that `size()` is approximate (rolling) if Folly’s guarantee is not exact.

### 5.4 Add / remove

**Current:**

```cpp
const threadinfo_map_t::ptr_t& add_thread(std::unique_ptr<sinsp_threadinfo> threadinfo, bool from_scap_proctable);
void remove_thread(int64_t tid);
```

**Proposed:**

- **add_thread:** Insert into Folly map (e.g. `insert_or_assign`). Return the inserted `shared_ptr` **by value** (e.g. via `find_thread(tid, true)`) for consistency with lookup APIs and thread safety (no cache).
- **remove_thread:** `erase(tid)` plus existing bookkeeping (e.g. parent/child, group). Signature unchanged. No cache invalidation (find cache removed).

### 5.5 Topology helpers and APIs that currently return raw pointers

- **traverse_parent_state**, **create_thread_dependencies**: keep existing signatures. Document that the threadinfo reference/pointer must be valid (e.g. from a `shared_ptr` or from a callback scope where the table holds a reference).

- **get_ancestor_process**, **find_new_reaper**, **get_oldest_matching_ancestor** (see §4.6): replace **raw pointer** return with **shared_ptr** (or optional) so that the caller holds a reference and the result cannot be freed by another thread while in use.

**Proposed signatures:**

```cpp
// Today: sinsp_threadinfo* get_ancestor_process(sinsp_threadinfo& tinfo, uint32_t n = 1);
std::shared_ptr<sinsp_threadinfo> get_ancestor_process(const sinsp_threadinfo& tinfo, uint32_t n = 1) const;
// Returns nullptr (empty) if no such ancestor or if it was removed before we could take a reference.

// Today: sinsp_threadinfo* find_new_reaper(sinsp_threadinfo*);
std::shared_ptr<sinsp_threadinfo> find_new_reaper(const sinsp_threadinfo& tinfo);
// Or: std::shared_ptr<sinsp_threadinfo> find_new_reaper(const std::shared_ptr<sinsp_threadinfo>& tinfo);
// Returns nullptr if no reaper or on loop detection.

// Today: sinsp_threadinfo* get_oldest_matching_ancestor(sinsp_threadinfo* tinfo, get_thread_id_fn, bool is_virtual_id);
std::shared_ptr<sinsp_threadinfo> get_oldest_matching_ancestor(
    const sinsp_threadinfo& tinfo,
    const std::function<int64_t(sinsp_threadinfo*)>& get_thread_id,
    bool is_virtual_id = false) const;
```

- **get_ancestor_field_as_string**: can keep returning `std::string`; it may call get_ancestor_process (or similar) internally and use the result only within the same function (no raw pointer escape). If it currently takes/uses raw pointers, switch to the new shared_ptr-based helper.
- **Input style:** Prefer taking **const sinsp_threadinfo&** or **const std::shared_ptr<sinsp_threadinfo>&** for the “starting” thread so that the API does not encourage holding raw pointers.

### 5.6 State table (libsinsp::state::table)

- **get_entry(key):** return `find_thread(key, true)` (or equivalent) as today.
- **add_entry / erase_entry / foreach_entry / entries_count / clear_entries:** implemented using the concurrent map’s insert, erase, iteration, size, clear. Contract unchanged.

### 5.7 Summary table

| Current | Proposed |
|--------|----------|
| `get_thread(tid, ...)` → `const ptr_t&` | Return `shared_ptr` by value; implement via `find(tid)` + copy; **no find cache** |
| `find_thread(tid, lookup_only)` → `const ptr_t&` | Return `shared_ptr` by value; implement via Folly `find(tid)` + copy; **no find cache** |
| `get_threads()` → `threadinfo_map_t*` | **Removed.** Use `loop_threads(callback)` (and optionally `get_thread_count()`) |
| `add_thread(...)` → `const ptr_t&` | Return **by value**; implement via `insert`/`insert_or_assign` then `find_thread(tid, true)` (no cache) |
| `remove_thread(tid)` | Unchanged; implement via `erase(tid)` |
| `get_thread_count()` | Unchanged; implement via `size()` (document approximate if needed) |
| Topology helpers (traverse_parent_state, create_thread_dependencies) | Unchanged; document lifetime rules |
| get_ancestor_process, find_new_reaper, get_oldest_matching_ancestor | **Return `std::shared_ptr<sinsp_threadinfo>`** instead of raw pointer; take const ref (or shared_ptr) for input. See §4.6. |
| State table API | Same contract; implementation uses Folly map |

---

## 6. Test coverage for thread safety

- **Existing tests:** All existing unit tests that use the thread manager must still pass. Any call site that used `get_threads()` must be migrated to `loop_threads` or equivalent.
- **Concurrency tests (new):** Concurrent add + lookup (e.g. get_thread / find), concurrent remove + iteration (loop_threads), mixed add/remove/lookup/iteration; all run under **TSAN** with no data races or use-after-free.
- **TSAN in CI:** Enable ThreadSanitizer for the libsinsp (or relevant) tests and run in CI.

---

## 7. Risks and mitigations

- **Iterator and reference stability:** Folly’s ConstIterator holds a hazard pointer; the element is valid only while the iterator is valid. We avoid exposing raw references that outlive the iterator by (a) using `at()` which returns a copy, and (b) implementing `loop_threads` so that the callback receives a copy of the `shared_ptr`. No long-lived raw pointers to map elements.
- **size() approximate:** Folly documents `size()` as a rolling count. If any code relies on an exact count at a given instant, document the change or provide an alternative (e.g. count during iteration).
- **No contains():** Use `find(tid) != end()` instead of a separate existence check to avoid TOCTOU.
- **Internal sync of sinsp_threadinfo:** Unchanged; callers that mutate threadinfo from multiple threads must synchronize themselves.

---

## 8. Dependencies

- **Folly** (Facebook’s C++ library) with **ConcurrentHashMap** and **Hazptr** (hazard pointers). Add Folly as a dependency (e.g. vcpkg, system package, or git submodule); document minimum version and any build options (e.g. for ConcurrentHashMapSIMD). Ensure the project’s license is compatible with Folly’s (Apache 2.0).

---

## 9. Summary

| Aspect | Goal |
|--------|------|
| **Data structure** | `folly::ConcurrentHashMap<int64_t, std::shared_ptr<sinsp_threadinfo>>` for thread storage |
| **Thread safety** | Add, remove, lookup, iteration are thread-safe (wait-free reads, sharded writes, hazard pointers) |
| **Internal sync** | Out of scope: sinsp_threadinfo field updates not made thread-safe here |
| **API** | get_thread/find_thread return shared_ptr **by value** (no find cache); replace get_threads() with loop_threads(callback) |
| **Tests** | Concurrency tests + TSAN in CI to validate thread-safe behaviour |

This proposal provides a **less intrusive** path to a thread-safe thread manager by building on Folly’s ConcurrentHashMap: **iterator- and copy-based access** allow retaining a **shared_ptr**-oriented API (get_thread, find_thread, loop_threads with shared_ptr callback) without switching to a full visitation-only design, while still achieving safe concurrent add/remove/lookup/iteration.
