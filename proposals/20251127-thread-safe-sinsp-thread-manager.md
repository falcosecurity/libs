# Proposal for Thread-safe scalable sinsp_thread_manager

## Summary

The current `sinsp_thread_manager` operates in a single-threaded environment, utilizing a `std::unordered_map` plus some auxiliary data structures to represent the threads topology without any synchronization.
In the context of Falco's move towards a multi-threaded architecture to handle higher event volumes, we need to redesign this component to be thread-safe and scalable.

The operations *sinsp\_thread\_manager* provides are:

1. *sinsp\_thread\_info* lookup ($O(1)$) e.g. event parsing, rules evaluation (filterchecks)
1. *sinsp\_thread\_info* iteration ($O(N)$) e.g. parent/child relationhip, thread grouping
1. *sinsp\_thread\_info* insertion/deletion ($O(1)$) e.g. thread clone/exit

As we migrate to a multi-threaded architecture to handle higher event volumes:

1. **The naive synchronization approach:** Simply using mutexes will cause **contention**. As CPU core count increases, throughput will *decrease* due to lock overhead, context-switching and cache-line bouncing.
1. **The requirement:** We require a data structure where the "hot path" (Event Parsing/Lookups) remains **Wait-Free** and creates **low cache-line bounce** between cores.

The choice of the data structure is driven by the following assumptions:

* The access pattern is dominated by reads (read-mostly)
* We can distinguish between two type of write operations:
  * Topological changes (thread creation/deletion) - *relatively rare*
  * State updates (e.g. files open) - frequent but can be handled separately

This document focuses more on the topological changes, as they are the most challenging to implement in a wait-free manner, but keep in mind that state updates require another layer of synchronization.

## Goal

Demonstrate the feasibility of a thread-safe, wait-free sinsp_thread_manager implementation that can serve as the backbone for Falco's multi-threaded architecture, while maintaining high performance for the single-threaded use case.


## Non-Goals

This proposal does not address the synchronization details of the internal state of *sinsp\_thread\_info* objects, and focuses more on the data structure used to store and retrieve and maintain the threads topology.

## Proposal

### Architecture: Atomic pointers array

We will implement a data structure backed by a direct-indexing array, using **Read-Copy-Update (RCU)** for synchronization and deferred memory reclamation.

Allocating the internal vector to its full capacity of **2^{22}** atomic pointers immediately may seem an extreme approach to avoid runtime reallocations and moves and reduce the overall complexity of the data structure. However, the main disadvantage is the non-trivial, up-front memory cost, which is approximately 32 MB for the array of pointers on a 64-bit system. While this is a relatively small cost for a system component, it represents a permanent over-allocation of memory, as the number of active threads in a system will rarely, if ever, reach the maximum possible PID limit, meaning much of that 32MB will hold `nullptrs`.
The vector of atomic is a simplified version of a hash table and provides $O(1)$ lookups with minimal overhead, but we also need to maintaine topological relationships between threads (parent/child) for which we will use an intrusive RCU protected linked list.

This allows N readers to read thread state simultaneously without communicating with each other or the writer, with minimal synchronization overhead.

Note that the single allocation of the vector is an extreme solution and will allow to prototype fast and test the limitations of the approach. We can consider later to use a radix tree (like the kernel pidmap) or a real hash table to reduce memory consumption.

### Core Components

1. **Lookup Layer (Wait-Free):** A pre-allocated `std::vector` of atomic pointers indexed by TID. This provides $O(1)$ random access.
2. **Iteration Layer (Wait-Free):** RCU protected atomic pointers and lists within `sinsp_thread_info` objects (or in an internal wrapper class), similar to what is done in the Kernel.
3. **Concurrency Control:**
   * **Readers:** use RCU read primitives *rcu_read_lock()*, *rcu_read_unlock()* to delimit the reader critical sections, and atomic loads for pointer dereferencing *rcu_dereference()*.
   * **Writers:** use RCU pointer assignment *rcu_assign_pointer()* for atomic pointer updates, and a mutex to serialize writers when applying topological changes. Note that it may be possible in theory to have a lock-free writer, based on CAS operations, but the complexity of the solution would increase tremendously, and it would require a weaker consistency model.
   * **Reclamation:** retire object (Asynchronous deletion).

### Data Structures

#### The Thread Object (sinsp\_thread\_info)

The object carries its own navigation pointers to avoid allocating separate list nodes for iteration.
The following is a simplified version of the actual structure.

```c++
struct sinsp_thread_info {

    // --- Domain Data ---
    // Immutable after creation, or updated via atomic operations or other
    // synchronization mechanisms.
    int64_t m_tid;
    int64_t m_tgid;
    std::string m_comm;
    // ... other fields ...

    // Topology Pointers used for process tree transversal, re-parenting, etc.
    std::atomic<sinsp_thread_info*> m_ptid{nullptr}; // get to parent thread
    list_head<sinsp_thread_info> m_children{nullptr}; // iterate over children
    list_head<sinsp_thread_info> m_tasks{nullptr}; // linking all processes for traversal, named after the [tasks](https://github.com/torvalds/linux/blob/7d0a66e4bb9081d75c82ec4957c50034cb0ea449/include/linux/sched.h#L957-L958) member in task_struct in linux kernel

    // Pointer to the group leader thread info
    std::atomic<sinsp_thread_info*> m_group_leader{nullptr};
    // Intrusive list node for linking threads in the same thread group
    list_head m_group_node{nullptr};

    sinsp_thread_info(int64_t t) : tid(t) {}
};
```

In the pseudo-code above, `list_head` is an intrusive RCU-protected linked list node, similar to the Linux kernel's [list_head](https://github.com/torvalds/linux/blob/559e608c46553c107dbba19dae0854af7b219400/include/linux/types.h#L200-L202) struct.
It provides the necessary functionality to link `sinsp_thread_info` objects into various lists while ensuring thread-safe traversal and modification using RCU primitives.

### The Manager (sinsp\_thread\_manager)

The simplified version of the manager structure is as follows:

```c++
class sinsp_thread_manager {
private:
    // Store threads for O(1) lookup by TID
    std::vector<std::atomic<sinsp_thread_info*>> table_;

    // Serialize writers
    std::mutex process_list_lock;
    // Head of the global thread list, serves as an anchor for iteration
    std::atomic<sinsp_thread_info*> init_thread{nullptr};

public:
    // PID_MAX is typically 32768, but can be up to 4M on 64-bit systems.
    explicit sinsp_thread_manager(size_t max_pids = (1 << 22))
        : table_(max_pids) {};
};
```

### Concurrency Model

#### The Hot Path: Lookup (Wait-Free/Lock-Free)

This should be the most frequent operation, executed during event parsing and rules evaluation. The RCU primitives ensure that multiple readers can access the data in a lock-free and wait-free manner.

Using a visitor function to access the *sinsp\_thread\_info* would be a good approach to be able to keep control over the reader critical section. Alternatively, we could return a smart pointer based on RCU primitives.

```c++
using thread_visitor = std::function<void(const sinsp_thread_info*)>;

void visit(int64_t tid, thread_visitor callback) {
    if (tid >= table_.size()) [[unlikely]] return;

    rcu_read_lock(); // Begin RCU critical section

    // Acquire Logic
    sinsp_thread_info* current = rcu_dereference(table_[tid]);

    if (current) {
        // Execute the user's logic *inside* the RCU critical section
        callback(current);
    }
    rcu_read_unlock(); // End RCU critical section  
}

Usage Example:
// Correct and safe usage
manager.visit(some_tid, [](const sinsp_thread_info* info) {
    printf("Thread comm: %s\n", info->comm.c_str());
});
```

#### Iteration (Wait-Free/Lock-Free)

The structure contains multiple RCU-protected pointers and lists to allow navigation between threads. Common use cases include:
* Navigate over [process ancestry](https://github.com/falcosecurity/libs/blob/e22484c8405a6c02ab04203cfeae111214275375/userspace/libsinsp/thread_manager.cpp#L681-L748)
* [Re-parenting threads](https://github.com/falcosecurity/libs/blob/e22484c8405a6c02ab04203cfeae111214275375/userspace/libsinsp/thread_manager.cpp#L446-L501) after deletion 

Iteration over all threads is rare, used in those scenarios:
* Initialization e.g. fixing links after initial process scan
* [Dumping thread info](https://github.com/falcosecurity/libs/blob/e22484c8405a6c02ab04203cfeae111214275375/userspace/libsinsp/thread_manager.cpp#L762-L818) to scap files

* **Mechanism:** Linked List Traversal or simple pointer de-reference.
* **Performance:** $O(TransversedThreads)$.
* **Consistency:** Weakly Consistent, as the list may change during traversal.

```c++
void for_each_thread(thread_visitor callback) {
    rcu_read_lock(); // Begin RCU critical section
    sinsp_thread_info* current = rcu_dereference(init_thread);
    while (current) {
        // Execute the user's logic *inside* the RCU critical section
        callback(current);
        current = rcu_dereference(current->m_next);
    }
    rcu_read_unlock(); // End RCU critical section
}
```

#### The Write Path: Clone/Exec/Exit (Single writer)

Executed when a clone, fork, exec or exit syscall is detected. Locking is needed to serialize writers.

* **Mechanism:** Writer Lock \+ Atomic Swap.
* **Blocking:** Yes, but only blocks *other writers*. Readers are **never** blocked.

**Add Thread Logic:** (Locking to serialize writers)

1. Allocate new `sinsp_thread_info`.
1. Lock `list_lock_`.
1. Publish in the RCU list structure(s) e.g. link to parent, add to thread group list. This involves updating multiple RCU pointers.
1. `rcu_assign_pointer(table_[tid], new sinsp_thread_info)` \-\> **Publishes the new thread for lookups**
1. Unlock `list_lock_`.

Note that having different RCU structures (e.g. parent/child, thread group) means we may have temporal inconsistencies between them, e.g. a thread may be visible for iteration, but not yed visible through the vector lookup. Mixing up iteration and lookups should be avoided in general.

**Remove Thread Logic:** (Locking to serialize writers)

1. Lock `list_lock_`.
1. `table_[tid].store(nullptr, release)`
1. `rcu_assign_pointer(table_[tid], nullptr)` \-\> **Remove from lookups.**
1. Unlink from list, parent, children. This involves updating multiple RCU pointers.
1. Unlock `list_lock_`.
1. `old_node->retire()` \-\> **Memory freed asynchronously.**

**Replace Thread Logic:** (Locking to serialize writers)

1. Allocate new `sinsp_thread_info, copying data from the old one.
1. Lock `list_lock_`.
1. Update necessary RCU pointers to link the new node in place of the old one.
1. `rcu_assign_pointer(table_[tid], new sinsp_thread_info)` \-\> **Publishes the new thread for lookups**
1. Unlock `list_lock_`.
1. `old_node->retire()` \-\> **Memory freed asynchronously.**   

### Partitioning

The data structure presented do not impose any partitioning scheme of the event processing. However, processing all the events related to a specific thread group (TGID) in the same thread may help reducing reads/writes crossing the partition boundary, reducing contention on `sinsp_thread_info` updates, improving cache locality and reducing (some of) the effects of the temporal inconsistencies.
Having unbalanced load however, would worsen the temporal inconsistencies, as different partitions have different event processing delay.

### Deferred Memory Reclamation

RCU allows two schemes for deferred memory reclamation:
1. **Synchronous Deletion:** The writer waits for all pre-existing readers to complete before reclaiming memory. This is simpler but may introduce latency on the write path.
1. **Asynchronous Deletion:** The writer schedules the memory for reclamation after a grace period, allowing readers to complete without blocking the writer. This is less cache-friendly and requires one or more additional threads.

Only the experimental results of the two approaches can tell which one is better for our use case, intuitively asynchronous deletion may be better suited for high-throughput scenarios.

### RCU Userspace Library

There are two main options for RCU in userspace:
1. [Userspace RCU (liburcu)](https://github.com/urcu/userspace-rcu): A pure C RCU implementations for userspace applications. It provides various RCU flavors, including QSBR (Quiescent State Based Reclamation) and signal-based RCU.
2. [Folly RCU](https://github.com/facebook/folly/blob/main/folly/docs/Rcu.md): A C++ RCU implementation that integrates well with C++ applications. It provides a modern C++ interface and is designed for high performance.
The prototype can be implemented using either library, but Folly RCU may be easier to integrate with the existing C++ codebase of Falco.

## Risks and mitigations

### Cost of synchronization

The main risk of this approach is the cost of synchronization, especially on the write path. If we have enough contention on the writer lock, we risk having context-switching that would kill performance and very likely result in drops.
The kernel RCU implementation is relying on RW spinlocks, but it has the big advantage of being able to disable preemption when acquiring the spinlock, something we cannot do in user-space. This is probably the weakest point of this design, and we need to carefully benchmark it under high load.
Note that it is possible in general to have a lock-free writer using CAS operations, but the complexity of the solution would increase tremendously, and it would require a weaker consistency model.

### Temporal consistency and partitioning

Readers may observe temporal inconsistencies between different RCU structures, e.g. a thread may be visible through pointer navigation and not via direct lookup by TID.
What the RCU structure guarantees is that:

* we will avoid use-after-free issues
* infinite loops while iterating

We may incur into problems like not finding a parent thread during clone handling, that is being created concurrently. To mitigate this, we should spin/wait for a short time before triggering a proc scan.
Partitioning the events by TGID may help reduce the chances of this happening, at least for threads of the same process.

### Update in place vs RCU replace

We need to find the right balance between in-place updates vs RCU replace. The in place updates should be favoured for single field updates that can be done atomically. Only complex updates should go through the RCU replace path to avoid adding further write contention.
Note that in-place updates require external synchronization, atomic operations or locking. In case of nested structures, like fd tables, we may need to use other RCU protected structures to avoid RCU replacing the whole thread object for small updates.

### False sharing problem with contiguous atomic pointers

Storing atomic pointers in a contiguous vector may lead to false sharing issues, where multiple threads modify different atomic pointers that reside on the same cache line, leading to unnecessary cache coherence traffic and performance degradation. As TIDs are often allocated sequentially, we may want to use a mapping function that spreads the TIDs in non-contiguous locations, e.g. bit swap operations.

## Bibliography

* [https://lwn.net/Articles/262464/](https://lwn.net/Articles/262464/) What is RCU, Fundamentally?
* [https://www.efficios.com/pub/rcu/urcu-main.pdf](https://www.efficios.com/pub/rcu/urcu-main.pdf)
* [https://mirrors.edge.kernel.org/pub/linux/kernel/people/paulmck/perfbook/perfbook-eb.2024.12.27a.pdf](https://mirrors.edge.kernel.org/pub/linux/kernel/people/paulmck/perfbook/perfbook-eb.2024.12.27a.pdf)
* [https://www.cl.cam.ac.uk/research/srg/netos/papers/2001-caslists.pdf](https://www.cl.cam.ac.uk/research/srg/netos/papers/2001-caslists.pdf) Harris-Michael Algorithm for non-blocking single linked-list
