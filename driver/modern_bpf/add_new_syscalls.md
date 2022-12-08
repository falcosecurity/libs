# Add an already existing syscall into the modern BPF probe

## Choose the target syscall

The first thing we need to do is to choose a syscall from the [missing ones](https://github.com/falcosecurity/libs/issues/723).
Let's take the `access` syscall as an example! :rocket:

## Check the events involved

We need to understand which events this syscall sends to userspace. As you may know, every syscall sends an `enter` and an `exit` event and you can find this info in the [`syscall_table.c`](https://github.com/falcosecurity/libs/blob/c1d075ffda41dcbdeec0a9fee86f288b7b360d19/driver/syscall_table.c#L354).
For the `access` syscall, we have the event pair `PPME_SYSCALL_ACCESS_E`/`PPME_SYSCALL_ACCESS_X`. 👇

```c
#ifdef __NR_access
 [__NR_access - SYSCALL_TABLE_ID0] =                     {UF_USED | UF_ALWAYS_DROP, PPME_SYSCALL_ACCESS_E, PPME_SYSCALL_ACCESS_X, PPM_SC_ACCESS},
#endif
```

## Enter event

Let's start to implement the enter event logic!

Which are the parameters that the enter event sends to userspace? As usual, we can find this info in one of our tables: the [`event_table.c`](https://github.com/falcosecurity/libs/blob/c1d075ffda41dcbdeec0a9fee86f288b7b360d19/driver/event_table.c#L279).

For our `PPME_SYSCALL_ACCESS_E` event we have just `1` parameter of type `PT_FLAGS32` :point_down:

```c
/* PPME_SYSCALL_ACCESS_E */ {"access", EC_FILE | EC_SYSCALL, EF_NONE, 1, {{"mode", PT_FLAGS32, PF_HEX, access_flags} } }
```

Now we need to ask ourselves an important question: does the event size change at runtime or do we already know it at compile time?

The answer is pretty simple: If the event has at least `1` parameter among these types we cannot know its dimension a priori

* `PT_CHARBUF`
* `PT_FSPATH`
* `PT_FSRELPATH`
* `PT_BYTEBUF`
* `PT_SOCKADDR`
* `PT_SOCKTUPLE`
* `PT_FDLIST`
* `PT_DYN`

In all other cases, we know the dimension at compile time!

Why is so important to understand if the event has a fixed size? Simple, according to the event size we will change the way to implement our BPF program!
To be more concrete if the event has a fixed size we can use the `ringbuf` approach otherwise we have to use the `auxmap` one!

`ringbuf` approach means that under the hood we will push events directly into the BPF `ring buffer` while in the `auxmap` approach we need to copy our data in a BPF map and only in a second step we can push them to the `ring buffer`. Every time we have a variable-size event BPF forces us to use the `auxmap` approach, losing some precious clock cycles.

In the modern BPF proposal, you can find more details about the BPF [`ringbuffer`](https://github.com/falcosecurity/libs/blob/master/proposals/20220329-modern-bpf-probe.md#bpf-ring-buffer-map-kernel-version-58) and you can find also an [architectural view](https://github.com/falcosecurity/libs/blob/master/proposals/20220329-modern-bpf-probe.md#architecture) of how we push events to userspace with both approaches.

Now we can proceed with our example!
As we saw before the `PPME_SYSCALL_ACCESS_E` event has just `1`  parameter called `mode` with type `PT_FLAGS32`, so we can go for the `ringbuf` approach!

### Ringbuf approach

Every time an event follows the `ringbuf` approach we have to follow these steps:

1. Add the dimension of the fixed-size event into the [`event_dimension.h`](https://github.com/falcosecurity/libs/blob/master/driver/modern_bpf/definitions/events_dimensions.h) file.
2. Implement the BPF program following the `ringbuf` template.
3. Instruct our library `libpman` on how to call our BPF program implemented in step [2].
4. Write a test to assert that the BPF program correctly works.

#### 1. Set the fixed size

To do that, we first need to understand the format of an event sent to userspace

```c

 SCAP EVENT FORMAT:
 
 +------------------------------------------------------------------+
 |  Header    | u16 | u16 | u16 | u16 | ... | param1 | param2 | ... |
 +------------------------------------------------------------------+
 ^            ^                             ^
 |            |                             |
 ppm_hdr      |                             |
 lengths_arr--+                             |
 raw_params---------------------------------+
```

We have 3 main sections:

1. Fixed-size header (called `ppm_hdr` in the figure):

```c
 struct ppm_evt_hdr {
     uint64_t ts;       timestamp, in nanoseconds from epoch
     uint64_t tid;     the tid of the thread that generated this event
     uint32_t len;     the event len, including the header
     uint16_t type;     the event type
     uint32_t nparams;  the number of parameters of the event
 };
```

2. Array with `nparams` elements (called `lengths_arr` in the figure).

    Every element is on 16 bits and represents the param length.

3. All our params wrote in bytes (called `raw_params` in the figure).
  
    The length of every param is written in the corresponding element of
  the `lengths_arr` seen before.

Coming back to our case, the `PPME_SYSCALL_ACCESS_E` event has just 1 parameter with type `PT_FLAGS32`. As you can see from the [`enum ppm_param_type`](https://github.com/falcosecurity/libs/blob/475333b5bfa828209023f0c5bf93330e48f6a46c/driver/ppm_events_public.h#L1670), `PT_FLAGS32` is just a `uint32_t` so it's quite easy to understand the final size of the event: we will have the fixed size header + 16 bits for the param length + the space needed to store our param so `sizeof(uint32_t)`. Let's see it in code:

```c
#define ACCESS_E_SIZE HEADER_LEN + sizeof(int32_t) + PARAM_LEN
```

* `HEADER_LEN` is a macro that expresses the header size in bytes.
* `sizeof(int32_t)` is the space in bytes that we need to reserve to store the value of our `PT_FLAGS32` param.
* `PARAM_LEN` macro stands for `2` bytes, this is the space in which we need to write the length of our `PT_FLAGS32` param.

So considering again our figure, in the `access` case, we will have a final event like this with just `1` param 👇

```c
 +---------------------------+
 |  Header    | u16 | param1 |
 +---------------------------+
```

TL;DR; we have to add this line to the [`event_dimension.h`](https://github.com/falcosecurity/libs/blob/master/driver/modern_bpf/definitions/events_dimensions.h) file.

```c
#define ACCESS_E_SIZE HEADER_LEN + sizeof(int32_t) + PARAM_LEN
```

#### 2. Implement the BPF program

As we said we are using the `ringbuf` approach so we can advantage of the `ringbuf` template 👇.

> __Note__: this template can be used both for enter and exit events.

```c
/* if we are in the enter event */
SEC("tp_btf/sys_enter") 
int BPF_PROG(<your_syscall_name>_e,
      struct pt_regs *regs,
      long id)
/* if we are in the exit event*/
SEC("tp_btf/sys_exit")
int BPF_PROG(<your_syscall_name>_x,
      struct pt_regs *regs,
      long ret)
/**/
{
 struct ringbuf_struct ringbuf;
 /* Reserve the space for the event in the ring buffer.
  * Here you should put the dimension we computed in step 1.
  */
 if(!ringbuf__reserve_space(&ringbuf, <the_size_of_your_event>))
 {
  return 0;
 }

 /* Fill the event header with your event type */
 ringbuf__store_event_header(&ringbuf, <your_event_type>);

 /*=============================== COLLECT PARAMETERS  ===========================*/

 /* The params we need to collect. This logic is syscall-specific, we will see it. */

 /*=============================== COLLECT PARAMETERS  ===========================*/

 /* Push the whole event to userspace */
 ringbuf__submit_event(&ringbuf);

 return 0;
}
```

Quite easy, isn't it? Let's fill in the template for our `access` syscall.

```c
SEC("tp_btf/sys_enter")
int BPF_PROG(access_e,
      struct pt_regs *regs,
      long id)
{
 struct ringbuf_struct ringbuf;
 if(!ringbuf__reserve_space(&ringbuf, ACCESS_E_SIZE))
 {
  return 0;
 }

 ringbuf__store_event_header(&ringbuf, PPME_SYSCALL_ACCESS_E);

 /*=============================== COLLECT PARAMETERS  ===========================*/

 /* As we saw before the `PPME_SYSCALL_ACCESS_E` event sends just one param
  * to userspace, usually we add a comment for every param with the name and
  * the type.
  */

 /* Parameter 1: mode (type: PT_UINT32) */

 /* Now looking at the `access` manual page https://man7.org/linux/man-pages/man2/access.2.html
  * we can notice that `mode` is the second param (so index `1`):
  * 
  *                     0               1
  * `int access(const char *pathname, int mode)`
  *
  * We can use the `extract__syscall_argument` helper to take a syscall argument!
  * To choose the variable type (`int`) we usally look at the syscall prototype,
  * so in this case, we have `int mode.`
  */
 int mode = extract__syscall_argument(regs, 1);

 /* We saved in our program stack the `mode` argument so we only need to store it into the ringbuffer.
  * For doing this we have to choose the right ringbuf helper! Do you remember our comment?
  *
  * Parameter 1: mode (type: PT_UINT32)
  *
  * Well, we need to push a `PT_UINT32`, so as the documentation says
  * (https://github.com/falcosecurity/libs/blob/master/driver/modern_bpf/helpers/store/ringbuf_store_params.h#L234-L248)
  * we need to use the `ringbuf__store_u32` helper.
  */
 ringbuf__store_u32(&ringbuf, access_flags_to_scap(mode));

 /*=============================== COLLECT PARAMETERS  ===========================*/

 ringbuf__submit_event(&ringbuf);

 return 0;
}
```

And we have done, our enter event is ready to be sent! 📬

#### 3. How to call our BPF program

This step is the easiest one we have just to add an entry to the [event_prog_names](https://github.com/falcosecurity/libs/blob/475333b5bfa828209023f0c5bf93330e48f6a46c/userspace/libpman/src/events_prog_names.h#L24) table, in which we bind the event name to our BPF program 👇

```c
[PPME_SYSCALL_ACCESS_E] = "access_e",
```

#### 4. Write a test to assert the BPF program

Finally, we have to craft a test case to check if what we are doing is correct. Again we can use the `test` template

```cpp
/* if enter event */
TEST(SyscallEnter, <your_syscall_name>E)
/* if exit event */
TEST(SyscallExit, <your_syscall_name>X)
/**/
{
 auto evt_test = get_syscall_event_test(<syscall_code>, <event_direction>);

 /* Enable the code to receive events */
 evt_test->enable_capture();

 /*=============================== TRIGGER SYSCALL  ===========================*/

 /* Trigger the syscall we want to assert */

 /*=============================== TRIGGER SYSCALL ===========================*/

 /* We have already received the event we can disable the capture */
 evt_test->disable_capture();

 /* We search for the event just generated */
 evt_test->assert_event_presence();

 /* We don't find it, failure */
 if(HasFatalFailure())
 {
  return;
 }

 /* If we find it we save its content */
 evt_test->parse_event();

 /* We automatically assert its header */
 evt_test->assert_header();

 /*=============================== ASSERT PARAMETERS  ===========================*/

 /* Since you have populated the event kernel-side only you know what to assert here,
  * we will see it in our example.
  */

 /*=============================== ASSERT PARAMETERS  ===========================*/

 /* You have to assert the number of event paramateres */
 evt_test->assert_num_params_pushed(<number_event_params>);
}
```

Let's fill in the template for our `access` syscall.

```cpp
TEST(SyscallEnter, accessE)
{
 auto evt_test = get_syscall_event_test(__NR_access, ENTER_EVENT);

 evt_test->enable_capture();

 /*=============================== TRIGGER SYSCALL  ===========================*/

 int32_t mode = W_OK;
 char pathname[] = "//**null-file-path**//";
 /* we need to assert if we expect the syscall to fail or not */
 assert_syscall_state(SYSCALL_FAILURE, "access", syscall(__NR_access, pathname, mode));

 /*=============================== TRIGGER SYSCALL ===========================*/

 evt_test->disable_capture();

 evt_test->assert_event_presence();

 if(HasFatalFailure())
 {
  return;
 }

 evt_test->parse_event();

 evt_test->assert_header();

 /*=============================== ASSERT PARAMETERS  ===========================*/

 /* We report here the same comment we used kernel side */
 
 /* Parameter 1: mode (type: PT_UINT32)*/

 /* As we have done kernel-side we need to find the right helper to assert 
  * a param of type `PT_UINT32`. As we can see from the doc we have to use the
  * `assert_numeric_param` helper.
  * https://github.com/falcosecurity/libs/blob/master/test/modern_bpf/event_class/event_class.h#L319-L362
  */
 evt_test->assert_numeric_param(1, (uint32_t)mode);

 /*=============================== ASSERT PARAMETERS  ===========================*/

 /* `access` enter event contain just `1` parameter. */
 evt_test->assert_num_params_pushed(1);
}
```

With this test case, we have completed the enter event journey!

## Implement the exit event

Now let's try to implement the exit event logic! As for the enter event, we need to understand which parameters the exit event sends to userspace and we find this info in the [`event_table.c`](https://github.com/falcosecurity/libs/blob/c1d075ffda41dcbdeec0a9fee86f288b7b360d19/driver/event_table.c#L280).

For our `PPME_SYSCALL_ACCESS_X` we have 👇

```c
/* PPME_SYSCALL_ACCESS_X */ {"access", EC_FILE | EC_SYSCALL, EF_NONE, 2, {{"res", PT_ERRNO, PF_DEC}, {"name", PT_FSPATH, PF_NA} } }
```

Here we have `2` parameters: the first is a `PT_ERRNO` while the second is a `PT_FSPATH`.
So as we said before if an event as at least one param of type `PT_FSPATH` it has a variable length, so we have to use the `auxmap` approach.

### Auxmap approach

Every time an event follows the `auxmap` approach we have to follow these steps:

1. Implement the BPF program following the `auxmap` template.
2. Instruct our library `libpman` on how to call our BPF program implemented in step [1].
3. Write a test to assert that the BPF program correctly works.

#### 1. Implement the bpf program

With the `auxamp` approach, the event dimension will be directly computed at run-time so we can start directly with the implementation!
As for the `ringbuf` approach we have a template 👇

```c
/* if we are in the enter event */
SEC("tp_btf/sys_enter") 
int BPF_PROG(<your_syscall_name>_e,
      struct pt_regs *regs,
      long id)
/* if we are in the exit event*/
SEC("tp_btf/sys_exit")
int BPF_PROG(<your_syscall_name>_x,
      struct pt_regs *regs,
      long ret)
/**/
{
 struct auxiliary_map *auxmap = auxmap__get();
 if(!auxmap)
 {
  return 0;
 }

 /* Fill the event header with your event type */
 auxmap__preload_event_header(auxmap, <your_event>);

 /*=============================== COLLECT PARAMETERS  ===========================*/

 // The params we need to collect

 /*=============================== COLLECT PARAMETERS  ===========================*/

 /* We need to update the event header with the final event length, we know it only at this point */
 auxmap__finalize_event_header(auxmap);

 /* We push the event to userspace */
 auxmap__submit_event(auxmap);

 return 0;
}
```

Let's fill in the template for our `access` syscall.

```c
SEC("tp_btf/sys_exit")
int BPF_PROG(access_x,
      struct pt_regs *regs,
      long ret)
{
 struct auxiliary_map *auxmap = auxmap__get();
 if(!auxmap)
 {
  return 0;
 }

 auxmap__preload_event_header(auxmap, PPME_SYSCALL_ACCESS_X);

 /*=============================== COLLECT PARAMETERS  ===========================*/

 /* As we saw before this is the comment for the first param */

 /* Parameter 1: res (type: PT_ERRNO) */

 /* Here we want to store the syscall return value, this param is a `PT_ERRNO`
  * so as the doc says https://github.com/falcosecurity/libs/blob/master/driver/modern_bpf/helpers/store/auxmap_store_params.h#L258-L272
  * we need to use the `auxmap__store_s64_param` helper
  */
 auxmap__store_s64_param(auxmap, ret);

 /* Looking again at the `access` manual page https://man7.org/linux/man-pages/man2/access.2.html
  * we can notice that `pathname` is the first param (so index `0`).
  * This a pointer to the pathname so we use an `unsigned long` to store it.
  * As the doc says https://github.com/falcosecurity/libs/blob/master/driver/modern_bpf/helpers/store/auxmap_store_params.h#L327-L340
  * to store a `charbuf` param, so one between `PT_CHARBUF`, `PT_FSPATH`, `PT_FSRELPATH`, we need to use
  * the `auxmap__store_charbuf_param` helper.
  * - `MAX_PATH` is the maximum length we want to read from the pathname pointer
  * - `USER` means that the provided pointer points to userspace memory and not kernel memory.
  */

 /* Parameter 2: pathname (type: PT_FSPATH) */
 unsigned long path_pointer = extract__syscall_argument(regs, 0);
 auxmap__store_charbuf_param(auxmap, path_pointer, MAX_PATH, USER);

 /*=============================== COLLECT PARAMETERS  ===========================*/

 auxmap__finalize_event_header(auxmap);

 auxmap__submit_event(auxmap);

 return 0;
}
```

That's all for the exit event implementation!

#### 2. How to call our BPF program

Like before we have to add our entry to the [event_prog_names](https://github.com/falcosecurity/libs/blob/475333b5bfa828209023f0c5bf93330e48f6a46c/userspace/libpman/src/events_prog_names.h#L24) table :point_down:

```c
[PPME_SYSCALL_ACCESS_X] = "access_x",
```

#### 4. Write a test to assert the BPF program

We can use the same template seen before for the enter event. Note that the event test template doesn't change according to the approach we use kernel-side, the userspace doesn't know if we are using the `ringbuf` approach or the `auxmap` one.

```cpp
TEST(SyscallExit, accessX)
{
 auto evt_test = get_syscall_event_test(__NR_access, EXIT_EVENT);

 evt_test->enable_capture();

 /*=============================== TRIGGER SYSCALL  ===========================*/

 int32_t mode = W_OK;
 char pathname[] = "//**null-file-path**//";
 assert_syscall_state(SYSCALL_FAILURE, "access", syscall(__NR_access, pathname, mode));
 /* here the syscall fails so the first parameter we assert should be equal
  * to `-errno`.
  */
 int64_t errno_value = -errno;

 /*=============================== TRIGGER SYSCALL ===========================*/

 evt_test->disable_capture();

 evt_test->assert_event_presence();

 if(HasFatalFailure())
 {
  return;
 }

 evt_test->parse_event();

 evt_test->assert_header();

 /*=============================== ASSERT PARAMETERS  ===========================*/

 /* Parameter 1: res (type: PT_ERRNO)*/
 /* For all the numeric parameters we have the same helper `assert_numeric_param` */
 evt_test->assert_numeric_param(1, (int64_t)errno_value);

 /* For a `PT_FSPATH` param we have the related helper
  * https://github.com/falcosecurity/libs/blob/master/test/modern_bpf/event_class/event_class.h#L364-L376
  */
 /* Parameter 2: path (type: PT_FSPATH)*/
 evt_test->assert_charbuf_param(2, pathname);

 /*=============================== ASSERT PARAMETERS  ===========================*/

 /* the exit event has 2 parameters */
 evt_test->assert_num_params_pushed(2);
}
```

## Conclusion

Following this tutorial, you should be able to implement simple syscalls in the modern BPF probe. Pay attention! Every syscall has its peculiarities, so the scaffolding logic may not be enough in some cases, however, it should help you in understanding how the logic works under the hood.
Last but not least, you can find the `access` syscall already implemented in this [pull request](https://github.com/falcosecurity/libs/pull/752), you should recognize almost all steps we have seen together in this tutorial!
