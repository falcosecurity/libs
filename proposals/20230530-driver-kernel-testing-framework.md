# Driver Kernel Testing Framework

## Objective

The objective is to establish a comprehensive and structured testing process for Falco's kernel drivers. 

This framework ensures compatibility, stability, and optimal performance across different kernel versions, distributions, and architectures. The intended outcome is a robust testing infrastructure, enabling developers and adopters to have confidence in the reliability and functionality of the kernel drivers.

Additionally, it aims to set clear expectations and increase awareness among adopters by consistently communicating the complexities involved in kernel testing.


## Key Success Indicators

Acceptable confidence in the kernel drivers can be evaluated based on the following factors:

- Functionality: The drivers should run and work as intended, effectively capturing events within the kernel environment for the purpose of threat detection.

- Regression testing: Core metrics, which will be determined, should be monitored to ensure that there are no significant regressions or performance issues introduced with each iteration or update of the kernel drivers.

- Cost budgeting: The cost associated with kernel monitoring for threat detection should be appropriately budgeted, taking into consideration factors such as resource utilization, scalability, and the overall value provided by the monitoring solution.

By assessing these indicators, we can gauge the overall confidence, success, and performance of the kernel drivers within [The Falco Project](https://falco.org/).

## Key Terms

First, let's clarify a few definitions and provide further context.

- `kernel versions`: In the context of the testing framework, kernel versions refer to changes in the major and minor version of the kernel (e.g., 5.15 or 6.4). These version changes are specifically relevant for testing the Falco drivers, with a particular emphasis on testing with Long-Term Support (LTS) releases.
- `kernel drivers`: 
    - The kernel drivers powering Falco are custom code developed by Falco contributors to passively observe and analyze events within the Linux kernel. These drivers hook into tracepoints to gather information and generate structured Falco alerts. Falco's monitoring process is passive and does not exert any influence or modify the behavior of the events being monitored, such as syscalls.
    - Falco employs various kernel instrumentation strategies, including both traditional kernel modules and eBPF. eBPF is advertised as the safer option, as the driver code runs in a virtual machine with limited access to kernel data structures.
    - Lastly, the drivers themselves do not have their own control flow. Instead, they are invoked whenever a kernel event triggers at the hookpoints they are attached to. Consequently, the load on the drivers is contingent upon the workload and infrastructure in which they are deployed, making it different from a classic optimization problem where most influencing factors are under control.
- `libscap`: The `libscap` module responsible for setting up and interacting with Falco's kernel drivers is of great importance in the context of kernel testing. `libscap` plays a critical role in consuming events from the shared space between Falco and its drivers, which acts as a temporary storage for monitored events. Inefficient performance of libscap has the potential to create backpressure on kernel monitoring, which can result in missed tracepoint invocations.
- `kernel test grid`: The term "kernel test grid" will be used throughout this document for simplicity. It represents a condensed grid comprising dimensions such as kernel version, kernel architecture, compiler version, and kernel driver type. Due to practical considerations, the kernel test grid will be considerably smaller in scale compared to the grid of published kernel drivers. This approach is justified by the common practice of deriving outcome validity using statistical sampling theories.
- `compiler versions`: The object code of the kernel module (`kmod`) is compiled using the gcc compiler, whereas we utilize clang for BPF drivers (`bpf`, `modern_bpf`). Falco is committed to identifying the optimal compiler version and build container based on the kernel version and driver type.


## Why does Kernel Testing matter?

Kernel testing is crucial for various reasons, including some unique aspects discussed in the preceding definitions. 

In particular, the actions performed in Falco's kernel drivers have the potential to impact the host's performance, even if they operate passively without interfering with syscalls or other critical aspects. This is because driver code executes within the application context of the workload running on top of the kernel. As a general guideline, it is recommended to limit the execution of operations in kernel space. This principle is also applicable to tools like Falco, which extract information from kernel data structures available at the respective hookpoint. However, there is a trade-off, as transferring excessive raw information from the kernel to userspace can be highly costly. 

Therefore, finding the right balance is key to success. Careful design and decision-making regarding the allocation of tasks, lookups, and data operations between the kernel drivers and userspace are essential to avoid any performance degradation in applications or the kernel itself. 

Moreover, robust testing practices contribute to the long-term viability and scalability of the kernel drivers as The Falco Project continues to advance its kernel monitoring capabilities.


## Challenges and Considerations

Ensuring compatibility between different kernel versions, distributions, architectures, and compiler versions is complex due to frequent updates and changes in the Linux kernel. 

The curse of dimensionality and combinatorial explosion present challenges in kernel testing, as the testing complexity exponentially increases with the number of dimensions. Testing every possible combination exhaustively becomes impractical.

Additionally, performance and impact can vary based on specific workloads and fine-grained kernel settings, which are difficult to predict for each adopter's unique use case.

Therefore, a strategic approach is crucial to balance coverage and resources in testing. Furthermore, considering real-world workloads and settings is essential for comprehensive testing and accurate performance evaluation, serving as the guiding principle throughout the process.


## Proposal

### Phase 1: Functionality

> Feasible (targeted for Falco release 0.36)

- Objective: Ensure Falco drivers run and work across different kernel versions and distributions.
- Actions: Implement a comprehensive testing process and kernel test grid to validate driver compatibility, stability, and functionality across various kernel environments.
- Expected Outcome: Increased confidence in the reliability and stability of Falco drivers.

#### Test Category 1

Ensuring that the kernel driver successfully compiles for the agreed-upon kernel test grid. The optimal compiler version and build container are selected in alignment with the advancements in the Linux source tree and its related dependencies, based on the kernel version and driver type.


#### Test Category 2

Verifying that the kernel driver can load, run, and capture events without errors. This is determined through [scap-open](https://github.com/falcosecurity/libs/tree/master/userspace/libscap/examples/01-open) and unit tests conducted in virtual machine (VM) environments. In essence, when we mention that the "driver loads and runs", it implies that the scap-open counter for captured events during a test run is positive and that the [drivers_test](https://github.com/falcosecurity/libs/tree/master/test/drivers) unit tests pass. The latter tests not only load the driver live but also simulate syscall events and verify that the expected information is extracted from the kernel tracepoint and retrieved by the libscap driver type-specific engine in userspace.


#### Test Infrastructure

Our goal is to facilitate the expansion and integration of full Continuous Integration (CI) for the kernel test grid, enabling comprehensive testing of the kernel driver functionality. Concurrently, we will develop a test framework utilizing localhost virtual machines (VMs), which will include a limited kernel test grid. This framework will be accessible to adopters, providing them with a convenient option for local testing during the development or testing phases.


#### Current State

Currently (as of May 31, 2023), the relevant [falcosecurity/libs](https://github.com/falcosecurity/libs) CI drivers tests include:

- Building kernel drivers for:
    - Latest Archlinux kernel to spot possible incompatibilities with the latest kernel tree changes
    - ubuntu-22.04 (x86_64)
    - linux-2.6.32
    - linux-3.10
    - linux-4.18
    - linux-5.19
    - linux-6.2
- Running [drivers_test](https://github.com/falcosecurity/libs/tree/master/test/drivers) unit tests on:
    - ubuntu-22.04 (x86_64)
    - ubuntu-2204:2022.10.2 (arm64)
    - ubuntu-2004:202107-02 (x86_64)


#### Desired `kernel test grid` Expansion

*Distributions*

Choose a minimum of five popular distributions from the pool of distributions for which Falco currently publishes kernel drivers (retrieved from [falcosecurity/kernel-crawler](https://github.com/falcosecurity/kernel-crawler/tree/kernels) on May 31, 2023). Ensure a balanced representation between deb-based and rpm-based distributions.

- AliyunLinux
- AlmaLinux
- AmazonLinux
- AmazonLinux2
- AmazonLinux2022
- AmazonLinux2023
- ArchLinux
- BottleRocket
- CentOS
- Debian
- Fedora
- Flatcar
- Minikube
- OpenSUSE
- OracleLinux
- PhotonOS
- RockyLinux
- Talos
- Ubuntu

*Kernel versions*

To achieve comprehensive coverage, the statistical sampling of versions across distributions will prioritize the minimum and maximum supported kernel versions per driver type. Additionally, a particular emphasis will be placed on selecting LTS (Long-Term Support) releases when choosing the remaining kernel versions. As part of this approach, a minimum of 10 kernel versions will be carefully selected for each driver type.

*Architectures*

Place higher priority on testing for `x86_64` compared to `aarch64`.

*Driver type*

Ensure equal testing coverage for each driver, taking into account the different minimum kernel versions they support.

*Compiler versions*

Select the most appropriate compiler version and build container for the CI-integrated tests.

#### LOE and Cost Estimates for Phase 1 Completion

> The expanded CI tests may necessitate the use of approximately 30 low-resource virtual machines (VMs) that run continuously 24/7. These VMs would be distributed across multiple third-party cloud providers. To adequately cover the condensed kernel test grid, it is estimated that approximately 150 test runs would be required for each testing cycle. These tests can be launched using GitHub workflows leveraging SSH remote commands. The test results are then retrieved through this method as well. In addition to the test VMs, it may be necessary to expand the CI workflows in terms of builder containers.


### Phase 2: Regression, Cost and Benchmarking

> At Risk (contingent upon the availability of increased CI budgeting and additional engineering resources from community members, post Falco release 0.36)

- Objective: Conduct comprehensive regression testing, cost budgeting, and benchmarking.
- Actions: Allocate additional resources and budget to expand the testing infrastructure, enabling thorough regression testing and performance evaluation with realistic workloads and simulations of production settings.
- Expected Outcome: Improved detection of regressions, optimized cost budgeting for kernel monitoring, and benchmarking for performance optimization.

TBD

Note: Phase 2 is currently at risk due to resource limitations. The successful implementation of this phase relies not only on increased CI budgeting, but more importantly, on the availability of additional engineering resources. Furthermore, we aim to collaborate with the CNCF TAG Environmental Sustainability to establish core indices that reflect the appropriate cost implications of comprehensive kernel monitoring for threat detection. This collaboration will ensure that we adopt not only a sustainable approach but also the most compatible one, considering the various cost factors involved (see [Proof of Environmental Sustainability activities and best practices for CNCF projects](https://github.com/cncf/tag-env-sustainability/issues/64#issuecomment-1496197590)).



### Resources

- CI [Github Workflows](https://github.com/falcosecurity/libs/tree/master/.github/workflows)
- CI [CircleCI](https://github.com/falcosecurity/libs/tree/master/.circleci) 
- [falcosecurity/kernel-crawler](https://github.com/falcosecurity/kernel-crawler/) supported [kernels](https://github.com/falcosecurity/kernel-crawler/tree/kernels) 
- Issue [CI Integration for Driver Test Suites](https://github.com/falcosecurity/libs/issues/531)
- CNCF TAG Environmental Sustainability [Proof of Environmental Sustainability activities and best practices for CNCF projects](https://github.com/cncf/tag-env-sustainability/issues/64#issuecomment-1496197590)