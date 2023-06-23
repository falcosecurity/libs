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

The initial proposal primarily emphasizes the "Functionality" aspect, while the other key indicators will be addressed in future iterations.

## Key Terms

First, let's clarify a few definitions and provide further context.

- `kernel versions`: In the context of the testing framework, kernel versions refer to changes in the major and minor version of the kernel (e.g., 5.15 or 6.4). These version changes are specifically relevant for testing the Falco drivers, with a particular emphasis on testing with Long-Term Support (LTS) releases. We use the term "kernel versions" as it is more commonly used in everyday language. However, from a technical perspective, what we actually mean is a specific kernel release that we test, which is tied to the targeted major and minor version of the kernel.
- `kernel drivers`: 
    - The kernel drivers powering Falco are custom code developed by contributors. They hook into tracepoints to gather information from kernel data structures of selected kernel events, enabling the generation of structured Falco alerts. Falco's monitoring process is passive and does not modify the behavior of the monitored kernel actions, such as syscalls.
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

The curse of dimensionality and combinatorial explosion present challenges in kernel testing, as the testing complexity exponentially increases with the number of dimensions. Testing every possible combination exhaustively becomes impractical. However, we have an advantage in that most distributions only change kernels from one LTS version to the next LTS, while frequently publishing new builds (kernel releases). In addition, compatibility issues tend to be tied to major and minor kernel version changes rather than individual kernel releases. As a result, the realistic grid of potential kernels becomes more manageable and tractable.

Performance and impact can vary based on specific workloads and fine-grained kernel settings, which are difficult to predict for each adopter's unique use case. Therefore, a strategic approach is crucial to balance coverage and resources in testing.

Furthermore, considering real-world workloads and settings is essential for comprehensive testing and accurate performance evaluation, serving as the guiding principle throughout the process.


## Proposal

The "Functionality" tests of the CI-powered test framework are targeted for Falco release 0.36.

- Objective: Ensure Falco drivers run and work across different kernel versions and distributions.
- Actions: Implement a comprehensive testing process and kernel test grid to validate driver compatibility, stability, and functionality across various kernel environments.
- Expected Outcome: Increased confidence in the reliability and stability of Falco drivers.

### Test Category 1

Ensuring that the kernel driver successfully compiles for the agreed-upon kernel test grid. The optimal compiler version and build container are carefully selected to align with the advancements in the Linux source tree and its related dependencies. This selection takes into account various factors, including the specific kernel version, driver type, and the distribution being used.


### Test Category 2

Verifying that the kernel driver can load, run, and capture events without errors. This is determined through [scap-open](https://github.com/falcosecurity/libs/tree/master/userspace/libscap/examples/01-open) and unit tests conducted in virtual machine (VM) environments. In essence, when we mention that the "driver loads and runs", it implies that the scap-open counter for captured events during a test run is positive and that the [drivers_test](https://github.com/falcosecurity/libs/tree/master/test/drivers) unit tests pass. The latter tests not only load the driver live but also simulate syscall events and verify that the expected information is extracted from the kernel tracepoint and retrieved by the libscap driver type-specific engine in userspace.


### Test Infrastructure

Our goal is to facilitate the expansion and integration of full Continuous Integration (CI) for the kernel test grid, enabling thorough testing of the functionality of the kernel drivers. 

Concurrently, we will develop a test framework utilizing localhost virtual machines (VMs), which will include a limited kernel test grid. This framework will be accessible to adopters, providing them with a convenient option for local testing during the development or testing phases.


### Current State

Currently (as of June 6, 2023), the relevant [falcosecurity/libs](https://github.com/falcosecurity/libs) CI drivers tests include:

<details>
	<summary>Build kernel drivers</summary>
		<ul>
			<li>build-latest-kernel, nightly-test build against latest mainline kernel (including RC)</li>
			<li>ubuntu-22.04 (x86_64)</li>
			<li>linux-2.6.32 (x86_64)</li>
			<li>linux-3.10 (x86_64)</li>
			<li>linux-4.18 (x86_64)</li>
			<li>linux-5.19 (x86_64)</li>
			<li>linux-6.2 (x86_64)</li>
		</ul>
</details> 

<details>
    <summary>Run <a href="https://github.com/falcosecurity/libs/tree/master/test/drivers"> drivers_test</a> unit tests</summary>
        <ul>
            <li>ubuntu-22.04 (x86_64)</li>
            <li>ubuntu-2204:2022.10.2 (arm64)</li>
            <li>ubuntu-2004:202107-02 (x86_64)</li>
        </ul>
</details> 

</br>


### Desired Testing

*Distributions*

Choose a minimum of five popular distributions from the pool of distributions for which Falco currently publishes kernel drivers (retrieved from [falcosecurity/kernel-crawler](https://github.com/falcosecurity/kernel-crawler/tree/kernels) on May 31, 2023). Ensure a balanced representation between deb-based and rpm-based distributions, taking into account their real-world popularity.

<details>
    <summary>Candidate Kernel Distributions</summary>
        <table>
            <tr>
                <td><b>Distribution</b></td>
            </tr>
            <tr>
                <td>AliyunLinux</td>
            </tr>
            <tr>
                <td>AlmaLinux</td>
            </tr>
            <tr>
                <td>AmazonLinux</td>
            </tr>
            <tr>
                <td>AmazonLinux2</td>
            </tr>
            <tr>
                <td>AmazonLinux2022</td>
            </tr>
            <tr>
                <td>AmazonLinux2023</td>
            </tr>
            <tr>
                <td>ArchLinux</td>
            </tr>
            <tr>
                <td>BottleRocket</td>
            </tr>
            <tr>
                <td>CentOS</td>
            </tr>
            <tr>
                <td>Debian</td>
            </tr>
            <tr>
                <td>Fedora</td>
            </tr>
            <tr>
                <td>Flatcar</td>
            </tr>
            <tr>
                <td>Minikube</td>
            </tr>
            <tr>
                <td>OpenSUSE</td>
            </tr>
            <tr>
                <td>OracleLinux</td>
            </tr>
            <tr>
                <td>PhotonOS</td>
            </tr>
            <tr>
                <td>RockyLinux</td>
            </tr>
            <tr>
                <td>Talos</td>
            </tr>
            <tr>
                <td>Ubuntu</td>
            </tr>
        </table>
</details> 

</br>


*Kernel Versions*

To achieve adequate and realistic coverage, the statistical sampling of versions across distributions will prioritize the minimum and maximum supported kernel versions per driver type. Additionally, a particular emphasis will be placed on selecting LTS (Long-Term Support) releases when choosing the remaining kernel versions. As part of this approach, a minimum of 10 kernel versions will be carefully selected for each driver type.

*Architectures*


Cover each officially supported architecture by The Falco Project.

The prioritization of officially supported architectures for Falco is based on their adoption levels, with `x86_64` considered as P0 (highest priority) and `aarch64` as P1 (next priority level). For any other architectures supported by its libraries, a best effort approach (lower priority) is taken (e.g. `s390x`).


*Driver Type*

Ensure equal testing coverage for each driver, taking into account the different minimum kernel versions they support.

*Compiler Versions*

Select the most appropriate compiler version and build container for the CI-integrated tests. Apart from the compiler version, the GLIBC version in the build container can also have an impact on the ability to compile the driver for a given kernel.

> The expanded CI tests may necessitate the use of approximately 30 low-resource virtual machines (VMs) that can run continuously 24/7. These VMs would be distributed across multiple third-party cloud providers. Alternatively, VMs with KVM on hosted GitHub runners can be utilized, or an equivalent suitable solution can be adopted. To adequately cover the condensed kernel test grid, it is estimated that up to 70 test runs would be required for each testing cycle. These tests can be launched using GitHub workflows leveraging SSH remote commands. The test results are then retrieved through this method as well. Initially, it would be logical to support these tests on demand only (such as nightly tests) to avoid simultaneous runs that may try to access the same VM at the same time. In addition to the test VMs, it may be necessary to expand the CI workflows in terms of builder containers.

Please refer to Appendix 1 for a concrete example of a possible kernel test grid.


## Outlook

The following possibilities serve as an outlook for future enhancements. These potential improvements are anticipated after the release of Falco 0.36.

- Objective: Conduct comprehensive regression testing, cost budgeting, and benchmarking.
- Actions: Allocate additional resources and budget to expand the testing infrastructure, enabling thorough regression testing and performance evaluation with realistic workloads and simulations of production settings. Furthermore, it is suggested that the kernel test grid be made more dynamic.
- Expected Outcome: Improved detection of regressions, optimized cost budgeting for kernel monitoring, and benchmarking for performance optimization.

The successful implementation depends on increased CI budgeting and, more importantly, the availability of additional engineering resources. Additionally, we are actively collaborating with the CNCF TAG Environmental Sustainability to establish core indices that reflect the cost implications of kernel monitoring for threat detection. This collaboration ensures that we adopt a sustainable and compatible approach, taking into account various cost factors. You can find more information on our activities and best practices for CNCF projects in the [Proof of Environmental Sustainability activities and best practices for CNCF projects](https://github.com/cncf/tag-env-sustainability/issues/64#issuecomment-1496197590) issue.


## Resources

- CI [Github Workflows](https://github.com/falcosecurity/libs/tree/master/.github/workflows)
- [falcosecurity/kernel-crawler](https://github.com/falcosecurity/kernel-crawler/) supported [kernels](https://github.com/falcosecurity/kernel-crawler/tree/kernels) 
- Issue [CI Integration for Driver Test Suites](https://github.com/falcosecurity/libs/issues/531)
- CNCF TAG Environmental Sustainability [Proof of Environmental Sustainability activities and best practices for CNCF projects](https://github.com/cncf/tag-env-sustainability/issues/64#issuecomment-1496197590)


## Appendix 1

Below is an example of a kernel test grid, which is not the final grid but serves to provide a clearer and more concrete illustration. Each VM is booted into a predefined kernel release to ensure the correct driver is built, particularly for the `kmod` and `bpf` cases. The test grid will be regularly updated to incorporate the latest kernel versions.

<details>
    <summary>Example Kernel Test Grid</summary>
        <table>
            <tr>
                <td><b>Architecture</b></td>
                <td><b>Driver Type</b</td>
                <td><b>Distribution</b</td>
                <td><b>Kernel (major.minor)</b</td>
                <td><b># Test Runs</b</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>kmod and bpf</td>
                <td>AmazonLinux2</td>
                <td>4.19</td>
                <td>2</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>all drivers</td>
                <td>AmazonLinux2</td>
                <td>5.10</td>
                <td>3</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>kmod and bpf</td>
                <td>AmazonLinux2</td>
                <td>5.4</td>
                <td>2</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>all drivers</td>
                <td>AmazonLinux2022</td>
                <td>5.15</td>
                <td>3</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>all drivers</td>
                <td>AmazonLinux2023</td>
                <td>6.1</td>
                <td>3</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>all drivers</td>
                <td>ArchLinux</td>
                <td>5.18</td>
                <td>3</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>all drivers</td>
                <td>ArchLinux</td>
                <td>6.0</td>
                <td>3</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>kmod</td>
                <td>CentOS</td>
                <td>2.6</td>
                <td>1</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>kmod</td>
                <td>CentOS</td>
                <td>3.10</td>
                <td>1</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>kmod and bpf</td>
                <td>CentOS</td>
                <td>4.18</td>
                <td>2</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>all drivers</td>
                <td>CentOS</td>
                <td>5.14</td>
                <td>3</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>all drivers</td>
                <td>CentOS</td>
                <td>6.3</td>
                <td>3</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>all drivers</td>
                <td>Fedora</td>
                <td>5.17</td>
                <td>3</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>all drivers</td>
                <td>Fedora</td>
                <td>5.8</td>
                <td>3</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>all drivers</td>
                <td>Fedora</td>
                <td>6.2</td>
                <td>3</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>kmod</td>
                <td>OracleLinux</td>
                <td>2.6</td>
                <td>1</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>kmod</td>
                <td>OracleLinux</td>
                <td>3.10</td>
                <td>1</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>kmod and bpf</td>
                <td>OracleLinux</td>
                <td>4.14</td>
                <td>2</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>all drivers</td>
                <td>OracleLinux</td>
                <td>5.15</td>
                <td>3</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>kmod and bpf</td>
                <td>OracleLinux</td>
                <td>5.4</td>
                <td>2</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>kmod and bpf</td>
                <td>Ubuntu</td>
                <td>4.15</td>
                <td>2</td>
            </tr>
            <tr>
                <td>x86_64</td>
                <td>all drivers</td>
                <td>Ubuntu</td>
                <td>6.3</td>
                <td>3</td>
            </tr>
            <tr>
                <td>aarch64</td>
                <td>kmod and bpf</td>
                <td>AmazonLinux2</td>
                <td>5.4</td>
                <td>2</td>
            </tr>
            <tr>
                <td>aarch64</td>
                <td>all drivers</td>
                <td>AmazonLinux2022</td>
                <td>5.15</td>
                <td>3</td>
            </tr>
            <tr>
                <td>aarch64</td>
                <td>kmod and bpf</td>
                <td>ArchLinux</td>
                <td>4.15</td>
                <td>2</td>
            </tr>
            <tr>
                <td>aarch64</td>
                <td>kmod and bpf</td>
                <td>OracleLinux</td>
                <td>4.14</td>
                <td>2</td>
            </tr>
            <tr>
                <td>aarch64</td>
                <td>all drivers</td>
                <td>OracleLinux</td>
                <td>5.15</td>
                <td>3</td>
            </tr>
            <tr>
                <td>aarch64</td>
                <td>all drivers</td>
                <td>Ubuntu</td>
                <td>6.3</td>
                <td>3</td>
            </tr>
            <tr>
                <td>aarch64</td>
                <td>all drivers</td>
                <td>Fedora</td>
                <td>6.2</td>
                <td>3</td>
            </tr>
        </table>
</details>