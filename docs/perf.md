# Home of Falco Perf Monitoring

Our CI is capable of continuously benchmarking performance of our userspace code, both CPU and memory.   
Every PR will have a comment with the perf diff from master for multiple aspects, while on master the flamegraph are pushed to this github pages.

Navigate to the perf reports on the left, or click these links:

* [unit tests cpu perf](perf_unit_tests.md)
* [scap file reading cpu perf](perf_scap_file.md)
* [unit tests memory profile](heaptrack_unit_tests.md)
* [scap file reading memory profile](heaptrack_scap_file.md)