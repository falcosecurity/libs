# Home of Falco drivers syscalls report

Thanks to our [syscalls-bumper](https://github.com/falcosecurity/syscalls-bumper) project, we are able to always support latest syscalls added to linux kernel.  
Support for new syscalls is initially automatically added by the tool as generic events; when needed, a generic event can be made "specific",  
by creating a whole new event to track it.

## Glossary

* 🟢 -> means that the syscall is implemented as a specific event
* 🟡 -> means that the syscall is implemented as a generic event
