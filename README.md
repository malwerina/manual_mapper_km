# kernel_mapper1

Just a little demo of manual PE mapping in kernel mode.
Elements:
1. Mapper driver: it waits for the payloads, maps them, and run in a new kernel thread. The payload is reqired to have a function exported: `RunMe` with which the execution will start.
2. Payload driver: a sample payload that can be sent to the manual mapper. It reqires a name of an executable as an argument. During its run, it will watch search for the process with the given name, and elevate it.
3. Driver client: a usermode application that can be used for sending the payload to the driver, with specified parameter.

Hey, what if I made a malicious contribution to this project, and pretend that this was another person?

