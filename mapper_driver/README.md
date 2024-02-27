# Mapper Driver

## How to install

1. The driver is signed by a test signature, so, in order for the installation to succeed, Test Signing must be enabled on the target machine. As an Administrator, deploy the following command:

```
bcdedit /set testsigning on
```

Then reboot the system...


2. Install (as Administrator):

```
sc create MapperDrv type= kernel binPath= C:\Users\tester\Desktop\driver_test1\x64\Release\MapperDrv.sys
```

Start:

```
sc start MapperDrv
```

Start:

```
sc stop MapperDrv
```
