# Shared Memory

This repository contains an example Windows driver that demonstrates shared memory communication between a driver and user-mode application.

## Prerequisites

- Windows development environment.
- Windows Driver Kit (WDK) installed.

## Building the Driver

1. Open the solution in Visual Studio or build from the command line using the WDK build tools.
2. Build the driver project to generate the driver file (e.g., `Driver.sys`).

## Loading the Driver

1. Disable driver signature enforcement on your machine (for testing purposes).
2. Open a Command Prompt with administrative privileges.
3. Use the following command to load the driver:

```
sc create Driver binPath=Path\To\Driver.sys type=kernel
sc start Driver
```

## Using the Driver

1. Make sure the driver is loaded and running.
2. The driver sets up a shared memory region, and you can interact with it through the provided functions.

### ReadSharedMemory Function

The `ReadSharedMemory` function maps the shared memory into the current process's address space. It returns an NTSTATUS code to indicate success or failure.

### CreateSharedMemory Function

The `CreateSharedMemory` function initializes the shared memory region with appropriate security settings. It sets up an Access Control List (ACL) for the shared memory.

### DriverLoop Function

The `DriverLoop` function demonstrates the interaction with the shared memory. It reads from the shared memory and processes the data. In this example, it sends data back to the shared memory.

## Unloading the Driver

1. Open a Command Prompt with administrative privileges.
2. Use the following command to unload the driver:

```
sc stop Driver
sc delete Driver
```

## Important Notes

- This example demonstrates shared memory communication and basic driver operations. It's essential to adapt the code for production use, including proper error handling and security considerations.
- This code is for educational purposes and should not be used in a production environment without thorough testing and customization.

## Ressources

- [fengjixuchui/SharedMemory-By-Frankoo](https://github.com/fengjixuchui/SharedMemory-By-Frankoo)

## License

This code is provided under the MIT License. See the [LICENSE](LICENSE) file for details.

For questions or issues, please contact [TheMonsterDev](mailto:themonsterdev@gmail.com).
