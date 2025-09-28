console.log("[Agent] Record agent is loading...");

// Find the address of the function we want to hook
const recvfromPtr = Module.findGlobalExportByName('recvfrom');
if (!recvfromPtr) throw new Error("'recvfrom' could not be found.");

console.log(`[Agent] Hooking recvfrom at address: ${recvfromPtr}`);

const originalRecvfrom = new NativeFunction(recvfromPtr,
  'ssize_t', ['int', 'pointer', 'size_t', 'int', 'pointer', 'pointer']
);

// Use Interceptor.replace to completely control the function
Interceptor.replace(recvfromPtr, new NativeCallback((socket, buffer, length, flags, addr, addrlen) => {
  try {
    // 1. Call the original function to get real controller data
    const bytesRead = originalRecvfrom(socket, buffer, length, flags, addr, addrlen);

    // 2. If data was received, read it from the buffer
    if (bytesRead > 0 && addrlen != 0 && length == 2048) {
      console.log(`[Agent] Captured recvfrom: socket=${socket}, length=${length}, bytesRead=${bytesRead}, address=${addr}, address_len=${addrlen}`);
      // 3. Send the data to Python to be saved to the file
      send({ action: 'record_data' }, buffer.readByteArray(bytesRead));
    }

    // 4. Return the original result to the application
    return bytesRead;
  } catch (error) {
    console.error(`[Agent] Error setting up hooks: ${error}`);
  }
}, 'ssize_t', ['int', 'pointer', 'size_t', 'int', 'pointer', 'pointer']));

console.log("[Agent] Recording hook for 'recvfrom' is now active.");