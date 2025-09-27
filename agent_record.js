let MODE = 'record';
let MACRO_FRAMES = [];
let REPLAY_INDEX = 0;

// This function handles messages FROM the Python controller
recv(message => {
  if (message.type === 'load_macro') {
    MACRO_FRAMES = message.payload;
    console.log(`[Agent] Loaded ${MACRO_FRAMES.length} frames for replay.`);
  }
});

console.log(`[Agent] Mode set to: ${MODE}`);

try {
  // Find the address of the function we want to hook
  const recvfromPtr = Module.findGlobalExportByName('recvfrom');

  console.log(`[Agent] Hooking recvfrom at address: ${recvfromPtr}`);

  // Create a NativeFunction object for the original recvfrom.
  // This is needed in record mode to call the real function.
  const originalRecvfrom = new NativeFunction(recvfromPtr,
    'ssize_t', ['int', 'pointer', 'size_t', 'int', 'pointer', 'pointer']
  );

  // Use Interceptor.replace to completely control the function
  Interceptor.replace(recvfromPtr, new NativeCallback((socket, buffer, length, flags, addr, addrlen) => {
    // 1. Call the original function to get real controller data
    const bytesRead = originalRecvfrom(socket, buffer, length, flags, addr, addrlen);

    // 2. If data was received, read it from the buffer
    if (bytesRead > 0) {
      const data = buffer.readByteArray(bytesRead);
      // 3. Send the data to Python to be saved to the file
      send({ action: 'record_data' }, data);
    }

    // 4. Return the original result to the application
    return bytesRead;
  }, 'ssize_t', ['int', 'pointer', 'size_t', 'int', 'pointer', 'pointer']));

} catch (error) {
  console.error(`[Agent] Error setting up hooks: ${error}`);
}