let MACRO_FRAMES = [];
let REPLAY_INDEX = 0;

function hexStringToArrayBuffer(hexString) {
  // Remove any spaces and ensure we have an even number of characters.
  const cleanHex = hexString.replace(/\s+/g, '');
  if (cleanHex.length % 2 !== 0) {
    console.error("Hex string has an odd number of characters.");
    return null;
  }
  
  // Create a Uint8Array to hold the binary data.
  const byteArray = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    // Parse every two characters as a hex number and add it to the array.
    byteArray[i / 2] = parseInt(cleanHex.substr(i, 2), 16);
  }
  return byteArray.buffer;
}

recv((message) => {
  try {
    if (message.type === 'load_macro') {
      const hexFrames = message.payload;
      console.log(`[Agent] Received ${hexFrames.length} hex frames. Converting to binary...`);
      
      // Use our new helper function to convert the list of strings to a list of ArrayBuffers.
      MACRO_FRAMES = hexFrames.map(hexStringToArrayBuffer);
      
      console.log(`[Agent] Parsed ${MACRO_FRAMES.length} frames for replay.`);
    }
  } catch (error) {
    console.error("[Agent] Error processing macro data:", error.stack);
  }
});

const recvfromPtr = Module.findGlobalExportByName('recvfrom');
if (!recvfromPtr) throw new Error("'recvfrom' could not be found.");

console.log(`[Agent] Hooking recvfrom at address: ${recvfromPtr}`);

// Create a NativeFunction object for the original recvfrom.
const originalRecvfrom = new NativeFunction(recvfromPtr,
  'ssize_t', ['int', 'pointer', 'size_t', 'int', 'pointer', 'pointer']
);

Interceptor.replace(recvfromPtr, new NativeCallback((socket, buffer, length, flags, address, address_len_ptr) => {
  try {
    const bytesRead = originalRecvfrom(socket, buffer, length, flags, address, address_len_ptr);

    if (MACRO_FRAMES.length == 0 || address_len_ptr == 0 || length != 2048) {
      console.log(`[Agent] ORIGINAL frame frameSize=${bytesRead} socket=${socket}, length=${length}, address=${address}, address_len_ptr=${address_len_ptr}`);
      return bytesRead;
    }

    const frameBuffer = MACRO_FRAMES[REPLAY_INDEX];
    const frameSize = frameBuffer.byteLength;

     //const liveData = buffer.readByteArray(bytesRead);

    console.log(`[Agent] Replaying frame ${REPLAY_INDEX + 1}/${MACRO_FRAMES.length}: frameSize=${frameSize} socket=${socket}, length=${length}, address=${address}, address_len_ptr=${address_len_ptr}`);

    // 4. Write the safe chunks of data into the application's memory.
    buffer.writeByteArray(frameBuffer);

    REPLAY_INDEX = (REPLAY_INDEX + 1) % MACRO_FRAMES.length;

    // Return the length of the main data buffer, just like the real function would
    return frameSize;
  } catch (error) {
    console.error("[Agent] Error setting up replay hook:", error.stack);
    return 0;
  }
}, 'ssize_t', ['int', 'pointer', 'size_t', 'int', 'pointer', 'pointer']));