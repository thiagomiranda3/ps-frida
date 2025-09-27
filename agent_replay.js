let MODE = 'replay';
let MACRO_FRAMES = [];
let FRAMES_SIZE = 0;
let REPLAY_INDEX = 0;

// This function handles messages FROM the Python controller
recv((message, data) => {
  if (message.type === 'load_macro') {
    console.log(`[Agent] Received macro data blob of size ${data.byteLength}. Parsing frames...`);
    
    // This is the raw ArrayBuffer of all combined packets
    const all_frames_buffer = data;
    
    let offset = 0;
    // Loop through the buffer, reading the 4-byte length prefix for each frame
    while (offset < all_frames_buffer.byteLength) {
        // Read the length (as a 32-bit unsigned integer)
        const frameLength = new DataView(all_frames_buffer, offset, 4).getUint32(0, true);
        offset += 4;
        
        // Slice out the frame data
        const frame = all_frames_buffer.slice(offset, offset + frameLength);
        MACRO_FRAMES.push(frame);
        
        offset += frameLength;
    }
    
    FRAMES_SIZE = MACRO_FRAMES.length;
    console.log(`[Agent] Parsed ${FRAMES_SIZE} frames for replay.`);
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
    if (FRAMES_SIZE === 0) {
      console.log("[Agent] Replay mode active, but no frames to play yet. Returning original.");
      const bytesRead = originalRecvfrom(socket, buffer, length, flags, addr, addrlen);
      return bytesRead;
    }

    // 1. Get the next frame from our recorded macro
    const frameData = MACRO_FRAMES[REPLAY_INDEX];
    const frameLength = frameData.byteLength;

    // 2. Write our fake data into the application's buffer
    buffer.writeByteArray(frameData);

    // 3. Advance the index, looping back to the start when finished
    REPLAY_INDEX = (REPLAY_INDEX + 1) % FRAMES_SIZE;

    // 4. Return the length of our fake frame, tricking the application
    return frameLength;
  }, 'ssize_t', ['int', 'pointer', 'size_t', 'int', 'pointer', 'pointer']));
} catch (error) {
  console.error(`[Agent] Error setting up hooks: ${error}`);
}