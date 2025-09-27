let MODE = 'replay';
let MACRO_FRAMES = [];
let FRAMES_SIZE = 0;
let REPLAY_INDEX = 0;

// This function handles messages FROM the Python controller
recv(message => {
  if (message.type === 'load_macro') {
    MACRO_FRAMES = message.payload;
    FRAMES_SIZE = MACRO_FRAMES.length;
    //console.log(`[Agent] Loaded ${MACRO_FRAMES.length} frames for replay.`);
  }
});

// Find the address of the function we want to hook
const recvfromPtr = Module.findExportByName(null, 'recvfrom');

// Create a NativeFunction object for the original recvfrom.
// This is needed in record mode to call the real function.
const originalRecvfrom = new NativeFunction(recvfromPtr,
  'ssize_t', ['int', 'pointer', 'size_t', 'int', 'pointer', 'pointer']
);

// Use Interceptor.replace to completely control the function
Interceptor.replace(recvfromPtr, new NativeCallback((socket, buffer, length, flags, addr, addrlen) => {
  if (FRAMES_SIZE === 0) {
    console.log("[Agent] Replay mode active, but no frames to play. Returning 0.");
    return 0; // Tell the app no data was received
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