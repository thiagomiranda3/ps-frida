let MACRO_FRAMES = [];
let REPLAY_INDEX = 0;

// The recv function now accepts a second argument, 'data', for the binary payload.
recv((message, data) => {
  try {
    if (message.type === 'load_macro') {
      console.log(`[Agent] Received macro data blob of size ${data.byteLength}. Parsing frames...`);
      const all_frames_buffer = data;
      let offset = 0;

      let recordedFrames = [];
      // Loop through the raw binary blob from Python
      while (offset < all_frames_buffer.byteLength) {
        // Read the 4-byte length prefix for the entire recorded frame
        const totalFrameLength = new DataView(all_frames_buffer, offset, 4).getUint32(0, true);
        offset += 4;

        // Slice out the full frame data (which contains our bundled packets)
        const frame_buffer = all_frames_buffer.slice(offset, offset + totalFrameLength);

        // Now, parse the bundled data from within the frame
        const data_len = new DataView(frame_buffer, 0, 4).getUint32(0, true);
        const data_buf = frame_buffer.slice(4, 4 + data_len);

        const addr_len = new DataView(frame_buffer, 4 + data_len, 4).getUint32(0, true);
        const addr_buf = frame_buffer.slice(4 + data_len + 4, 4 + data_len + 4 + addr_len);

        // Store the parsed data as an object in our array
        recordedFrames.push({
          data: data_buf,
          addr: addr_buf,
          addr_len: addr_len
        });

        offset += totalFrameLength;
      }

      MACRO_FRAMES = recordedFrames;

      console.log(`[Agent] Parsed ${MACRO_FRAMES.length} frames for replay.`);
    }
  } catch (error) {
    console.error("[Agent] Error reading the macro file:", error.stack);
    return 0;
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
    if (MACRO_FRAMES.length === 0) {
      //console.log("[Agent] Replay mode active, but no frames to play yet. Returning original.");
      const bytesRead = originalRecvfrom(socket, buffer, length, flags, address, address_len_ptr);
      return bytesRead;
    }

    const frame = MACRO_FRAMES[REPLAY_INDEX];

    console.log(`[Agent] Replaying frame ${REPLAY_INDEX + 1}/${MACRO_FRAMES.length}: data_len=${frame.data.byteLength}, addr_len=${frame.addr_len}`);

    // 1. Get the max capacity for BOTH buffers from the application.
    const appDataCapacity = length;
    const appAddrCapacity = address_len_ptr.readU32(); // Read the capacity for the address buffer.

    // 2. Determine how many bytes we can safely write to EACH buffer.
    const bytesToWrite = Math.min(frame.data.byteLength, appDataCapacity);
    const addrBytesToWrite = Math.min(frame.addr.byteLength, appAddrCapacity);

    // 3. Slice our recorded data to ensure we don't overflow either buffer.
    const dataChunk = frame.data.slice(0, bytesToWrite);
    const addrChunk = frame.addr.slice(0, addrBytesToWrite);

    // 4. Write the safe chunks of data into the application's memory.
    buffer.writeByteArray(dataChunk);
    //address.writeByteArray(addrChunk);

    // 5. CRITICAL: Write the length of the address we ACTUALLY wrote.
    //address_len_ptr.writeU32(addrBytesToWrite);

    REPLAY_INDEX = (REPLAY_INDEX + 1) % MACRO_FRAMES.length;

    // Return the length of the main data buffer, just like the real function would
    return bytesToWrite;
  } catch (error) {
    console.error("[Agent] Error setting up replay hook:", error.stack);
    return 0;
  }
}, 'ssize_t', ['int', 'pointer', 'size_t', 'int', 'pointer', 'pointer']));