// agent_record.js
console.log("[Agent] Record agent is loading...");

try {
  // Find the address of the function we want to hook
  const recvfromPtr = Module.findGlobalExportByName('recvfrom');
  if (!recvfromPtr) throw new Error("'recvfrom' could not be found.");

  console.log(`[Agent] Hooking recvfrom at address: ${recvfromPtr}`);

  Interceptor.attach(recvfromPtr, {
      onEnter: function(args) {
          // In 'onEnter', we save pointers to the memory locations
          // where the OS will write the results.
          this.buffer = args[1];
          this.address = args[4];
          this.address_len_ptr = args[5];
      },
      onLeave: function(retval) {
          // In 'onLeave', after the original function has run,
          // we read the data that the OS wrote.
          const bytesRead = retval.toInt32();
          if (bytesRead <= 0) {
              return; // Nothing to record
          }

          // 1. Read the main controller data buffer
          const data_buf = this.buffer.readByteArray(bytesRead);
          
          // 2. Read the sender's address length and the address data itself
          const addr_len = this.address_len_ptr.readU32();
          const addr_buf = this.address.readByteArray(addr_len);

          // 3. Bundle everything into a single binary message to send to Python.
          // Format: [4 bytes: data_len] [data] [4 bytes: addr_len] [addr_data]
          const total_len = 4 + data_buf.byteLength + 4 + addr_buf.byteLength;
          const message_buf = Memory.alloc(total_len);

          let offset = 0;
          message_buf.add(offset).writeU32(data_buf.byteLength); offset += 4;
          message_buf.add(offset).writeByteArray(data_buf); offset += data_buf.byteLength;
          message_buf.add(offset).writeU32(addr_buf.byteLength); offset += 4;
          message_buf.add(offset).writeByteArray(addr_buf);

          // 4. Send the single, combined buffer back to the Python controller.
          send({ action: 'record_data' }, message_buf.readByteArray(total_len));
      }
  });
  
  console.log("[Agent] Recording hook for 'recvfrom' is now active.");
} catch (error) {
  console.error("[Agent] An error occurred while setting up the hook:", error.stack);
}