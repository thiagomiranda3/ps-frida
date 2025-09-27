import frida
import sys
import os
import struct
import argparse

APP_PATH = "/Applications/RemotePlay.app/Contents/MacOS/RemotePlay"

def load_recording(filename):
    """Reads the recording file and parses it into a list of data packets."""
    packets = []
    try:
        with open(filename, "rb") as f:
            while True:
                length_bytes = f.read(4)
                if not length_bytes:
                    break
                length = struct.unpack('I', length_bytes)[0]
                
                packet_data = f.read(length)
                if len(packet_data) < length:
                    break
                packets.append(packet_data)
        print(f"[REPLAYER] Loaded {len(packets)} packets from {filename}")
        return packets
    except FileNotFoundError:
        print(f"[REPLAYER] Error: Recording file '{filename}' not found.")
        return []

def main():
    # --- 1. Set up Argument Parser ---
    parser = argparse.ArgumentParser(
        description="A record and replay tool for PS Remote Play using Frida."
    )
    # Add the new --pid argument to the main parser
    parser.add_argument(
        '-p', '--pid', 
        type=int, 
        help='PID of an already running process to attach to (instead of spawning a new one).'
    )
    
    subparsers = parser.add_subparsers(dest='mode', required=True, help='Execution mode')

    parser_record = subparsers.add_parser('record', help='Record a new macro.')
    parser_record.add_argument(
        '-o', '--output', 
        required=True, 
        help='Path to save the recording file.'
    )

    parser_replay = subparsers.add_parser('replay', help='Replay a macro from a file.')
    parser_replay.add_argument(
        '-i', '--input', 
        required=True, 
        help='Path to the macro file to replay.'
    )

    args = parser.parse_args()

    # --- 2. Define the message handler ---
    def on_message(message, data):
        if message.get('type') != 'send':
            return

        payload = message.get('payload', {})
        action = payload.get('action')

        if action == 'record_data':
            output_file = args.output
            with open(output_file, "ab") as f:
                f.write(struct.pack('I', len(data)))
                f.write(data)

    def on_agent_log(level, text):
        """This function will be called every time the agent uses console.log"""
        print(f"[{level.upper()}] {text}")

    print(f"--- Starting in {args.mode.upper()} mode ---")

    # --- 3. Attach or Spawn Process based on --pid argument ---
    session = None
    pid_to_resume = None
    device = frida.get_local_device()

    try:
        if args.pid:
            # A PID was provided, so we attach to it
            pid = args.pid
            print(f"[*] Attaching to running process with PID: {pid}...")
            session = device.attach(pid)
        else:
            # No PID, so we spawn a new process
            print(f"[*] Spawning new process: {APP_PATH}...")
            pid = device.spawn([APP_PATH])
            session = device.attach(pid)
            pid_to_resume = pid # Mark this PID to be resumed later
            
    except frida.ProcessNotFoundError:
        print(f"Error: Process with PID {args.pid} not found.")
        sys.exit(1)
    except frida.ExecutableNotFoundError:
        print(f"Error: Executable not found at '{APP_PATH}'. Please check the path.")
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        sys.exit(1)

    # --- 4. Inject Script and Initialize ---
    with open("agent_" + args.mode + ".js", "r") as f:
        script_code = f.read()
    
    script = session.create_script(script_code)
    
    script.set_log_handler(on_agent_log)
    script.on('message', on_message)
    script.load()

    if args.mode == 'replay':
        macro_data = load_recording(args.input)
        if not macro_data:
            print("No macro data to replay. Exiting.")
            session.detach()
            return
        print("[*] Packing and sending macro data to agent...")
        blob_to_send = b"".join([struct.pack('I', len(p)) + p for p in macro_data])
        script.post({'type': 'load_macro'}, blob_to_send)

    # --- 5. Resume if we spawned the process ---
    if pid_to_resume:
        device.resume(pid_to_resume)

    input("[*] Agent injected. Press Enter to detach and exit. ")
    session.detach()
    print("[*] Detached successfully. Exiting.")

if __name__ == '__main__':
    main()