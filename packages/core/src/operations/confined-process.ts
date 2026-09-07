/** Linux-only protection of engine memory from same-UID generated descendants. */
import { dlopen, FFIType } from 'bun:ffi';
import { fstatSync } from 'node:fs';

export function protectConfinedProcess(): void {
  if (process.platform !== 'linux' || process.arch !== 'x64') {
    throw new Error('confined_process_platform_unsupported');
  }
  const library = dlopen('libc.so.6', {
    prctl: {
      args: [FFIType.i32, FFIType.u64, FFIType.u64, FFIType.u64, FFIType.u64],
      returns: FFIType.i32,
    },
    fcntl: { args: [FFIType.i32, FFIType.i32, FFIType.i32], returns: FFIType.i32 },
  });
  try {
    if (library.symbols.prctl(4, 0, 0, 0, 0) !== 0 || library.symbols.prctl(3, 0, 0, 0, 0) !== 0) {
      throw new Error('confined_process_memory_unprotected');
    }
    // Test/debug correlation only. Neither this environment value nor worker
    // process output is trusted by the external admission journal.
    process.env.ARCHON_CONFINED_ENGINE_PID = String(process.pid);
    if (process.env.ARCHON_CONTROL_FD !== undefined) {
      const fd = Number(process.env.ARCHON_CONTROL_FD);
      if (!Number.isInteger(fd) || fd < 3 || fd > 255 || !fstatSync(fd).isSocket()) {
        throw new Error('confined_control_descriptor_invalid');
      }
      const flags = library.symbols.fcntl(fd, 1, 0);
      if (flags < 0 || library.symbols.fcntl(fd, 2, flags | 1) !== 0) {
        throw new Error('confined_control_descriptor_unprotected');
      }
      process.env.ARCHON_CONTROL_INODE = String(fstatSync(fd).ino);
    }
  } finally {
    library.close();
  }
}
