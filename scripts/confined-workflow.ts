/** Private supervisor/worker entry. Never install as a general launch endpoint. */
import { readFile, writeFile } from 'node:fs/promises';
import { closeSync, writeSync } from 'node:fs';
import { BUNDLED_GIT_COMMIT, BUNDLED_VERSION } from '@archon/paths';
import {
  prepareConfinedWorkflow,
  executeConfinedWorkflow,
} from '@archon/core/operations/confined-workflow';

const [mode, request, response] = process.argv.slice(2);
if (mode === 'identity') {
  console.log(JSON.stringify({ sourceRevision: BUNDLED_GIT_COMMIT, version: BUNDLED_VERSION }));
  process.exit(0);
}
if (!request || !response || (mode !== 'prepare' && mode !== 'run')) {
  throw new Error('expected prepare|run request.json response.json');
}
const input: unknown = JSON.parse(await readFile(request, 'utf8'));
const result =
  mode === 'prepare'
    ? await prepareConfinedWorkflow(input)
    : { status: await executeConfinedWorkflow(input) };
if (mode === 'run' && process.env.ARCHON_CONTROL_FD !== undefined && 'status' in result) {
  const fd = Number(process.env.ARCHON_CONTROL_FD);
  // executeConfinedWorkflow validated this descriptor, disabled dumping and set
  // CLOEXEC before untrusted descendants could exist. Do not use output files
  // or an HTTP worker report as an authoritative execution acknowledgement.
  const runId = (input as { runId: string }).runId;
  writeSync(fd, JSON.stringify({ run_id: runId, state: result.status }));
  closeSync(fd);
}
await writeFile(response, JSON.stringify(result));
process.exit(0);
