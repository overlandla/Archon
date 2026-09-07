/** Private supervisor/worker entry. Never install as a general launch endpoint. */
import { readFile, writeFile } from 'node:fs/promises';
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
await writeFile(response, JSON.stringify(result));
process.exit(0);
