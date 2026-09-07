/** Real capture and SQLite seams, isolated from package-level module mocks. */
import { afterAll, describe, expect, test } from 'bun:test';
import { mkdtemp, mkdir, writeFile, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { removeTempTree } from '@archon/paths/test-utils';

const originalHome = process.env.ARCHON_HOME;
const root = await mkdtemp(join(tmpdir(), 'archon-confined-'));
process.env.ARCHON_HOME = join(root, 'state');
const { prepareConfinedWorkflow, executeConfinedWorkflow } = await import('./confined-workflow');
const { SqliteAdapter } = await import('../db/adapters/sqlite');
const { getDatabase, getDialect, withDatabase } = await import('../db/connection');

afterAll(async () => {
  if (originalHome === undefined) delete process.env.ARCHON_HOME;
  else process.env.ARCHON_HOME = originalHome;
  await removeTempTree(root);
});

async function fixture(settings = '') {
  const source = await mkdtemp(join(root, 'source-'));
  await mkdir(join(source, '.archon/workflows'), { recursive: true });
  await writeFile(
    join(source, '.archon/workflows/proof.yaml'),
    `name: proof\ndescription: Controlled test\n${settings}nodes:\n  - id: check\n    bash: 'true'\n`
  );
  return {
    runId: crypto.randomUUID(),
    cwd: '/workspace',
    sourceRoot: source,
    workflowIdentity: 'proof',
    model: 'fixture-model',
    codexBinary: '/usr/local/bin/codex',
  };
}

describe('confined engine entry', () => {
  test('retains captured identity and rejects changed executed bytes', async () => {
    const input = await fixture();
    const sealed = await prepareConfinedWorkflow(input);
    expect(sealed.workflowRevision).toMatch(/^[0-9a-f]{64}$/);
    await expect(executeConfinedWorkflow({ ...sealed, workflowIdentity: 'other' })).rejects.toThrow(
      'confined_identity_mismatch'
    );
    await expect(
      executeConfinedWorkflow({ ...sealed, workflowRevision: '0'.repeat(64) })
    ).rejects.toThrow();
    await writeFile(join(sealed.captureRoot, 'project/.archon/workflows/proof.yaml'), 'changed');
    await expect(executeConfinedWorkflow(sealed)).rejects.toThrow();
  });

  test.each([
    'provider: claude\n',
    'model: other\n',
    'fallbackModel: other\n',
    'persist_sessions: true\n',
    'webSearchMode: live\n',
  ])('rejects workflow policy %s during preparation', async settings => {
    await expect(prepareConfinedWorkflow(await fixture(settings))).rejects.toThrow();
  });

  test('rejects source links before capture', async () => {
    const input = await fixture();
    await symlink('/etc/passwd', join(input.sourceRoot, 'escape'));
    await expect(prepareConfinedWorkflow(input)).rejects.toThrow('confined_source_unsupported');
  });

  test('rejects ambient workflow and escaping script scopes before capture', async () => {
    const input = await fixture();
    const { getHomeWorkflowsPath, getHomeScriptsPath } = await import('@archon/paths');
    for (const path of [getHomeWorkflowsPath(), getHomeScriptsPath()]) {
      try {
        await mkdir(path, { recursive: true });
        await symlink('/etc/passwd', join(path, 'escape'));
        await expect(prepareConfinedWorkflow(input)).rejects.toThrow(
          'confined_ambient_source_unsupported'
        );
      } finally {
        await removeTempTree(path);
      }
    }
  });

  test('concurrent scoped databases remain independent across awaits', async () => {
    const databases = [new SqliteAdapter(':memory:'), new SqliteAdapter(':memory:')];
    try {
      await Promise.all(
        databases.map((database, index) =>
          withDatabase(database, async () => {
            await database.query('CREATE TABLE confinement_probe (value INTEGER)');
            await database.query('INSERT INTO confinement_probe VALUES ($1)', [index]);
            await new Promise(resolve => setTimeout(resolve, 10));
            expect(getDatabase()).toBe(database);
            expect(getDialect()).toBe(database.sql);
            const result = await getDatabase().query<{ value: number }>(
              'SELECT value FROM confinement_probe'
            );
            expect(result.rows).toEqual([{ value: index }]);
          })
        )
      );
    } finally {
      await Promise.all(databases.map(database => database.close()));
    }
  });
});
