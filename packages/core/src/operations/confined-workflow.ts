/** Engine entry point for an externally confined, source-bound worker.
 * The supervisor owns admission, freshness, mounts and the durable run identity.
 * This module neither accepts network requests nor establishes confinement.
 */
import { isDeepStrictEqual } from 'node:util';
import { lstat, readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { z } from '@hono/zod-openapi';
import { getHomeWorkflowsPath, getHomeCommandsPath, getHomeScriptsPath } from '@archon/paths';
import { CodexProvider } from '@archon/providers/codex/provider';
import { registerBuiltinProviders } from '@archon/providers/registry';
import type { WorkflowConfig, WorkflowDeps } from '@archon/workflows/deps';
import {
  executeWorkflow,
  prepareWorkflowSource,
  finalizeWorkflowSource,
  resolveProjectPaths,
  type PreparedWorkflowSource,
} from '@archon/workflows/executor';
import {
  capturedSourceRoots,
  loadWorkflowSource,
  recordSelectedWorkflow,
  workflowSourceConfigSchema,
  getRunSourceCapturePath,
} from '@archon/workflows/workflow-source';
import { discoverWorkflowsWithConfig } from '@archon/workflows/workflow-discovery';
import type { WorkflowDefinition } from '@archon/workflows/schemas/workflow';
import { SqliteAdapter } from '../db/adapters/sqlite';
import { withDatabase } from '../db/connection';
import { createWorkflowStore } from '../workflows/store-adapter';

export const confinedInvocationSchema = z.strictObject({
  runId: z.uuid(),
  cwd: z.string().startsWith('/'),
  sourceRoot: z.string().startsWith('/'),
  workflowIdentity: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/),
  model: z.string().min(1).max(128),
  codexBinary: z.string().startsWith('/'),
});
export type ConfinedInvocation = z.infer<typeof confinedInvocationSchema>;

export const sealedInvocationSchema = confinedInvocationSchema.extend({
  captureRoot: z.string().startsWith('/'),
  workflowRevision: z.string().regex(/^[0-9a-f]{64}$/),
  sourceConfig: workflowSourceConfigSchema,
});
export type SealedInvocation = z.infer<typeof sealedInvocationSchema>;

function dependencies(input: ConfinedInvocation): WorkflowDeps {
  registerBuiltinProviders();
  const codexDefaults = {
    model: input.model,
    codexBinaryPath: input.codexBinary,
    webSearchMode: 'disabled' as const,
  };
  const config: WorkflowConfig = {
    assistant: 'codex',
    commands: {},
    defaults: { loadDefaultCommands: false, loadDefaultWorkflows: false },
    assistants: {
      claude: {},
      codex: codexDefaults,
    },
  };
  return {
    store: createWorkflowStore(),
    loadConfig: () => Promise.resolve(config),
    getAgentProvider: (provider): CodexProvider => {
      if (provider !== 'codex') throw new Error('confined_provider_unsupported');
      return new CodexProvider();
    },
  };
}

async function selectClosedWorkflow(
  deps: WorkflowDeps,
  input: ConfinedInvocation,
  prepared: PreparedWorkflowSource
): Promise<WorkflowDefinition> {
  const { workflows, errors } = await discoverWorkflowsWithConfig(
    input.cwd,
    deps.loadConfig,
    prepared.roots
  );
  const matches = workflows.filter(value => value.workflow.name === input.workflowIdentity);
  if (errors.length || matches.length !== 1) throw new Error('confined_workflow_unresolved');
  const workflow = matches[0].workflow;
  if (workflow.provider !== undefined && workflow.provider !== 'codex') {
    throw new Error('confined_provider_unsupported');
  }
  if (workflow.model !== undefined && workflow.model !== input.model) {
    throw new Error('confined_model_mismatch');
  }
  for (const key of [
    'fallbackModel',
    'persist_sessions',
    'sandbox',
    'container',
    'worktree',
    'requires',
    'inputs',
  ]) {
    if (key in workflow) throw new Error('confined_workflow_setting_unsupported');
  }
  if (
    workflow.interactive ||
    (workflow.webSearchMode !== undefined && workflow.webSearchMode !== 'disabled')
  ) {
    throw new Error('confined_workflow_setting_unsupported');
  }
  // Runtime sub-runs resolve from live authoring roots in the general engine.
  // Keep this first contract to a static prompt/command/bash graph; no capability
  // may appear merely because an unsupported node is currently unreachable.
  for (const node of workflow.nodes) {
    if (node.kind !== 'agent' && !(node.kind === 'exec' && node.runtime === 'sh')) {
      throw new Error('confined_node_unsupported');
    }
    for (const key of [
      'workflow',
      'include',
      'loop',
      'loop_group',
      'mcp',
      'skills',
      'plugins',
      'agents',
      'hooks',
      'persist_session',
      'fallbackModel',
      'sandbox',
      'betas',
    ]) {
      if (key in node) throw new Error('confined_node_unsupported');
    }
    if ('provider' in node && node.provider !== undefined && node.provider !== 'codex') {
      throw new Error('confined_provider_unsupported');
    }
    if ('model' in node && node.model !== undefined && node.model !== input.model) {
      throw new Error('confined_model_mismatch');
    }
    if (
      'webSearchMode' in node &&
      node.webSearchMode !== undefined &&
      node.webSearchMode !== 'disabled'
    ) {
      throw new Error('confined_node_unsupported');
    }
  }
  return workflow;
}

/** Defense in depth for a supervisor-owned, already staged release tree.
 * The caller must prevent concurrent writers during this check and capture;
 * this path walk alone is not a race-safe staging boundary.
 */
async function requireStagedTree(root: string): Promise<void> {
  let entries = 0;
  let bytes = 0;
  async function visit(path: string): Promise<void> {
    const info = await lstat(path);
    if (++entries > 10000 || info.isSymbolicLink()) throw new Error('confined_source_unsupported');
    if (info.isDirectory()) {
      for (const name of await readdir(path)) await visit(join(path, name));
    } else if (info.isFile() && info.nlink === 1) {
      bytes += info.size;
      if (bytes > 16 * 1024 * 1024) throw new Error('confined_source_too_large');
      if (path.startsWith(join(root, '.archon/workflows') + '/') && /\.ya?ml$/.test(path)) {
        // The general loader deliberately drops/normalizes some settings. A
        // closed contract rejects unsupported authored fields before that step.
        z.strictObject({
          name: z.string(),
          description: z.string(),
          provider: z.literal('codex').optional(),
          model: z.string().optional(),
          webSearchMode: z.literal('disabled').optional(),
          nodes: z.array(
            z.strictObject({
              id: z.string(),
              depends_on: z.array(z.string()).optional(),
              provider: z.literal('codex').optional(),
              model: z.string().optional(),
              prompt: z.string().optional(),
              command: z.string().optional(),
              bash: z.string().optional(),
            })
          ),
        }).parse(Bun.YAML.parse(await readFile(path, 'utf8')));
      }
    } else {
      throw new Error('confined_source_unsupported');
    }
  }
  await visit(root);
}

/** Prepare in a clean supervisor process before mounting the FINAL capture read-only.
 * The supervisor compares the returned revision to its requested release before
 * execution. This operation never plans, creates a worktree or invokes a provider.
 */
export async function prepareConfinedWorkflow(raw: unknown): Promise<SealedInvocation> {
  const input = confinedInvocationSchema.parse(raw);
  await requireStagedTree(input.sourceRoot);
  // General capture includes home-scoped trees even with bundled defaults off.
  // This closed entry requires absent ambient authoring scopes, not merely a
  // caller promise to select a project workflow over them.
  for (const path of [getHomeWorkflowsPath(), getHomeCommandsPath(), getHomeScriptsPath()]) {
    try {
      await lstat(path);
    } catch (error) {
      if (error instanceof Error && 'code' in error && error.code === 'ENOENT') continue;
      throw error;
    }
    throw new Error('confined_ambient_source_unsupported');
  }
  const database = new SqliteAdapter(':memory:');
  try {
    return await withDatabase(database, async () => {
      const deps = dependencies(input);
      const prepared = await prepareWorkflowSource(deps, {
        sourceRoot: input.sourceRoot,
        runId: input.runId,
      });
      await selectClosedWorkflow(deps, input, prepared);
      await recordSelectedWorkflow(prepared.captureRoot, input.workflowIdentity);
      const finalized = await finalizeWorkflowSource(deps, prepared, { cwd: input.cwd });
      return {
        ...input,
        captureRoot: finalized.captureRoot,
        workflowRevision: finalized.manifest.digest,
        sourceConfig: finalized.manifest.source_config,
      };
    });
  } finally {
    await database.close();
  }
}

/** Run only after the supervisor seals the request, runtime and actual capture.
 * SQLite remains in this process's memory. The supervisor must never use worker
 * output as admission identity, retry permission or verification evidence.
 */
export async function executeConfinedWorkflow(raw: unknown): Promise<string> {
  const input = sealedInvocationSchema.parse(raw);
  const database = new SqliteAdapter(':memory:');
  try {
    return await withDatabase(database, async () => {
      const deps = dependencies(input);
      const capture = await loadWorkflowSource(input.captureRoot, input.workflowRevision);
      if (!isDeepStrictEqual(capture.manifest.source_config, input.sourceConfig))
        throw new Error('confined_config_mismatch');
      if (capture.manifest.workflow_name !== input.workflowIdentity)
        throw new Error('confined_identity_mismatch');
      const prepared: PreparedWorkflowSource = {
        runId: input.runId,
        ...capture,
        roots: capturedSourceRoots(capture.captureRoot, input.sourceConfig),
      };
      const paths = await resolveProjectPaths(deps, input.cwd, input.runId);
      if (getRunSourceCapturePath(paths.artifactsDir) !== input.captureRoot)
        throw new Error('confined_capture_not_final');
      const workflow = await selectClosedWorkflow(deps, input, prepared);
      await database.query(
        'INSERT INTO remote_agent_conversations (id, platform_type, platform_conversation_id) VALUES ($1, $2, $3)',
        [input.runId, 'confined', input.runId]
      );
      const result = await executeWorkflow(
        deps,
        {
          sendMessage: () => Promise.resolve(),
          getStreamingMode: () => 'batch',
          getPlatformType: () => 'confined',
        },
        input.runId,
        input.cwd,
        workflow,
        '',
        input.runId,
        { preparedSource: prepared }
      );
      return 'paused' in result ? 'paused' : result.success ? 'completed' : 'failed';
    });
  } finally {
    await database.close();
  }
}
