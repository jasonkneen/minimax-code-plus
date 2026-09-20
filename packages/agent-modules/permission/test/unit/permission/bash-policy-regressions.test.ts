import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';

import { applyPermissionUpdate, createToolPermissionContext } from '../../../src/context.js';
import { BashToolPermissionChecker } from '../../../src/tools/bash-checker.js';
import { evaluateBashStatic } from '../../../src/tools/bash-permission.js';
import type { PermissionBehavior, PermissionRule } from '../../../src/types.js';

function bashRule(behavior: PermissionBehavior, content?: string): PermissionRule {
  return {
    source: 'session',
    ruleBehavior: behavior,
    ruleValue: { toolName: 'bash', ruleContent: content },
  };
}

describe.each(['default', 'auto', 'bypass'] as const)('bash rule precedence in %s mode', (mode) => {
  const commands = [
    'npm publish',
    'nohup npm publish',
    'timeout 30 npm publish',
    'nice -n 5 npm publish',
    'setsid npm publish',
    'xargs npm publish',
    'nohup timeout 30 npm publish',
    'CI=1 npm publish',
    'env CI=1 npm publish',
    'nohup /usr/bin/npm publish',
    'echo ready && nohup npm publish',
  ];

  describe.each(['deny', 'ask'] as const)('%s before allow', (behavior) => {
    it.each(commands)('enforces the restricted prefix for %s', (command) => {
      const rules = [bashRule('allow', 'npm:*'), bashRule(behavior, 'npm publish:*')];
      expect(evaluateBashStatic(command, rules, undefined, mode).verdict).toBe(behavior);
    });

    it.each(['npm publish', 'npm pub*'])('matches stripped exact/wildcard rule %s', (content) => {
      const rules = [bashRule('allow', 'npm:*'), bashRule(behavior, content)];
      expect(evaluateBashStatic('nohup npm publish', rules, undefined, mode).verdict).toBe(
        behavior,
      );
    });

    it('still matches raw wrapper rules', () => {
      const rules = [bashRule('allow', 'npm:*'), bashRule(behavior, 'nohup npm:*')];
      expect(evaluateBashStatic('nohup npm publish', rules, undefined, mode).verdict).toBe(
        behavior,
      );
    });

    it('still matches whole-tool rules', () => {
      const rules = [bashRule('allow', 'npm:*'), bashRule(behavior)];
      expect(evaluateBashStatic('nohup npm publish', rules, undefined, mode).verdict).toBe(
        behavior,
      );
    });
  });

  it('allows an unrestricted wrapped command in the same prefix family', () => {
    const rules = [bashRule('allow', 'npm:*'), bashRule('deny', 'npm publish:*')];
    expect(evaluateBashStatic('nohup npm install', rules, undefined, mode).verdict).toBe('allow');
  });

  it('keeps deny stronger than ask regardless of rule order', () => {
    const rules = [
      bashRule('ask', 'npm:*'),
      bashRule('allow', 'npm:*'),
      bashRule('deny', 'npm publish:*'),
    ];
    expect(evaluateBashStatic('nohup npm publish', rules, undefined, mode).verdict).toBe('deny');
  });
});

describe('permission context rule updates', () => {
  it.each(['addRules', 'replaceRules', 'removeRules'] as const)(
    '%s preserves local-script classification and the host file probe',
    (type) => {
      const workingDirectory = path.resolve('synthetic-workspace');
      const isFile = vi.fn((file: string) => file === path.join(workingDirectory, 'build.js'));
      const ctx = createToolPermissionContext({
        workingDirectory,
        dataDir: path.join(workingDirectory, 'data'),
        homeDir: path.join(workingDirectory, 'home'),
        platform: 'linux',
        shellFamily: 'posix',
        isFile,
        rules: [{ source: 'session', ruleBehavior: 'allow', ruleValue: { toolName: 'read' } }],
      });
      const checker = new BashToolPermissionChecker();
      const input = { command: 'echo ready && node ./build.js' };
      const before = checker.checkPermissions('bash', input, ctx);
      expect(isFile).toHaveBeenCalledWith(path.join(workingDirectory, 'build.js'));
      isFile.mockClear();

      const updated = applyPermissionUpdate(ctx, {
        type,
        source: 'session',
        destination: 'session',
        behavior: 'allow',
        rules: [{ toolName: 'read' }],
      });
      expect(checker.checkPermissions('bash', input, updated)).toEqual(before);
      expect(isFile).toHaveBeenCalledWith(path.join(workingDirectory, 'build.js'));
      expect(updated.isFile).toBe(isFile);
      expect(updated).not.toBe(ctx);
      expect(Object.isFrozen(updated)).toBe(true);
      expect(Object.isFrozen(updated.rules)).toBe(true);
      expect(ctx.rules).toHaveLength(1);
    },
  );
});
