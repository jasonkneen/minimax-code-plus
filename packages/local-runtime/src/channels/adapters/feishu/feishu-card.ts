import { createDecipheriv, createHash } from 'node:crypto';

import type { AskQuestionnaireRequest } from '@mavis/shared/questionnaire';

import {
  type ChannelQuestionnaireOptionToken,
  decodeQuestionnaireOptionToken,
} from '../../questionnaire-bridge.js';
import { DEFAULT_BOT_NAME, makeHeader } from './feishu-card-header.js';

// Re-exports so call sites can keep importing from `./feishu-card.js` —
// the reply / thinking card builders live in `./feishu-reply-card.ts` and
// the shared header primitive lives in `./feishu-card-header.ts`.
export { DEFAULT_BOT_NAME, makeHeader } from './feishu-card-header.js';
export {
  buildReplyCard,
  buildThinkingCard,
  parseReplyTextToElements,
} from './feishu-reply-card.js';

/**
 * Feishu / Lark card spec encoder + webhook helpers.
 *
 * Style is aligned with the historical `feat/im-genui-full-mr` (`im-slice-all`
 * worktree) implementation — we emit a Feishu **Card 2.0 form** card with a
 * `select_static` / `multi_select_static` per step plus a single submit
 * button (`form_action_type: 'submit'`), instead of one button per option.
 * The submit value carries `kind: 'questionnaire_submit'` + `requestId` so
 * the host card-action handler can route a `form_value` map back to a
 * structured {@link AskQuestionnaireReplyPayload}.
 *
 * No SDK import here — pure `node:crypto`. This keeps `feishu-card.ts` safe
 * to import from vitest test files without pulling axios/protobufjs in.
 *
 * Architecture-redline note: the historical implementation lived under the
 * IM Gateway in `apps/electron/main/modules/imGateway/questionnaire-card.ts`.
 * This file is the Local Runtime port — the IM Gateway / daemon are NOT
 * brought back, only the card-shape + decode helpers are reused.
 */

// ---------------------------------------------------------------------------
// Constants + types
// ---------------------------------------------------------------------------

/** Suffix appended to a step id to name its free-text ("Others...") input. */
export const QUESTIONNAIRE_OTHER_SUFFIX = '__other';

/** Submit-button value embedded in the questionnaire form card. */
export interface QuestionnaireSubmitActionValue {
  kind: 'questionnaire_submit';
  requestId: string;
  sessionId: string;
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

function normalizeText(s: string): string {
  return s.replace(/\n/g, ' ').trim();
}

function escapeMarkdownCode(s: string): string {
  return s.replace(/`/g, '\\`');
}

function clampOptionLabel(label: string): string {
  const text = normalizeText(label) || '(empty)';
  return text.length > 100 ? `${text.slice(0, 97)}...` : text;
}

// ---------------------------------------------------------------------------
// Card encoders
// ---------------------------------------------------------------------------

/**
 * Build a Feishu Card 2.0 form card from an AskQuestionnaireRequest.
 *
 * Layout: one `form` container holding, per step, a question markdown block
 * plus a form element (`select_static` for single, `multi_select_static` for
 * multiple) named by the step id, an always-present `input` named
 * `${stepId}__other` for the "Others..." path, and a trailing submit `button`
 * whose `value` carries `{ kind: 'questionnaire_submit', requestId, sessionId }`.
 *
 * Mirrors `feat/im-genui-full-mr` (`im-slice-all`) shape so the rendered
 * card looks identical to what users saw before the onboard rewrite.
 */
export function buildQuestionnaireCard(
  questionnaire: AskQuestionnaireRequest,
  botName: string = DEFAULT_BOT_NAME,
): Record<string, unknown> {
  const sessionId = questionnaire.requester?.sessionId ?? '';
  const formElements: unknown[] = [];

  questionnaire.steps.forEach((step, stepIndex) => {
    const headerText = step.header?.trim();
    const questionLines = [`**${stepIndex + 1}. ${escapeMarkdownCode(step.question)}**`];
    if (headerText) {
      questionLines.unshift(`<font color='grey'>${escapeMarkdownCode(headerText)}</font>`);
    }
    if (step.description?.trim()) {
      questionLines.push(
        `<font color='grey'>${escapeMarkdownCode(step.description.trim())}</font>`,
      );
    }
    formElements.push({ tag: 'markdown', content: questionLines.join('\n') });

    if (step.image?.src) {
      const linkText = step.image.alt?.trim() || '配图';
      formElements.push({
        tag: 'markdown',
        content: `[${linkText}](${step.image.src})`,
      });
    }

    const options = step.options.map((opt) => ({
      text: { tag: 'plain_text', content: clampOptionLabel(opt.label) },
      value: opt.id,
    }));

    if (options.length > 0) {
      const selectTag = step.selectionMode === 'multiple' ? 'multi_select_static' : 'select_static';
      formElements.push({
        tag: selectTag,
        name: step.id,
        placeholder: {
          tag: 'plain_text',
          content: step.selectionMode === 'multiple' ? '可多选' : '请选择',
        },
        options,
      });
    }

    // "Others..." free-text input is always available per schema invariant.
    formElements.push({
      tag: 'input',
      name: `${step.id}${QUESTIONNAIRE_OTHER_SUFFIX}`,
      placeholder: { tag: 'plain_text', content: step.otherPlaceholder },
    });
  });

  const submitValue: QuestionnaireSubmitActionValue = {
    kind: 'questionnaire_submit',
    requestId: questionnaire.id,
    sessionId,
  };
  formElements.push({
    tag: 'button',
    text: { tag: 'plain_text', content: '提交' },
    type: 'primary',
    form_action_type: 'submit',
    name: 'questionnaire_submit_btn',
    behaviors: [{ type: 'callback', value: submitValue }],
    value: submitValue,
  });

  return {
    schema: '2.0',
    config: { wide_screen_mode: true, update_multi: true },
    header: makeHeader({
      title: botName,
      subtitle: 'ask',
      template: 'turquoise',
      icon: 'chat_outlined',
      tagText: '问卷',
      tagColor: 'turquoise',
    }),
    body: {
      elements: [
        {
          tag: 'form',
          name: 'questionnaire_form',
          elements: formElements,
        },
      ],
    },
  };
}

/**
 * Read-only "Submitted" card that replaces the questionnaire after the user
 * answers. Deliberately contains NO form container and NO buttons, so it can
 * never be re-submitted.
 */
export function buildQuestionnaireSubmittedCard(
  _questionnaire: AskQuestionnaireRequest,
  botName: string = DEFAULT_BOT_NAME,
): Record<string, unknown> {
  return {
    schema: '2.0',
    // `update_multi: true` is REQUIRED for Card 2.0 PATCH to apply at all —
    // without it Feishu silently no-ops the morph and the card snaps back to
    // its pre-patch state on the next render tick. Same fix already in place
    // on `buildThinkingCard` / `buildReplyCard` / `buildQuestionnaireCard`.
    config: { wide_screen_mode: true, update_multi: true },
    header: makeHeader({
      title: botName,
      subtitle: 'ask',
      template: 'green',
      icon: 'succeed_outlined',
      tagText: '已提交',
      tagColor: 'green',
    }),
    body: {
      elements: [
        {
          tag: 'markdown',
          content: '✅ **已提交**',
        },
      ],
    },
  };
}

/**
 * Read-only "Expired" card that replaces the questionnaire when a submit arrives
 * after the request was superseded by a newer ask or expired. No form
 * container, no buttons — purely informational.
 */
export function buildQuestionnaireExpiredCard(
  questionnaire: AskQuestionnaireRequest,
  botName: string = DEFAULT_BOT_NAME,
): Record<string, unknown> {
  return {
    schema: '2.0',
    // PATCH requires `update_multi: true` (see buildQuestionnaireSubmittedCard).
    config: { wide_screen_mode: true, update_multi: true },
    header: makeHeader({
      title: botName,
      subtitle: 'ask',
      template: 'grey',
      tagText: '已过期',
      tagColor: 'grey',
    }),
    body: {
      elements: [
        {
          tag: 'markdown',
          content: `⌛ **该问卷已过期**${questionnaire.title ? ` — ${escapeMarkdownCode(questionnaire.title)}` : ''}`,
        },
      ],
    },
  };
}

// ---------------------------------------------------------------------------
// Card-action decoder
// ---------------------------------------------------------------------------

/**
 * Subset of the Feishu card-action webhook payload we care about. The full
 * shape carries many fields (token, open_message_id, open_chat_id, …); the
 * adapter projects them onto its own context, but the decoder only needs
 * `action.value` to recover the {@link ChannelQuestionnaireOptionToken}.
 */
export interface FeishuCardActionPayload {
  action?: {
    value?: unknown;
    tag?: string;
    name?: string;
    option?: string;
  };
  open_message_id?: string;
  open_chat_id?: string;
  open_id?: string;
  user_id?: string;
  // ... rest of Feishu fields ignored
}

/**
 * Decoded view of a card action. `token` is `undefined` when the action did
 * not carry a recognisable questionnaire token (foreign card, malformed
 * value); adapters then drop the action without surfacing it to the
 * questionnaire bridge.
 */
export interface DecodedFeishuCardAction {
  token: ChannelQuestionnaireOptionToken | undefined;
  /** Free-form Others text when the user clicked the Others chip + typed. */
  otherText?: string;
  rawValue: unknown;
}

/**
 * Extract a {@link ChannelQuestionnaireOptionToken} from a Feishu card
 * action payload. The decoder is intentionally permissive on the wrapper —
 * Feishu's `value` field can be a JSON-string OR a parsed object; both
 * decode the same way via `decodeQuestionnaireOptionToken`. The Others
 * text comes from either `value.otherText` (preferred) or `action.option`
 * (Feishu input fallback).
 */
export function decodeCardAction(payload: FeishuCardActionPayload): DecodedFeishuCardAction {
  const rawValue = payload.action?.value;
  const valueRecord = isRecord(rawValue) ? rawValue : undefined;
  const tokenCandidate = valueRecord?.token ?? rawValue;
  const token = decodeQuestionnaireOptionToken(tokenCandidate);
  const otherText =
    pickString(valueRecord?.otherText) ??
    pickString(valueRecord?.other) ??
    pickString(payload.action?.option);
  return {
    token,
    ...(otherText ? { otherText } : {}),
    rawValue,
  };
}

function pickString(value: unknown): string | undefined {
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// Encrypt payload decoder (AES-256-GCM over the Feishu envelope)
// ---------------------------------------------------------------------------

/**
 * Decrypt a Feishu webhook body that arrived in the encrypted envelope
 * `{ "encrypt": "<base64>" }`. Returns the decoded JSON object, or
 * `undefined` when decryption fails (wrong key, malformed base64, GCM tag
 * mismatch) so the adapter can choose its own response code.
 *
 * The on-wire layout is an extension of the historical Feishu envelope:
 *   1. key = sha256(encrypt_key) — 32 bytes.
 *   2. ciphertext = base64-decode(encrypt).
 *   3. iv = ciphertext[0..16], body = ciphertext[16..-16], tag = ciphertext[-16..].
 *   4. AES-256-GCM decrypt `body` with `iv`, fail closed if the 16-byte
 *      authentication tag does not verify (`decipher.final()` throws).
 *   5. JSON.parse the resulting UTF-8 string.
 *
 * The 16-byte authentication tag replaces the (unauthenticated) PKCS#7
 * padding that the legacy AES-256-CBC envelope relied on, so any bit-flip
 * attack against the ciphertext or IV is rejected before the payload
 * reaches `JSON.parse`.
 */
export function decryptFeishuEvent(
  encryptedBase64: string,
  encryptKey: string,
): Record<string, unknown> | undefined {
  if (!encryptedBase64 || !encryptKey) return undefined;
  try {
    const key = createHash('sha256').update(encryptKey, 'utf8').digest();
    const cipherBytes = Buffer.from(encryptedBase64, 'base64');
    // Need at least: 16-byte IV + 1-byte body + 16-byte tag.
    if (cipherBytes.length <= 16 + 16) return undefined;
    const iv = cipherBytes.subarray(0, 16);
    const tag = cipherBytes.subarray(-16);
    const body = cipherBytes.subarray(16, -16);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    // `decipher.final()` throws on tag mismatch — authentication happens
    // BEFORE `JSON.parse` so tampered ciphertext can never reach the parser.
    const plain = Buffer.concat([decipher.update(body), decipher.final()]);
    const parsed = JSON.parse(plain.toString('utf8')) as unknown;
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return undefined;
  } catch {
    return undefined;
  }
}

/**
 * Unwrap a webhook body that MAY be encrypted. When `body.encrypt` exists
 * AND `encryptKey` is configured, decrypt; otherwise pass through. This is
 * the single entry point adapters call before forwarding the body to
 * `parseLocalFeishuEvent` so the rest of the pipeline can stay
 * encryption-agnostic.
 */
export function unwrapMaybeEncryptedFeishuEvent(
  body: Record<string, unknown>,
  encryptKey?: string,
): Record<string, unknown> | undefined {
  const encrypted = typeof body.encrypt === 'string' ? body.encrypt : undefined;
  if (!encrypted) return body;
  if (!encryptKey) return undefined;
  return decryptFeishuEvent(encrypted, encryptKey);
}

// ---------------------------------------------------------------------------
// Card 2.0 form-submit decoder (split into feishu-card-form.ts)
// ---------------------------------------------------------------------------

export {
  buildReplyFromEvent,
  extractFormValue,
  extractQuestionnaireSubmitValue,
  mapFormValueToAnswers,
  normalizeSelected,
} from './feishu-card-form.js';
