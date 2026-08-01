/**
 * Control4 Zigbee device support: the `c4.dmx.*` text protocol.
 *
 * All newer C4 in-wall devices (C4-APD120 dimmer, C4-KD120 keypad dimmer,
 * C4-KC120277 configurable keypad) share identical endpoint structures and
 * carry LED control, button events and device identification over a
 * proprietary ASCII protocol on custom Zigbee profile 0xC25C ("MIB"):
 *
 *   Command format:  "0s<seq_hex> <command> <params>\r\n"
 *   Query format:    "0g<seq_hex> <command> <params>\r\n"
 *   Response format: "0r<seq_hex> 000 [data]\r\n"  (000 = success)
 *   Telemetry:       "0t<seq_hex> sa <command> <data>\r\n"
 *
 * Payloads are bare ASCII with no ZCL framing. Commands are sent to device
 * endpoint 1; responses and telemetry arrive from endpoint 197 (0xC5).
 * Standard Zigbee HA control (genOnOff / genLevelCtrl on endpoint 1,
 * profile 0x0104) handles on/off and dimming.
 *
 * This module is the pure protocol layer: constants, color math, frame
 * formatting, parsing and device classification. It has no zigbee-herdsman
 * dependencies beyond the logger, so it is testable in isolation.
 */

import {logger} from "./logger";
import type {KeyValue, Publish, Zh} from "./types";

const NS = "zhc:control4";

/**
 * The raw-send surface this module needs from zigbee-herdsman. Upstream
 * herdsman does not expose it yet; the bharat/zigbee-herdsman control4-prod
 * branch adds Endpoint.sendRaw with exactly this shape (also proposed
 * upstream as a generic escape hatch for non-ZCL vendor protocols).
 */
interface EndpointWithSendRaw {
    sendRaw(clusterId: number, data: Buffer, options?: {profileId?: number; timeout?: number; sendPolicy?: "immediate"}): Promise<void>;
}

// ─── Protocol Constants ──────────────────────────────────────────────

/** C4 "MIB" profile for text commands (49756) */
export const C4_MIB_PROFILE = 0xc25c;
/** Proprietary cluster carrying C4 text frames (NOT genPowerCfg, same ID) */
export const C4_CLUSTER = 1;

// ─── Button Layout ──────────────────────────────────────────────────
//
// All newer C4 devices have a 6-slot chassis. Button IDs are hex (00-05).
// APD120 dimmer uses only 01 (top rocker) and 04 (bottom rocker); KD120
// and KC120277 use all six slots.

export interface C4Button {
    idx: number;
    id: string;
}

export const BUTTONS: readonly C4Button[] = [
    {idx: 1, id: "00"},
    {idx: 2, id: "01"},
    {idx: 3, id: "02"},
    {idx: 4, id: "03"},
    {idx: 5, id: "04"},
    {idx: 6, id: "05"},
];

/** Legacy name map for the raw c4_led interface */
export const LED_IDS: Record<string, string> = {top: "01", bottom: "04"};
for (const b of BUTTONS) {
    LED_IDS[String(b.idx)] = b.id;
}

export const LED_MODES: Record<string, string> = {
    on: "03", // Color shown when the dimmer load is ON
    off: "04", // Color shown when the dimmer load is OFF
};

// ─── Local Load Paddle ──────────────────────────────────────────────
//
// Load-bearing devices (APD120 dimmers, KD keypad-dimmers) expose the two
// halves of the physical load paddle on a SEPARATE wire-id space from the
// six configurable button-array slots:
//   bp/cc/sc 00-05 = the configurable button-array slots (button_1..6)
//   bp/cc/sc 07    = top/up paddle half
//   bp/cc/sc 08    = bottom/down paddle half
// The two spaces coexist on one device. Paddle halves are surfaced as their
// own paddle_up / paddle_down actions rather than extending the button_N
// enum, which would produce out-of-enum names consumers drop.

export const PADDLE_WIRE_IDS: Record<number, string> = {
    7: "paddle_up", // wire id 0x07
    8: "paddle_down", // wire id 0x08
};

export const PADDLE_TARGETS: readonly string[] = ["paddle_up", "paddle_down"];

// The action variants shared by buttons and paddles: a bare press, a scene
// change, and click counts 1..4. Buttons and paddles use the same grammar,
// differing only in the prefix (button_N vs paddle_up / paddle_down).
function actionVariants(prefix: string): string[] {
    return [`${prefix}_press`, `${prefix}_scene`, `${prefix}_click_1`, `${prefix}_click_2`, `${prefix}_click_3`, `${prefix}_click_4`];
}

/** Action values for button and paddle events (the frozen MQTT enum contract). */
export const ACTION_VALUES: readonly string[] = [
    ...BUTTONS.flatMap((btn) => actionVariants(`button_${btn.idx}`)),
    ...PADDLE_TARGETS.flatMap(actionVariants),
];

// ─── Color Conversion Utilities ─────────────────────────────────────
//
// Colors arrive as HS (hue/saturation) or XY (CIE 1931) and must become
// 6-digit hex RGB for the C4 text protocol.
//
// C4 LEDs have a non-linear response: low channel values (like 0x18)
// produce disproportionately visible light, washing out saturated colors.
// The C4 Director only sends pure colors (channels at 0x00 or 0xFF).
// Gamma correction (γ=2.0) compresses low values, making e.g.
// HSV(241°, 92%, 100%) → 0000ff instead of 1814ff.

export const C4_LED_GAMMA = 2.0;

/** Apply gamma to a 0-1 channel value, return 0-255 integer */
export function applyGamma(value01: number): number {
    return Math.round(255 * Math.max(0, Math.min(1, value01)) ** C4_LED_GAMMA);
}

/** HSV → RGB hex. h: 0-360, s: 0-100, v: 0-1 */
export function hsvToRgbHex(h: number, s: number, v = 1): string {
    s /= 100;
    const c = v * s;
    const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
    const m = v - c;
    let rgb: [number, number, number];
    if (h < 60) rgb = [c, x, 0];
    else if (h < 120) rgb = [x, c, 0];
    else if (h < 180) rgb = [0, c, x];
    else if (h < 240) rgb = [0, x, c];
    else if (h < 300) rgb = [x, 0, c];
    else rgb = [c, 0, x];
    return rgb
        .map((ch) =>
            applyGamma(ch + m)
                .toString(16)
                .padStart(2, "0"),
        )
        .join("");
}

/** CIE 1931 XY → sRGB hex (D65 illuminant), assuming Y brightness = 1 */
export function xyToRgbHex(x: number, y: number): string {
    if (y === 0) return "000000";
    const yy = 1;
    const xx = (yy / y) * x;
    const zz = (yy / y) * (1 - x - y);
    const r = xx * 3.2406 + yy * -1.5372 + zz * -0.4986;
    const g = xx * -0.9689 + yy * 1.8758 + zz * 0.0415;
    const b = xx * 0.0557 + yy * -0.204 + zz * 1.057;
    return [r, g, b].map((ch) => applyGamma(ch).toString(16).padStart(2, "0")).join("");
}

/** RGB hex → HS (reverse conversion for state reads) */
export function rgbHexToHs(hex: string): {hue: number; saturation: number} {
    const r = Number.parseInt(hex.substring(0, 2), 16) / 255;
    const g = Number.parseInt(hex.substring(2, 4), 16) / 255;
    const b = Number.parseInt(hex.substring(4, 6), 16) / 255;
    const max = Math.max(r, g, b);
    const min = Math.min(r, g, b);
    const d = max - min;
    let h = 0;
    if (d !== 0) {
        if (max === r) h = ((g - b) / d) % 6;
        else if (max === g) h = (b - r) / d + 2;
        else h = (r - g) / d + 4;
        h = Math.round(h * 60);
        if (h < 0) h += 360;
    }
    const s = max === 0 ? 0 : Math.round((d / max) * 100);
    return {hue: h, saturation: s};
}

// ─── Sequence Counter ────────────────────────────────────────────────

let seqCounter = Math.floor(Math.random() * 0xffff);

export function nextSeq(): string {
    seqCounter = (seqCounter + 1) & 0xffff;
    return seqCounter.toString(16).padStart(4, "0");
}

/** Reset counter to a known value (for testing) */
export function resetSeqCounter(value = 0): void {
    seqCounter = value & 0xffff;
}

/** Get current counter value (for testing) */
export function getSeqCounter(): number {
    return seqCounter;
}

// ─── Protocol Text Formatting ────────────────────────────────────────

/** Format a SET command string (0s prefix) */
export function formatSetCommand(seq: string, cmdBody: string): string {
    return `0s${seq} ${cmdBody}\r\n`;
}

/** Format a GET command string (0g prefix) */
export function formatGetCommand(seq: string, cmdBody: string): string {
    return `0g${seq} ${cmdBody}\r\n`;
}

// ─── Response Parsers ───────────────────────────────────────────────

/** Parse LED color from response: "0r<seq> 000 c4.dmx.led <RRGGBB>" → hex string or null */
export function parseLedColorResponse(responseText?: string | null): string | null {
    if (!responseText) return null;
    const match = responseText.match(/000 c4\.dmx\.led (\w{6})/);
    return match ? match[1].toLowerCase() : null;
}

/** Parse dimmer type from response: "0r<seq> 000 c4.dmx.dim <XX>" → type code or null */
export function parseDimResponse(responseText?: string | null): string | null {
    if (!responseText) return null;
    const match = responseText.match(/000 c4\.dmx\.dim (\w+)/);
    return match ? match[1] : null;
}

/** Extract sequence number from a response: "0r<seq> ..." → seq string or null */
export function parseResponseSeq(text: string): string | null {
    const match = text.match(/^0r(\w{4})\s/);
    return match ? match[1] : null;
}

// ─── Button Event Parsing ───────────────────────────────────────────

const loggedUnknownWireIds = new Set<number>();

/** Reset the once-per-wire-id unknown-id log guard (for testing). */
export function resetC4ButtonLogState(): void {
    loggedUnknownWireIds.clear();
}

export interface C4ButtonTarget {
    prefix: string;
    buttonId?: number;
    paddle?: string;
}

export interface C4ButtonEvent {
    action: string;
    type: "press" | "click" | "scene";
    buttonId?: number;
    paddle?: string;
    clickCount?: number;
}

/**
 * Resolve a hex wire id from a c4.dmx.bp/cc/sc frame to an action target.
 * Pure logic (apart from a once-per-id diagnostic log).
 *
 *   0x00-0x05 → button_1..button_6 (the configurable button-array slots)
 *   0x07/0x08 → paddle_up / paddle_down (the local load paddle halves)
 *
 * Any other id (0x06, or 0x09+) is outside every known space: the historical
 * button_(N+1) mapping is kept so nothing that used to flow stops, but it is
 * logged once as an unknown wire id. Returns null only when the hex is
 * unparseable.
 */
export function resolveButtonTarget(wireIdHex: string): C4ButtonTarget | null {
    const wireId = Number.parseInt(wireIdHex, 16);
    if (Number.isNaN(wireId)) return null;

    const paddle = PADDLE_WIRE_IDS[wireId];
    if (paddle) return {prefix: paddle, paddle};

    if (wireId < 0x00 || wireId > 0x05) {
        if (!loggedUnknownWireIds.has(wireId)) {
            loggedUnknownWireIds.add(wireId);
            logger.warning(
                `[C4 BUTTON] Unknown wire id 0x${wireId.toString(16).padStart(2, "0")}: not a button slot (0x00-0x05) or paddle half (0x07/0x08)`,
                NS,
            );
        }
    }
    return {prefix: `button_${wireId + 1}`, buttonId: wireId + 1};
}

/** Attach the identity field (buttonId or paddle) for a resolved target. */
function targetIdentity(target: C4ButtonTarget): {paddle: string} | {buttonId: number | undefined} {
    return target.paddle ? {paddle: target.paddle} : {buttonId: target.buttonId};
}

export function parseButtonEvent(text: string): C4ButtonEvent | null {
    // Button press: 0t<seq> sa c4.dmx.bp <btn>
    const bpMatch = text.match(/^0t\w+ sa c4\.dmx\.bp (\w+)/);
    if (bpMatch) {
        const target = resolveButtonTarget(bpMatch[1]);
        if (!target) return null;
        return {action: `${target.prefix}_press`, ...targetIdentity(target), type: "press"};
    }

    // Click count: 0t<seq> sa c4.dmx.cc <btn> <count>
    const ccMatch = text.match(/^0t\w+ sa c4\.dmx\.cc (\w+) (\w+)/);
    if (ccMatch) {
        const target = resolveButtonTarget(ccMatch[1]);
        if (!target) return null;
        const count = Number.parseInt(ccMatch[2], 16);
        return {action: `${target.prefix}_click_${count}`, ...targetIdentity(target), clickCount: count, type: "click"};
    }

    // Scene change: 0t<seq> sa c4.dmx.sc <btn>
    const scMatch = text.match(/^0t\w+ sa c4\.dmx\.sc (\w+)/);
    if (scMatch) {
        const target = resolveButtonTarget(scMatch[1]);
        if (!target) return null;
        return {action: `${target.prefix}_scene`, ...targetIdentity(target), type: "scene"};
    }

    return null;
}

// ─── Load Status Telemetry Parsing ──────────────────────────────────
//
// Control4 devices broadcast unsolicited load-status telemetry on every
// load change, as C4 text frames on EP 197:
//
//   0t<seq> sa c4.dmx.ls 00 00 <level> 0078 0000 0000 ...
//
// The THIRD data field after "c4.dmx.ls" is the current load level as a
// hex percent (0x00..0x64). This is how a manual paddle press reports its
// new level without any ZCL reporting.

export function parseLoadStatus(text: string): {level: number} | null {
    const match = text.match(/^0t\w+ sa c4\.dmx\.ls (\w+) (\w+) (\w+)/);
    if (!match) return null;

    const level = Number.parseInt(match[3], 16);
    if (Number.isNaN(level) || level > 0x64) {
        // Out of the valid 0..100 percent range: treat as unparsed.
        logger.warning(`[C4 LS] Ignoring out-of-range load level: ${text}`, NS);
        return null;
    }

    return {level};
}

// ─── Device Type Detection Logic ─────────────────────────────────────

export type C4DeviceType = "dimmer" | "keypaddim" | "keypad";

export const DIM_TYPE_MAP: Record<string, C4DeviceType> = {
    "01": "dimmer", // C4-APD120 (forward-phase, 2 buttons)
    "02": "keypaddim", // C4-KD120  (reverse-phase, 6 buttons + load)
};

/** Determine device type from c4.dmx.dim response text. Pure logic. */
export function classifyDeviceType(dimResponseText?: string | null): C4DeviceType {
    const dimType = parseDimResponse(dimResponseText);
    if (dimType && DIM_TYPE_MAP[dimType]) {
        return DIM_TYPE_MAP[dimType];
    }
    if (dimType) {
        // Unknown dim type but has load: treat as keypaddim
        return "keypaddim";
    }
    // No response / error = no load = pure keypad
    return "keypad";
}

/**
 * True when a c4.dmx.dim response is an explicit "no load" answer rather than
 * a dim code. A true keypad ANSWERS the dim probe instead of staying silent:
 * production observed the negative "0r<seq> n01", and the generic error form
 * is "0r<seq> v<NN>" (e.g. v01). Either arrives as a real response that
 * carries no dim code, which proves the device is reachable and drives no
 * load. Pure logic.
 */
export function isC4DimNegativeResponse(rawText?: string | null): boolean {
    if (!rawText) return false;
    return /\bn01\b/.test(rawText) || /^0r\w+\s+v\d{2}\b/.test(rawText);
}

export interface C4DimProbeOutcome {
    kind: "heal" | "negative" | "silent";
    dimCode?: string;
}

/**
 * Classify a c4.dmx.dim probe outcome from its raw response text. Pure logic.
 *
 *   {kind: "heal", dimCode}  a dim code answer proves a load type
 *   {kind: "negative"}       an explicit no-load answer (n01 / v01 error form)
 *   {kind: "silent"}         no response at all (a timeout)
 *
 * The distinction matters for self-heal: a negative answer confirms a keypad
 * immediately, while silence only counts toward the silent-probe budget.
 */
export function classifyDimProbeResponse(rawText?: string | null): C4DimProbeOutcome {
    if (rawText == null) return {kind: "silent"};
    const dimCode = parseDimResponse(rawText);
    if (dimCode) return {kind: "heal", dimCode};
    if (isC4DimNegativeResponse(rawText)) return {kind: "negative"};
    return {kind: "silent"};
}

// ─── Self-Heal Confidence Model ─────────────────────────────────────
//
// A c4.dmx.dim probe that times out was historically read as "no load =
// pure keypad" and persisted forever, so a single transient Zigbee timeout
// at detection time became a permanent wrong classification. A confidence
// marker is attached to every keypad verdict:
//
//   confirmed: proven by a dim answer, or by N consecutive silent probes
//   assumed:   a single no-answer probe; may be a timeout artifact
//
// Load types (dimmer / keypaddim) are always confirmed: the device answered
// the dim query, which proves it drives a load. Only "keypad" can be
// assumed. Legacy stored keypad state that predates this marker is treated
// as assumed by construction, because production has proven such verdicts
// can be timeout artifacts.

export const C4_CONFIDENCE_CONFIRMED = "confirmed";
export const C4_CONFIDENCE_ASSUMED = "assumed";

/** Consecutive silent dim probes required to upgrade an assumed keypad to confirmed (and stop probing it). */
export const C4_MAX_SILENT_PROBES = 3;

/**
 * The persisted per-device meta keys (a frozen contract: existing production
 * devices carry these exact snake_case keys in device.meta):
 * c4_device_type, c4_type_confidence, c4_dim_code, c4_silent_probes.
 */
export type C4Meta = Record<string, unknown>;

/**
 * Derive the effective confidence of a device's current classification from
 * its herdsman meta. Backward compatible: any keypad verdict without an
 * explicit "confirmed" marker (including legacy stored state) is assumed.
 */
export function effectiveConfidence(meta?: C4Meta): string {
    if (meta && meta.c4_type_confidence === C4_CONFIDENCE_CONFIRMED) {
        return C4_CONFIDENCE_CONFIRMED;
    }
    return C4_CONFIDENCE_ASSUMED;
}

export interface C4HealEvidence {
    dimCode?: string | null;
    ls?: boolean;
    paddle?: boolean;
}

/**
 * Given the current classification and a piece of load evidence, decide the
 * corrected device type, or null if no correction is warranted. Pure logic.
 *
 *   dim answer is authoritative: 01 → dimmer, any other code → keypaddim.
 *   ls telemetry: only proves the device drives a load, not which kind, so
 *                  it upgrades an (assumed) keypad or unclassified device to
 *                  keypaddim as the safe default, but never downgrades an
 *                  existing dimmer / keypaddim.
 *   paddle telemetry: a local load paddle half (bp 07/08) only exists on a
 *                  load-bearing device, so it is load proof identical to ls:
 *                  upgrades an assumed keypad / unclassified device to
 *                  keypaddim, never downgrades.
 */
export function healTypeFromEvidence(currentType: string | undefined | null, evidence: C4HealEvidence): C4DeviceType | null {
    if (evidence && evidence.dimCode != null) {
        const healed = DIM_TYPE_MAP[evidence.dimCode] ?? "keypaddim";
        return healed !== currentType ? healed : null;
    }
    if (evidence && (evidence.ls || evidence.paddle)) {
        if (currentType === "keypad" || currentType == null) return "keypaddim";
        return null;
    }
    return null;
}

/** Get button list for a device type */
export function getButtonsForDeviceType(deviceType?: string | null): readonly C4Button[] {
    if (deviceType === "dimmer") {
        return BUTTONS.filter((b) => b.idx === 2 || b.idx === 5);
    }
    return BUTTONS; // keypaddim and keypad use all 6 slots
}

/** Build state object from a read LED color (flat hex attribute) */
export function buildLedColorState(buttonIdx: number, suffix: string, hexColor: string): Record<string, string> {
    return {[`c4_led_${buttonIdx}_${suffix}`]: hexColor};
}

// ─── Color Hex Validation ────────────────────────────────────────────

export function isValidColorHex(str: string): boolean {
    return /^[0-9a-f]{6}$/.test(str);
}

export function normalizeColorHex(str: string): string {
    return str.replace("#", "").toLowerCase();
}

// ─── Model Metadata ──────────────────────────────────────────────────

export const MODEL_NAMES: Record<string, string> = {
    dimmer: "C4-APD120",
    keypaddim: "C4-KD120",
    keypad: "C4-KC120277",
};

export const MODEL_DESCRIPTIONS: Record<string, string> = {
    dimmer: "Control4 Adaptive Phase Dimmer",
    keypaddim: "Control4 Keypad Dimmer",
    keypad: "Control4 Configurable Keypad",
};

export const GENBASIC_ATTRS: readonly string[] = [
    "zclVersion", // 0x0000
    "applicationVersion", // 0x0001
    "stackVersion", // 0x0002
    "hwVersion", // 0x0003
    "manufacturerName", // 0x0004
    "modelId", // 0x0005
    "dateCode", // 0x0006
    "powerSource", // 0x0007
    "swBuildId", // 0x4000
];

// ═══════════════════════════════════════════════════════════════════════
// I/O layer (depends on zigbee-herdsman via Zh types + sendRaw)
// ═══════════════════════════════════════════════════════════════════════

// ─── Core: Send C4 Text Command ─────────────────────────────────────
//
// The C4 text protocol sends raw ASCII as the APS payload with NO ZCL
// framing, via Endpoint.sendRaw. Two verbs: 0s = SET (write), 0g = GET
// (query). Both follow the same transport framing; only the verb prefix
// differs.

export async function sendC4Raw(device: Zh.Device, text: string): Promise<string> {
    const ep = device.getEndpoint(1);
    if (!ep) throw new Error("Endpoint 1 not found on device");

    await (ep as unknown as EndpointWithSendRaw).sendRaw(C4_CLUSTER, Buffer.from(text, "ascii"), {
        profileId: C4_MIB_PROFILE,
        timeout: 10000,
        sendPolicy: "immediate",
    });
    return text.trim();
}

export async function sendC4(device: Zh.Device, cmdBody: string): Promise<string> {
    const seq = nextSeq();
    return await sendC4Raw(device, formatSetCommand(seq, cmdBody));
}

export async function queryC4(device: Zh.Device, cmdBody: string): Promise<string> {
    const seq = nextSeq();
    return await sendC4Raw(device, formatGetCommand(seq, cmdBody));
}

// ─── Response Queue for Synchronous Query/Response ──────────────────
//
// The C4 text protocol is asynchronous: queries are sent to EP 1 and
// responses arrive from EP 197. This response queue enables awaitable
// query/response patterns used during device detection and LED reading.
//
// 1. queryC4WithResponse() registers a Promise resolver keyed by seq
// 2. The query is sent to the device
// 3. The raw fromZigbee handler receives the response and checks here
// 4. If the seq matches, the Promise is resolved with the response text
// 5. If the timeout expires, the Promise resolves with null

const pendingQueries = new Map<string, (responseText: string) => void>();

/** Resolve a pending query by response sequence. Returns true when a waiter existed. */
export function resolveC4PendingQuery(seq: string, responseText: string): boolean {
    const handler = pendingQueries.get(seq);
    if (!handler) return false;
    handler(responseText);
    return true;
}

export async function queryC4WithResponse(device: Zh.Device, cmdBody: string, timeoutMs = 3000): Promise<string | null> {
    const seq = nextSeq();

    return await new Promise((resolve) => {
        const timer = setTimeout(() => {
            pendingQueries.delete(seq);
            logger.warning(`[C4 Q/R] Timeout for seq ${seq}: ${cmdBody}`, NS);
            resolve(null);
        }, timeoutMs);

        pendingQueries.set(seq, (responseText) => {
            clearTimeout(timer);
            pendingQueries.delete(seq);
            resolve(responseText);
        });

        sendC4Raw(device, formatGetCommand(seq, cmdBody)).catch((err) => {
            clearTimeout(timer);
            pendingQueries.delete(seq);
            logger.warning(`[C4 Q/R] Send failed for seq ${seq}: ${(err as Error).message}`, NS);
            resolve(null);
        });
    });
}

// ─── Device Type Detection ──────────────────────────────────────────
//
// A SINGLE C4 query identifies all three device types:
//   c4.dmx.dim response:
//     "01" → APD120 (forward-phase dimmer, 2-button rocker)
//     "02" → KD120  (reverse-phase keypad dimmer, 6 buttons + load)
//     error/n01 → KC120277 (configurable keypad, 6 buttons, no load)
//
// NOTE: probing c4.dmx.led 02 03 (button 02 existence) does NOT work: all
// C4 devices respond to LED queries for all 6 slots, including the
// 2-button APD120 (unused slots read 000000).

export interface C4Detection {
    deviceType: C4DeviceType;
    dimCode: string | null;
    confidence: string;
}

export async function detectDeviceType(device: Zh.Device): Promise<C4Detection> {
    logger.info(`[C4 DETECT] Probing device ${device.ieeeAddr}...`, NS);

    const dimResp = await queryC4WithResponse(device, "c4.dmx.dim", 3000);
    logger.info(`[C4 DETECT] c4.dmx.dim response: ${dimResp || "(timeout)"}`, NS);

    const dimCode = parseDimResponse(dimResp);
    const deviceType = classifyDeviceType(dimResp);

    // A dim answer proves the load type (confirmed). A no-answer keypad
    // verdict is low confidence by construction: it may be a transient
    // Zigbee timeout rather than a true keypad, so the self-heal machinery
    // is allowed to revisit it later.
    const confidence = dimCode ? C4_CONFIDENCE_CONFIRMED : C4_CONFIDENCE_ASSUMED;
    logger.info(`[C4 DETECT] Device type: ${deviceType} (confidence: ${confidence})`, NS);
    return {deviceType, dimCode, confidence};
}

// ─── Read Stored LED Colors ─────────────────────────────────────────
//
// C4 devices store LED colors in firmware (persisted across power cycles
// and network migrations). This reads all stored colors for the device's
// button set and returns them as a state update object.

export async function readStoredColors(device: Zh.Device, deviceType?: string | null): Promise<KeyValue> {
    const buttons = getButtonsForDeviceType(deviceType);

    const state: KeyValue = {};
    for (const btn of buttons) {
        for (const [mode, suffix] of [
            ["03", "on"],
            ["04", "off"],
        ]) {
            const resp = await queryC4WithResponse(device, `c4.dmx.led ${btn.id} ${mode}`, 2000);
            const hex = parseLedColorResponse(resp);
            if (hex) {
                Object.assign(state, buildLedColorState(btn.idx, suffix, hex));
                logger.debug(`[C4 DETECT] LED ${btn.id} mode ${mode}: #${hex}`, NS);
            } else {
                logger.debug(`[C4 DETECT] LED ${btn.id} mode ${mode}: no response`, NS);
            }
        }
    }
    return state;
}

// ─── Debounced Load State Read (manual paddle sync) ─────────────────
//
// Control4 devices do NOT support ZCL attribute reporting (the load light
// is registered with configureReporting: false), so a manual paddle press
// at the wall never pushes a state update on its own. C4 devices DO answer
// ZCL reads, and button presses arrive as C4 text telemetry, so every
// button event schedules a read of the load state (genOnOff.onOff +
// genLevelCtrl.currentLevel on EP1). The standard light() fromZigbee
// handlers pick those read responses up and update state/brightness.
//
// The read is debounced per device: a dimmer paddle hold emits a burst of
// events, so the read fires once the device has been quiet for the
// debounce window, letting the load settle and coalescing the burst.

export const C4_STATE_READ_DEBOUNCE_MS = 750;

const c4StateReadTimers = new Map<string, ReturnType<typeof setTimeout>>();

// ─── Throttled Load State Publish (unsolicited ls telemetry) ─────────
//
// The primary manual-sync path: Control4 devices push their new load
// level as c4.dmx.ls telemetry on every load change, so no ZCL read is
// needed in the common case.
//
// This is a THROTTLE, not a coalesce-to-one. Each ls frame stores the
// latest level and resets a per-device trailing-edge timer; a publish
// happens once the device has been quiet for C4_LOAD_STATE_DEBOUNCE_MS.
// The contract: at most one publish per 500 ms quiet window, and the
// final settled level is ALWAYS published.
//
// Publishing uses the standard light() fields (state + brightness). At
// level 0 only {state: "OFF"} is published, with NO brightness key: the
// device resumes at its previous level via on_level, so wiping the
// last-on brightness would only degrade the slider.

export const C4_LOAD_STATE_DEBOUNCE_MS = 500;

interface C4LoadStateEntry {
    level: number;
    timer: ReturnType<typeof setTimeout> | null;
}

const c4LoadStateTimers = new Map<string, C4LoadStateEntry>();

// Per-device timestamp (ms) of the most recent ls frame seen. Used to
// demote the ZCL read to a fallback: if ls telemetry already arrived,
// the scheduled read is redundant and gets skipped.
const c4LastLsSeen = new Map<string, number>();

/**
 * Schedule a trailing-edge debounced publish of load state for a device.
 * Each ls frame stores the latest level and resets the per-device timer;
 * once the device goes quiet for C4_LOAD_STATE_DEBOUNCE_MS, the latest
 * level for that window is published. Also records the ls-seen timestamp
 * so scheduleC4StateRead can skip its fallback read.
 */
export function scheduleC4LoadStatePublish(device: Zh.Device | undefined, level: number, publish: Publish): void {
    if (!device) return;

    const key = device.ieeeAddr;
    c4LastLsSeen.set(key, Date.now());

    const existing = c4LoadStateTimers.get(key);
    if (existing?.timer) clearTimeout(existing.timer);

    const entry: C4LoadStateEntry = {level, timer: null};
    entry.timer = setTimeout(() => {
        c4LoadStateTimers.delete(key);
        const lvl = entry.level;
        publish(lvl > 0 ? {state: "ON", brightness: Math.round((lvl * 255) / 100)} : {state: "OFF"});
    }, C4_LOAD_STATE_DEBOUNCE_MS);

    c4LoadStateTimers.set(key, entry);
}

/**
 * Schedule a debounced read of the load on/off + level state for a device.
 * Each call resets the per-device timer; the read fires once the device
 * has been quiet for C4_STATE_READ_DEBOUNCE_MS. Pure keypads have no load,
 * so they are skipped. Read failures are logged and swallowed.
 *
 * This is a FALLBACK behind the ls-telemetry path: if an ls frame arrived
 * after the read was scheduled, the debounced load-state publish already
 * refreshed the state, so the read is skipped.
 */
export function scheduleC4StateRead(device: Zh.Device | undefined, deviceType?: string | null): void {
    if (!device) return;

    // Pure keypads drive no load, so there is nothing to read. When the
    // device type is unknown the read is attempted anyway (guarded below).
    if (deviceType === "keypad") return;

    const key = device.ieeeAddr;
    const scheduledAt = Date.now();
    const existing = c4StateReadTimers.get(key);
    if (existing) clearTimeout(existing);

    const timer = setTimeout(async () => {
        c4StateReadTimers.delete(key);

        // Fallback demotion: if an ls frame arrived after this read was
        // scheduled, the debounced load-state publish already updated state.
        const lastLs = c4LastLsSeen.get(key);
        if (lastLs !== undefined && lastLs > scheduledAt) {
            logger.debug(`[C4 STATE] Skipping ZCL read for ${key}; ls telemetry already refreshed state`, NS);
            return;
        }

        let ep1: Zh.Endpoint | undefined;
        try {
            ep1 = device.getEndpoint(1);
        } catch (err) {
            logger.debug(`[C4 STATE] getEndpoint(1) failed: ${(err as Error).message}`, NS);
            return;
        }
        if (!ep1) return;

        try {
            await ep1.read("genOnOff", ["onOff"]);
        } catch (err) {
            logger.debug(`[C4 STATE] genOnOff read failed: ${(err as Error).message}`, NS);
        }
        try {
            await ep1.read("genLevelCtrl", ["currentLevel"]);
        } catch (err) {
            logger.debug(`[C4 STATE] genLevelCtrl read failed: ${(err as Error).message}`, NS);
        }
    }, C4_STATE_READ_DEBOUNCE_MS);

    c4StateReadTimers.set(key, timer);
}

// ─── Self-Heal: Reclassification + Active Probe Campaign ─────────────
//
// Two mechanisms correct a device mis-classified as keypad by a silent
// dim-probe timeout, without ever requiring a manual c4_detect:
//
//   PASSIVE: any load evidence that arrives on its own (an ls broadcast or
//   a c4.dmx.dim answer) proves the device drives a load, so it is
//   reclassified immediately via applyC4Heal.
//
//   ACTIVE: for a keypad that is still only "assumed", the dim probe is
//   re-run a few times (jittered start, exponential backoff) until either
//   it answers (heal) or it stays silent C4_MAX_SILENT_PROBES times in a
//   row (upgrade to a confirmed keypad and stop). Confirmed keypads are
//   never probed again, and the confirmed marker is persisted so a restart
//   does not restart the campaign from zero.

/** Jitter window for the first probe, spreading radio traffic so a fleet does not all probe at once on startup. */
export const C4_PROBE_INITIAL_MAX_MS = 60000;

/** Base gap between silent probes; doubled after each additional silence. */
export const C4_PROBE_BACKOFF_MS = 30000;

interface C4ProbeCampaign {
    silentCount: number;
    timer: ReturnType<typeof setTimeout> | null;
}

const c4ProbeCampaigns = new Map<string, C4ProbeCampaign>();

interface C4MetaFields {
    type?: string;
    confidence?: string;
    dimCode?: string | null;
    silentProbes?: number;
}

/** Persist self-heal fields onto device.meta and flush via device.save(). */
function persistC4Meta(device: Zh.Device, fields: C4MetaFields): void {
    if (fields.type !== undefined) device.meta.c4_device_type = fields.type;
    if (fields.confidence !== undefined) device.meta.c4_type_confidence = fields.confidence;
    if (fields.dimCode !== undefined) device.meta.c4_dim_code = fields.dimCode;
    if (fields.silentProbes !== undefined) device.meta.c4_silent_probes = fields.silentProbes;
    if (typeof device.save === "function") device.save();
}

/** Tear down any in-flight probe campaign for a device. */
function stopC4ProbeCampaign(device: Zh.Device): void {
    const campaign = c4ProbeCampaigns.get(device.ieeeAddr);
    if (campaign?.timer) clearTimeout(campaign.timer);
    c4ProbeCampaigns.delete(device.ieeeAddr);
}

/** Reset all in-memory self-heal campaign state (for testing). */
export function resetC4HealState(): void {
    for (const campaign of c4ProbeCampaigns.values()) {
        if (campaign.timer) clearTimeout(campaign.timer);
    }
    c4ProbeCampaigns.clear();
}

/**
 * Reclassify a device from load evidence and persist the correction.
 * Returns the state fragment to publish (containing the frozen-contract
 * c4_device_type plus an extended c4_detect_result), or null when no
 * correction is warranted. Idempotent: once a device is confirmed at the
 * target type, repeat evidence is a no-op so the probe path and the
 * response path can both observe the same answer without double
 * publishing.
 */
export function applyC4Heal(
    device: Zh.Device | undefined,
    currentType: string | undefined | null,
    evidence: C4HealEvidence,
    publish?: Publish,
): KeyValue | null {
    if (!device) return null;

    const newType = healTypeFromEvidence(currentType, evidence);
    if (!newType) return null;

    const already = device.meta.c4_device_type === newType && device.meta.c4_type_confidence === C4_CONFIDENCE_CONFIRMED;
    if (already) return null;

    const dimCode = evidence.dimCode != null ? evidence.dimCode : ((device.meta.c4_dim_code as string | null) ?? null);
    let evidenceDesc: string;
    if (evidence.dimCode != null) {
        evidenceDesc = `c4.dmx.dim answer ${evidence.dimCode}`;
    } else if (evidence.paddle) {
        evidenceDesc = "c4.dmx.bp local load paddle telemetry";
    } else {
        evidenceDesc = "c4.dmx.ls load telemetry";
    }

    logger.info(`[C4 HEAL] ${device.ieeeAddr}: ${currentType ?? "(none)"} -> ${newType} (evidence: ${evidenceDesc})`, NS);

    // Reclassification changes c4_device_type at runtime, mirroring the
    // c4_detect flow exactly: update device.meta + device.save() and publish
    // the new c4_device_type.
    persistC4Meta(device, {type: newType, confidence: C4_CONFIDENCE_CONFIRMED, dimCode});

    // Load is proven, so any active probe campaign is done.
    stopC4ProbeCampaign(device);

    const state: KeyValue = {
        c4_device_type: newType,
        c4_detect_result: {
            ieee_address: device.ieeeAddr,
            device_type: newType,
            confidence: C4_CONFIDENCE_CONFIRMED,
            dim_code: dimCode,
            model: MODEL_NAMES[newType] ?? "unknown",
            description: MODEL_DESCRIPTIONS[newType] ?? "Unknown Control4 device",
            healed: true,
            evidence: evidenceDesc,
        },
    };

    if (publish) publish(state);
    return state;
}

/**
 * Upgrade an assumed keypad to a confirmed keypad. Called both after
 * enough silence and immediately on an explicit negative dim answer; the
 * evidence/logReason override lets each path record its own proof.
 */
function markConfirmedC4Keypad(device: Zh.Device, publish?: Publish, opts: {evidence?: string; logReason?: string} = {}): void {
    const evidence = opts.evidence ?? `${C4_MAX_SILENT_PROBES} consecutive silent c4.dmx.dim probes`;
    const logReason = opts.logReason ?? `keypad confirmed after ${C4_MAX_SILENT_PROBES} silent c4.dmx.dim probes`;

    persistC4Meta(device, {confidence: C4_CONFIDENCE_CONFIRMED});
    logger.info(`[C4 HEAL] ${device.ieeeAddr}: ${logReason}`, NS);

    if (publish) {
        publish({
            c4_detect_result: {
                ieee_address: device.ieeeAddr,
                device_type: "keypad",
                confidence: C4_CONFIDENCE_CONFIRMED,
                dim_code: null,
                model: MODEL_NAMES.keypad,
                description: MODEL_DESCRIPTIONS.keypad,
                healed: false,
                evidence,
            },
        });
    }
}

/**
 * Normalize a probeFn return value into a {kind, dimCode?} outcome. The
 * default probeFn returns a classifyDimProbeResponse object, but the
 * legacy test seam contract is a bare dim code string (heal) or null
 * (silent), so both shapes are accepted.
 */
function normalizeProbeOutcome(result: C4DimProbeOutcome | string | null | undefined): C4DimProbeOutcome {
    if (result == null) return {kind: "silent"};
    if (typeof result === "object") return result;
    return {kind: "heal", dimCode: result};
}

export interface C4ProbeCampaignOpts {
    probeFn?: (device: Zh.Device) => Promise<C4DimProbeOutcome | string | null>;
    random?: () => number;
    initialMaxMs?: number;
    backoffMs?: number;
    publish?: Publish;
}

/**
 * Start (once per process) an active dim-probe campaign for an assumed
 * keypad. No-op for non-keypads and for already-confirmed keypads. The
 * first probe is jittered across C4_PROBE_INITIAL_MAX_MS; subsequent
 * silent probes back off exponentially. A dim answer heals via the
 * response path; C4_MAX_SILENT_PROBES silences confirm the keypad and
 * stop the campaign.
 */
export function scheduleC4ProbeCampaign(
    device: Zh.Device | undefined,
    deviceType: string | undefined | null,
    publish?: Publish,
    opts: C4ProbeCampaignOpts = {},
): void {
    if (!device) return;
    if (deviceType !== "keypad") return; // never probe a load-bearing device
    if (effectiveConfidence(device.meta) === C4_CONFIDENCE_CONFIRMED) return; // never re-probe a confirmed keypad
    if (c4ProbeCampaigns.has(device.ieeeAddr)) return; // one campaign per process lifetime

    const probeFn = opts.probeFn ?? (async (dev: Zh.Device) => classifyDimProbeResponse(await queryC4WithResponse(dev, "c4.dmx.dim", 3000)));
    const random = opts.random ?? Math.random;
    const initialMaxMs = opts.initialMaxMs ?? C4_PROBE_INITIAL_MAX_MS;
    const backoffMs = opts.backoffMs ?? C4_PROBE_BACKOFF_MS;

    const campaign: C4ProbeCampaign = {silentCount: (device.meta.c4_silent_probes as number | undefined) ?? 0, timer: null};
    c4ProbeCampaigns.set(device.ieeeAddr, campaign);

    const runProbe = async (): Promise<void> => {
        campaign.timer = null;

        let outcome: C4DimProbeOutcome;
        try {
            outcome = normalizeProbeOutcome(await probeFn(device));
        } catch (err) {
            logger.warning(`[C4 HEAL] Probe failed for ${device.ieeeAddr}: ${(err as Error).message}`, NS);
            outcome = {kind: "silent"};
        }

        if (outcome.kind === "heal") {
            // The dim response also flows through the raw fromZigbee handler,
            // which heals and publishes; applyC4Heal here is idempotent
            // (no-op if already healed) so the injected-probe path still heals.
            applyC4Heal(device, deviceType, {dimCode: outcome.dimCode}, publish);
            c4ProbeCampaigns.delete(device.ieeeAddr);
            return;
        }

        if (outcome.kind === "negative") {
            // A true keypad answers the dim probe with an explicit no-load
            // response rather than timing out. That is proof, not silence, so
            // confirm immediately instead of burning the silent-probe budget
            // and its exponential backoff.
            markConfirmedC4Keypad(device, publish, {
                logReason: "keypad confirmed by explicit n01 answer",
                evidence: "explicit n01 answer",
            });
            c4ProbeCampaigns.delete(device.ieeeAddr);
            return;
        }

        campaign.silentCount += 1;
        persistC4Meta(device, {silentProbes: campaign.silentCount});

        if (campaign.silentCount >= C4_MAX_SILENT_PROBES) {
            markConfirmedC4Keypad(device, publish);
            c4ProbeCampaigns.delete(device.ieeeAddr);
            return;
        }

        campaign.timer = setTimeout(runProbe, backoffMs * 2 ** (campaign.silentCount - 1));
    };

    campaign.timer = setTimeout(runProbe, Math.floor(random() * initialMaxMs));
}

// ─── Startup Arming of the Probe Campaign ───────────────────────────
//
// scheduleC4ProbeCampaign was originally only kicked off from the raw
// fromZigbee handler, so a device had to emit C4 text traffic before its
// campaign armed. Quiet keypads never did, so in production 6 of 8
// devices sat unprobed. Every assumed-keypad device is now armed at
// startup via the definition's onEvent "start" hook. A device whose
// stored classification is a load type (dimmer / keypaddim) or a
// confirmed keypad is skipped by scheduleC4ProbeCampaign; an absent
// classification is treated as an assumed keypad so a never-detected
// device still gets probed. The per-device jitter inside the campaign
// keeps a fleet from probing at once, and the fz-side arming stays as an
// idempotent supplement.

/**
 * Arm the self-heal probe campaign for assumed-keypad (or unclassified)
 * devices when the bridge starts. Called from the definition's onEvent
 * handler with the event's device and state; the opts parameter is a test
 * seam forwarded to scheduleC4ProbeCampaign.
 */
export function c4ArmProbeOnStart(device: Zh.Device | undefined, state: KeyValue | undefined, opts: C4ProbeCampaignOpts = {}): void {
    if (!device) return;

    const currentType = (state?.c4_device_type as string | undefined) ?? (device.meta.c4_device_type as string | undefined) ?? "keypad";
    scheduleC4ProbeCampaign(device, currentType, opts.publish, opts);
}

/**
 * Short device identity for log attribution: the ieeeAddr, plus the
 * friendly name when the device object carries one cheaply.
 */
export function c4DeviceLabel(device: Zh.Device | undefined): string {
    if (!device) return "?";
    const ieee = device.ieeeAddr ?? "?";
    const name = (device.meta.friendlyName as string | undefined) ?? undefined;
    return name ? `${ieee} (${name})` : ieee;
}
