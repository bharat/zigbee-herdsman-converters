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

const NS = "zhc:control4";

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
