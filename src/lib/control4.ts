/**
 * Control4 in-wall Zigbee devices (C4-APD120 dimmer, C4-KD120 keypad dimmer,
 * C4-KC120277 configurable keypad) carry LED control, button events and
 * device identification over a proprietary ASCII protocol on custom Zigbee
 * profile 0xC25C ("MIB"):
 *
 *   Command:   "0s<seq_hex> <command> <params>\r\n"
 *   Query:     "0g<seq_hex> <command> <params>\r\n"
 *   Response:  "0r<seq_hex> 000 [data]\r\n"  (000 = success)
 *   Telemetry: "0t<seq_hex> sa <command> <data>\r\n"
 *
 * Commands go to device endpoint 1; responses and telemetry arrive from
 * endpoint 197 (0xC5). Standard on/off and dimming use genOnOff /
 * genLevelCtrl on endpoint 1 (profile 0x0104).
 */

import {logger} from "./logger";
import type {KeyValue, Publish, Zh} from "./types";

const NS = "zhc:control4";

// Raw-APS send surface required from zigbee-herdsman (not yet in upstream
// releases); C4 payloads are bare ASCII with no ZCL framing.
interface EndpointWithSendRaw {
    sendRaw(clusterId: number, data: Buffer, options?: {profileId?: number; timeout?: number; sendPolicy?: "immediate"}): Promise<void>;
}

/** C4 "MIB" profile for text commands (49756) */
export const C4_MIB_PROFILE = 0xc25c;
/** Proprietary cluster carrying C4 text frames (NOT genPowerCfg, same ID) */
export const C4_CLUSTER = 1;

// All newer C4 devices have a 6-slot chassis with hex button ids 00-05;
// the APD120 dimmer uses only 01 (top rocker) and 04 (bottom rocker).

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

// Load-bearing devices expose the physical paddle halves on wire ids
// 0x07/0x08, a separate id space from the six button-array slots (00-05);
// they surface as paddle_up / paddle_down actions rather than button_N.
export const PADDLE_WIRE_IDS: Record<number, string> = {
    7: "paddle_up",
    8: "paddle_down",
};

export const PADDLE_TARGETS: readonly string[] = ["paddle_up", "paddle_down"];

function actionVariants(prefix: string): string[] {
    return [`${prefix}_press`, `${prefix}_scene`, `${prefix}_click_1`, `${prefix}_click_2`, `${prefix}_click_3`, `${prefix}_click_4`];
}

/** Action values for button and paddle events (the frozen MQTT enum contract). */
export const ACTION_VALUES: readonly string[] = [
    ...BUTTONS.flatMap((btn) => actionVariants(`button_${btn.idx}`)),
    ...PADDLE_TARGETS.flatMap(actionVariants),
];

// C4 LEDs respond non-linearly (low channel values wash out saturated
// colors) and only ever show pure colors; gamma 2.0 compresses low values,
// e.g. HSV(241°, 92%, 100%) → 0000ff instead of 1814ff.
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

export function formatSetCommand(seq: string, cmdBody: string): string {
    return `0s${seq} ${cmdBody}\r\n`;
}

export function formatGetCommand(seq: string, cmdBody: string): string {
    return `0g${seq} ${cmdBody}\r\n`;
}

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

export function parseResponseSeq(text: string): string | null {
    const match = text.match(/^0r(\w{4})\s/);
    return match ? match[1] : null;
}

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
 * Map a bp/cc/sc wire id: 0x00-0x05 → button_1..6, 0x07/0x08 → paddle halves.
 * Other ids keep the legacy button_(N+1) mapping but are logged once.
 */
export function resolveButtonTarget(wireIdHex: string): C4ButtonTarget | null {
    const wireId = Number.parseInt(wireIdHex, 16);
    if (Number.isNaN(wireId)) return null;

    const paddle = PADDLE_WIRE_IDS[wireId];
    if (paddle) return {prefix: paddle, paddle};

    if (wireId < 0x00 || wireId > 0x05) {
        if (!loggedUnknownWireIds.has(wireId)) {
            loggedUnknownWireIds.add(wireId);
            logger.warning(`Unknown wire id 0x${wireId.toString(16).padStart(2, "0")}: not a button slot (0x00-0x05) or paddle half (0x07/0x08)`, NS);
        }
    }
    return {prefix: `button_${wireId + 1}`, buttonId: wireId + 1};
}

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

/** Parse ls telemetry ("0t<seq> sa c4.dmx.ls ..."): the third data field is the load level as a hex percent (0x00-0x64). */
export function parseLoadStatus(text: string): {level: number} | null {
    const match = text.match(/^0t\w+ sa c4\.dmx\.ls (\w+) (\w+) (\w+)/);
    if (!match) return null;

    const level = Number.parseInt(match[3], 16);
    if (Number.isNaN(level) || level > 0x64) {
        logger.warning(`Ignoring out-of-range load level: ${text}`, NS);
        return null;
    }

    return {level};
}

export type C4DeviceType = "dimmer" | "keypaddim" | "keypad";

export const DIM_TYPE_MAP: Record<string, C4DeviceType> = {
    "01": "dimmer", // C4-APD120 (forward-phase, 2 buttons)
    "02": "keypaddim", // C4-KD120  (reverse-phase, 6 buttons + load)
};

/** Determine device type from c4.dmx.dim response text: any dim code means a load, no response means keypad. */
export function classifyDeviceType(dimResponseText?: string | null): C4DeviceType {
    const dimType = parseDimResponse(dimResponseText);
    if (dimType && DIM_TYPE_MAP[dimType]) {
        return DIM_TYPE_MAP[dimType];
    }
    if (dimType) {
        return "keypaddim";
    }
    return "keypad";
}

/**
 * True for an explicit "no load" answer to the dim probe ("n01", or the
 * generic error form "v<NN>"): the device is reachable but drives no load.
 */
export function isC4DimNegativeResponse(rawText?: string | null): boolean {
    if (!rawText) return false;
    return /\bn01\b/.test(rawText) || /^0r\w+\s+v\d{2}\b/.test(rawText);
}

export interface C4DimProbeOutcome {
    kind: "heal" | "negative" | "silent";
    dimCode?: string;
}

/** "heal" = a dim code answer (proves a load type), "negative" = explicit no-load answer, "silent" = timeout. */
export function classifyDimProbeResponse(rawText?: string | null): C4DimProbeOutcome {
    if (rawText == null) return {kind: "silent"};
    const dimCode = parseDimResponse(rawText);
    if (dimCode) return {kind: "heal", dimCode};
    if (isC4DimNegativeResponse(rawText)) return {kind: "negative"};
    return {kind: "silent"};
}

// A dim answer proves a load type, but silence may just be a transient
// timeout, so only keypad verdicts carry an assumed/confirmed marker.

export const C4_CONFIDENCE_CONFIRMED = "confirmed";
export const C4_CONFIDENCE_ASSUMED = "assumed";

/** Consecutive silent dim probes required to upgrade an assumed keypad to confirmed (and stop probing it). */
export const C4_MAX_SILENT_PROBES = 3;

/** Persisted device.meta keys (frozen contract): c4_device_type, c4_type_confidence, c4_dim_code, c4_silent_probes. */
export type C4Meta = Record<string, unknown>;

/** Any keypad verdict without an explicit "confirmed" marker (including legacy state) is assumed. */
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
 * A dim answer is authoritative; ls or paddle telemetry only proves a load
 * exists, so it upgrades a keypad to keypaddim but never downgrades a load type.
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

export function getButtonsForDeviceType(deviceType?: string | null): readonly C4Button[] {
    if (deviceType === "dimmer") {
        return BUTTONS.filter((b) => b.idx === 2 || b.idx === 5);
    }
    return BUTTONS; // keypaddim and keypad use all 6 slots
}

export function buildLedColorState(buttonIdx: number, suffix: string, hexColor: string): Record<string, string> {
    return {[`c4_led_${buttonIdx}_${suffix}`]: hexColor};
}

export function isValidColorHex(str: string): boolean {
    return /^[0-9a-f]{6}$/.test(str);
}

export function normalizeColorHex(str: string): string {
    return str.replace("#", "").toLowerCase();
}

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
    "zclVersion",
    "applicationVersion",
    "stackVersion",
    "hwVersion",
    "manufacturerName",
    "modelId",
    "dateCode",
    "powerSource",
    "swBuildId",
];

// Everything below performs I/O against the device via Endpoint.sendRaw.

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

// Queries go out on EP 1 but responses arrive from EP 197, so awaitable
// queries register a resolver keyed by seq; the raw fromZigbee handler
// resolves it when the matching response arrives.
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
            logger.warning(`Timeout for seq ${seq}: ${cmdBody}`, NS);
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
            logger.warning(`Send failed for seq ${seq}: ${(err as Error).message}`, NS);
            resolve(null);
        });
    });
}

export interface C4Detection {
    deviceType: C4DeviceType;
    dimCode: string | null;
    confidence: string;
}

/** Identify the device type with a single c4.dmx.dim query: "01" → dimmer, "02" → keypaddim, error/no answer → keypad. */
export async function detectDeviceType(device: Zh.Device): Promise<C4Detection> {
    logger.info(`Probing device ${device.ieeeAddr}...`, NS);

    const dimResp = await queryC4WithResponse(device, "c4.dmx.dim", 3000);
    logger.info(`c4.dmx.dim response: ${dimResp || "(timeout)"}`, NS);

    const dimCode = parseDimResponse(dimResp);
    const deviceType = classifyDeviceType(dimResp);

    // A dim answer proves the load type; a no-answer keypad verdict may be a
    // transient timeout, so it stays low-confidence for later self-heal.
    const confidence = dimCode ? C4_CONFIDENCE_CONFIRMED : C4_CONFIDENCE_ASSUMED;
    logger.info(`Device type: ${deviceType} (confidence: ${confidence})`, NS);
    return {deviceType, dimCode, confidence};
}

/** Read all LED colors stored in device firmware (persisted across power cycles) as a state update. */
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
                logger.debug(`LED ${btn.id} mode ${mode}: #${hex}`, NS);
            } else {
                logger.debug(`LED ${btn.id} mode ${mode}: no response`, NS);
            }
        }
    }
    return state;
}

// Reverse maps for read-back verification (issue #145): firmware value →
// the name the control4_dimmers integration publishes and compares. Each
// table must EXACTLY invert the integration's _BEHAVIOR_TO_FIRMWARE /
// _LED_MODE_TO_FIRMWARE; a wrong entry makes verify report a false mismatch
// on a correctly-configured device. Values are hardware-confirmed (#145).

/** Firmware button behavior (read via "c4.dmx.btn NN 01") → integration behavior name. */
export const BEHAVIOR_FROM_FIRMWARE: Record<string, string> = {
    "00": "load_on",
    "01": "load_off",
    "02": "toggle_load",
    "03": "keypad",
};

/**
 * Firmware LED mode (the param-01 selector, read via "c4.dmx.led NN 01") →
 * integration mode name. Firmware "programmed" (00) is called "fixed" on the
 * HA side, but the integration compares against the firmware name.
 */
export const LED_MODE_FROM_FIRMWARE: Record<string, string> = {
    "00": "programmed",
    "01": "follow_load",
    "02": "push_release",
};

/**
 * Parse a single-byte parameter read response:
 * "0r<seq> 000 c4.dmx.led 02" → "02" (normalized 2-digit lowercase hex) or
 * null. The 1-2 hex-digit anchor cannot match a 6-digit color response, so a
 * crossed-up reply parses as null rather than garbage.
 */
export function parseParamResponse(cmd: "led" | "btn", responseText?: string | null): string | null {
    if (!responseText) return null;
    const match = responseText.match(new RegExp(`000 c4\\.dmx\\.${cmd} ([0-9a-fA-F]{1,2})$`));
    if (!match) return null;
    return match[1].toLowerCase().padStart(2, "0");
}

/**
 * Read one slot's stored config for read-back verification (issue #145):
 * on/off LED colors, the LED mode selector, and the button behavior, as the
 * exact state keys the control4_dimmers integration ingests. A key is absent
 * when its read timed out (the integration skips absent fields as unreadable
 * rather than treating them as drift). An unmapped firmware value is
 * published raw so it surfaces as a loud mismatch the integration can
 * re-push, instead of silently passing verification.
 */
export async function readStoredSlotConfig(device: Zh.Device, slotId: number): Promise<KeyValue> {
    const btn = BUTTONS.find((b) => b.idx === slotId);
    if (!btn) throw new Error(`Invalid slot id ${slotId}, expected 1-${BUTTONS.length}`);

    const state: KeyValue = {};

    for (const [mode, suffix] of [
        ["03", "on"],
        ["04", "off"],
    ]) {
        const resp = await queryC4WithResponse(device, `c4.dmx.led ${btn.id} ${mode}`, 2000);
        const hex = parseLedColorResponse(resp);
        if (hex) state[`c4_led_${slotId}_${suffix}`] = hex;
        else logger.debug(`Slot ${slotId} LED ${suffix} color: no response`, NS);
    }

    const modeResp = await queryC4WithResponse(device, `c4.dmx.led ${btn.id} 01`, 2000);
    const modeVal = parseParamResponse("led", modeResp);
    if (modeVal) {
        const modeName = LED_MODE_FROM_FIRMWARE[modeVal];
        if (!modeName) logger.warning(`Slot ${slotId} LED mode read returned unknown value ${modeVal}`, NS);
        state[`button_${slotId}_led_mode`] = modeName ?? modeVal;
    } else {
        logger.debug(`Slot ${slotId} LED mode: no response`, NS);
    }

    const behaviorResp = await queryC4WithResponse(device, `c4.dmx.btn ${btn.id} 01`, 2000);
    const behaviorVal = parseParamResponse("btn", behaviorResp);
    if (behaviorVal) {
        const behaviorName = BEHAVIOR_FROM_FIRMWARE[behaviorVal];
        if (!behaviorName) logger.warning(`Slot ${slotId} behavior read returned unknown value ${behaviorVal}`, NS);
        state[`button_${slotId}_behavior`] = behaviorName ?? behaviorVal;
    } else {
        logger.debug(`Slot ${slotId} behavior: no response`, NS);
    }

    return state;
}

export const C4_STATE_READ_DEBOUNCE_MS = 750;

const c4StateReadTimers = new Map<string, ReturnType<typeof setTimeout>>();

export const C4_LOAD_STATE_DEBOUNCE_MS = 500;

interface C4LoadStateEntry {
    level: number;
    timer: ReturnType<typeof setTimeout> | null;
}

const c4LoadStateTimers = new Map<string, C4LoadStateEntry>();

// Timestamp (ms) of the most recent ls frame per device, so the fallback
// ZCL read can be skipped when telemetry already refreshed the state.
const c4LastLsSeen = new Map<string, number>();

/**
 * Trailing-edge throttle of ls telemetry: each frame resets the timer, so the
 * final publish always carries the settled level. Level 0 publishes OFF with
 * no brightness key, preserving the last-on level.
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
 * Debounced ZCL read of the load on/off + level (C4 devices support no
 * attribute reporting); a fallback skipped when ls telemetry already
 * refreshed the state, and skipped entirely for loadless keypads.
 */
export function scheduleC4StateRead(device: Zh.Device | undefined, deviceType?: string | null): void {
    if (!device) return;

    if (deviceType === "keypad") return;

    const key = device.ieeeAddr;
    const scheduledAt = Date.now();
    const existing = c4StateReadTimers.get(key);
    if (existing) clearTimeout(existing);

    const timer = setTimeout(async () => {
        c4StateReadTimers.delete(key);

        const lastLs = c4LastLsSeen.get(key);
        if (lastLs !== undefined && lastLs > scheduledAt) {
            logger.debug(`Skipping ZCL read for ${key}; ls telemetry already refreshed state`, NS);
            return;
        }

        let ep1: Zh.Endpoint | undefined;
        try {
            ep1 = device.getEndpoint(1);
        } catch (err) {
            logger.debug(`getEndpoint(1) failed: ${(err as Error).message}`, NS);
            return;
        }
        if (!ep1) return;

        try {
            await ep1.read("genOnOff", ["onOff"]);
        } catch (err) {
            logger.debug(`genOnOff read failed: ${(err as Error).message}`, NS);
        }
        try {
            await ep1.read("genLevelCtrl", ["currentLevel"]);
        } catch (err) {
            logger.debug(`genLevelCtrl read failed: ${(err as Error).message}`, NS);
        }
    }, C4_STATE_READ_DEBOUNCE_MS);

    c4StateReadTimers.set(key, timer);
}

// Self-heal for keypad verdicts caused by a silent dim-probe timeout: passive
// load evidence reclassifies immediately, and assumed keypads get an active
// re-probe campaign; confirmed keypads are never re-probed.

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

function persistC4Meta(device: Zh.Device, fields: C4MetaFields): void {
    if (fields.type !== undefined) device.meta.c4_device_type = fields.type;
    if (fields.confidence !== undefined) device.meta.c4_type_confidence = fields.confidence;
    if (fields.dimCode !== undefined) device.meta.c4_dim_code = fields.dimCode;
    if (fields.silentProbes !== undefined) device.meta.c4_silent_probes = fields.silentProbes;
    if (typeof device.save === "function") device.save();
}

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
 * Reclassify from load evidence, persist, and return the state fragment to
 * publish (null when no correction is warranted). Idempotent, so the probe
 * and response paths can both observe the same answer without double publishing.
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

    logger.info(`${device.ieeeAddr}: ${currentType ?? "(none)"} -> ${newType} (evidence: ${evidenceDesc})`, NS);

    persistC4Meta(device, {type: newType, confidence: C4_CONFIDENCE_CONFIRMED, dimCode});
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

function markConfirmedC4Keypad(device: Zh.Device, publish?: Publish, opts: {evidence?: string; logReason?: string} = {}): void {
    const evidence = opts.evidence ?? `${C4_MAX_SILENT_PROBES} consecutive silent c4.dmx.dim probes`;
    const logReason = opts.logReason ?? `keypad confirmed after ${C4_MAX_SILENT_PROBES} silent c4.dmx.dim probes`;

    persistC4Meta(device, {confidence: C4_CONFIDENCE_CONFIRMED});
    logger.info(`${device.ieeeAddr}: ${logReason}`, NS);

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

// probeFn may also return a bare dim code string or null (legacy test seam).
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
 * Start (once per process) the active dim-probe campaign for an assumed
 * keypad: a jittered first probe, then exponential backoff, until a dim answer
 * heals it or C4_MAX_SILENT_PROBES silences confirm it.
 */
export function scheduleC4ProbeCampaign(
    device: Zh.Device | undefined,
    deviceType: string | undefined | null,
    publish?: Publish,
    opts: C4ProbeCampaignOpts = {},
): void {
    if (!device) return;
    if (deviceType !== "keypad") return;
    if (effectiveConfidence(device.meta) === C4_CONFIDENCE_CONFIRMED) return;
    if (c4ProbeCampaigns.has(device.ieeeAddr)) return;

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
            logger.warning(`Probe failed for ${device.ieeeAddr}: ${(err as Error).message}`, NS);
            outcome = {kind: "silent"};
        }

        if (outcome.kind === "heal") {
            // The dim response also flows through the raw fromZigbee handler;
            // applyC4Heal is idempotent so both paths can observe the answer.
            applyC4Heal(device, deviceType, {dimCode: outcome.dimCode}, publish);
            c4ProbeCampaigns.delete(device.ieeeAddr);
            return;
        }

        if (outcome.kind === "negative") {
            // An explicit no-load answer is proof, not silence: confirm now
            // instead of burning the silent-probe budget.
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

/**
 * Arm the self-heal probe campaign at bridge start, so quiet devices get probed
 * without having to emit traffic first; an absent classification counts as an
 * assumed keypad so a never-detected device is still probed.
 */
export function c4ArmProbeOnStart(device: Zh.Device | undefined, state: KeyValue | undefined, opts: C4ProbeCampaignOpts = {}): void {
    if (!device) return;

    const currentType = (state?.c4_device_type as string | undefined) ?? (device.meta.c4_device_type as string | undefined) ?? "keypad";
    scheduleC4ProbeCampaign(device, currentType, opts.publish, opts);
}

export function c4DeviceLabel(device: Zh.Device | undefined): string {
    if (!device) return "?";
    const ieee = device.ieeeAddr ?? "?";
    const name = (device.meta.friendlyName as string | undefined) ?? undefined;
    return name ? `${ieee} (${name})` : ieee;
}
