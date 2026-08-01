import * as c4 from "../lib/control4";
import * as exposes from "../lib/exposes";
import {logger} from "../lib/logger";
import * as m from "../lib/modernExtend";
import type {DefinitionWithExtend, Fz, KeyValue, Tz, Zh} from "../lib/types";

const e = exposes.presets;
const NS = "zhc:control4";

/**
 * Read arbitrary cluster attributes for the diagnostic converters. The typed
 * Endpoint.read API is keyed to known cluster attribute names; these
 * converters exist precisely to poke at anything, so the call goes through a
 * loosened signature.
 */
async function readLoose(ep: Zh.Endpoint, cluster: string | number, attrs: (string | number)[]): Promise<KeyValue> {
    const read = ep.read as unknown as (c: string | number, a: (string | number)[], o?: {timeout?: number}) => Promise<KeyValue | undefined>;
    return (await read.call(ep, cluster, attrs, {timeout: 10000})) ?? {};
}

// Control4 in-wall Zigbee devices: C4-APD120 (dimmer, 2 buttons + load),
// C4-KD120 (keypad dimmer, 6 buttons + load), C4-KC120277 (configurable
// keypad, 6 buttons, no load). All share identical endpoint structures and
// the proprietary c4.dmx text protocol on custom profile 0xC25C; device
// type differentiation happens at runtime via protocol probing. Standard
// on/off + dimming rides genOnOff/genLevelCtrl on endpoint 1.
//
// Requires an adapter stack that accepts profile 0xC25C (the whitelist in
// zigbee-herdsman) and Endpoint.sendRaw for outbound text commands.

// ─── fromZigbee: Capture C4 Text Protocol Responses ─────────────────
//
// C4 devices send responses and telemetry as raw ASCII from endpoint 197
// (0xC5), profile 0xC25C, cluster 1. With no ZCL framing, herdsman fires
// a "raw" event captured here. Cluster ID 1 resolves to genPowerCfg.
//
// Response format: "0r<seq> 000 [data]" (success) or "0r<seq> v01" (error)
// Telemetry format: "0t<seq> sa <command> <data>"

const fzControl4Response = {
    cluster: "genPowerCfg", // C4 uses cluster ID 1, which ZCL maps to genPowerCfg
    type: ["raw"],
    convert: async (model, msg, publish, options, meta) => {
        let text: string;
        try {
            text = Buffer.from(msg.data).toString("ascii").trim();
        } catch {
            return; // Not ASCII data: ignore
        }
        if (!text) return;

        const epId = msg.endpoint?.ID ?? "?";
        logger.debug(`[C4 RECV] EP ${epId}: ${text}`, NS);

        // ── Check for pending query responses (response queue) ──
        const respSeq = c4.parseResponseSeq(text);
        if (respSeq && c4.resolveC4PendingQuery(respSeq, text)) {
            logger.debug(`[C4 Q/R] Resolved pending query seq ${respSeq}`, NS);
        }

        const result: KeyValue = {c4_response: text, c4_response_ep: epId};

        const currentType = (meta.state?.c4_device_type as string | undefined) ?? (msg.device?.meta.c4_device_type as string | undefined);

        // Kick off the active self-heal campaign for an assumed keypad on
        // the first message seen from this device (idempotent thereafter).
        // No-op for load-bearing devices and confirmed keypads.
        c4.scheduleC4ProbeCampaign(msg.device, currentType, publish);

        // ── Passive self-heal: a c4.dmx.dim answer proves a load ──
        //
        // Any dim answer (solicited by a probe or otherwise) is
        // authoritative load evidence, so reclassify keypad/none immediately.
        const dimAnswerCode = c4.parseDimResponse(text);
        if (dimAnswerCode) {
            const healState = c4.applyC4Heal(msg.device, currentType, {dimCode: dimAnswerCode});
            if (healState) Object.assign(result, healState);
        }

        // ── Parse button/event messages ──
        const event = c4.parseButtonEvent(text);
        if (event) {
            result.action = event.action;
            logger.debug(`[C4 BUTTON] ${c4.c4DeviceLabel(msg.device)} ${event.type}: ${event.action}`, NS);

            // Passive self-heal: a local load paddle half only exists on
            // load-bearing hardware, so a paddle event proves the device
            // drives a load. Upgrades an assumed keypad / unclassified
            // device to keypaddim (never downgrades an existing load type).
            if (event.paddle) {
                const healState = c4.applyC4Heal(msg.device, currentType, {paddle: true});
                if (healState) Object.assign(result, healState);
            }

            // Smart behavior on press: if the button has load-control
            // behavior configured, send the genOnOff command to EP1 now.
            if (event.type === "press") {
                const behavior = meta.state?.[`button_${event.buttonId}_behavior`] as string | undefined;
                if (behavior && behavior !== "keypad") {
                    try {
                        const ep1 = msg.device.getEndpoint(1);
                        if (ep1) {
                            const cmd =
                                behavior === "toggle_load" ? "toggle" : behavior === "load_on" ? "on" : behavior === "load_off" ? "off" : null;
                            if (cmd) {
                                logger.debug(`[C4 BUTTON] ${c4.c4DeviceLabel(msg.device)} Smart behavior: genOnOff.${cmd}`, NS);
                                await ep1.command("genOnOff", cmd, {});
                            }
                        }
                    } catch (err) {
                        logger.warning(`[C4 BUTTON] ${c4.c4DeviceLabel(msg.device)} Smart behavior failed: ${(err as Error).message}`, NS);
                    }
                }
            }

            // Sync load state after any button event. Manual paddle presses
            // never report their state (no ZCL reporting), and the
            // smart-behavior genOnOff command above also does not update
            // state on its own, so this debounced read covers both paths.
            c4.scheduleC4StateRead(msg.device, meta.state?.c4_device_type as string | undefined);

            return result;
        }

        // ── Parse unsolicited load-status telemetry ──
        //
        // Devices push their new load level on every change. Coalesce the
        // dim-ramp burst and publish the settled state/brightness.
        const loadStatus = c4.parseLoadStatus(text);
        if (loadStatus) {
            logger.debug(`[C4 LS] ${c4.c4DeviceLabel(msg.device)} Load level ${loadStatus.level}%`, NS);

            // Passive self-heal: unsolicited ls telemetry proves the device
            // drives a load, so an assumed keypad becomes keypaddim.
            const healState = c4.applyC4Heal(msg.device, currentType, {ls: true});
            if (healState) Object.assign(result, healState);

            // Mute the raw c4_response for unsolicited ls telemetry: the
            // debounced scheduleC4LoadStatePublish below already carries the
            // level, so echoing c4_response here would double MQTT volume
            // during a ramp. Query responses (the 0r<seq> form) are NOT ls
            // telemetry and keep publishing c4_response via the fall-through
            // return below; only this telemetry case is muted.
            delete result.c4_response;
            delete result.c4_response_ep;

            c4.scheduleC4LoadStatePublish(msg.device, loadStatus.level, publish);
            return result;
        }

        return result;
    },
} satisfies Fz.Converter<"genPowerCfg", undefined, ["raw"]>;

// ─── toZigbee: Set LED Colors ────────────────────────────────────────
//
// Single LED:
//   {"c4_led": {"led": "1", "color": "ff0000"}}
//   {"c4_led": {"led": "top", "color": "ff0000", "mode": "on"}}
// All 4 dimmer LEDs at once:
//   {"c4_led": {"top_on": "ffffff", "top_off": "000000",
//               "bottom_on": "000000", "bottom_off": "0000ff"}}

const tzControl4Led = {
    key: ["c4_led"],
    convertSet: async (entity, key, value, meta) => {
        if (!meta.device) throw new Error("c4_led requires a device");
        const val = value as KeyValue;
        const state: KeyValue = {};

        // Batch mode: set all 4 dimmer LED states at once
        if (val.top_on !== undefined || val.top_off !== undefined || val.bottom_on !== undefined || val.bottom_off !== undefined) {
            const commands: [string, string, unknown][] = [
                ["01", "03", val.top_on],
                ["01", "04", val.top_off],
                ["04", "03", val.bottom_on],
                ["04", "04", val.bottom_off],
            ];

            for (const [ledId, mode, color] of commands) {
                if (color === undefined) continue;
                const colorHex = c4.normalizeColorHex(String(color));
                if (!c4.isValidColorHex(colorHex)) {
                    throw new Error(`Invalid color "${color}", expected 6-digit hex RGB`);
                }
                await c4.sendC4(meta.device, `c4.dmx.led ${ledId} ${mode} ${colorHex}`);
            }

            if (val.top_on) state.c4_top_led_on = val.top_on;
            if (val.top_off) state.c4_top_led_off = val.top_off;
            if (val.bottom_on) state.c4_bottom_led_on = val.bottom_on;
            if (val.bottom_off) state.c4_bottom_led_off = val.bottom_off;

            return {state};
        }

        // Single LED mode
        const led = (val.led as string | undefined) ?? "top";
        const color = val.color as string | undefined;
        const mode = (val.mode as string | undefined) ?? "on";

        if (!color) {
            throw new Error('c4_led requires "color" (6-digit hex RGB) or batch keys (top_on, top_off, etc.)');
        }

        const ledId = c4.LED_IDS[led] ?? led;
        const colorHex = c4.normalizeColorHex(color);

        if (!c4.isValidColorHex(colorHex)) {
            throw new Error(`Invalid color "${color}", expected 6-digit hex RGB like "ff0000"`);
        }

        const modeCode = c4.LED_MODES[mode] ?? mode;

        await c4.sendC4(meta.device, `c4.dmx.led ${ledId} ${modeCode} ${colorHex}`);
        state[`c4_led_${led}_${mode}`] = colorHex;

        return {state};
    },
} satisfies Tz.Converter;

// ─── toZigbee: Raw C4 Text Command ──────────────────────────────────
//
// For experimentation. The "0s<seq> " prefix and "\r\n" suffix are
// auto-added: {"c4_cmd": "c4.dmx.led 01 03 ff0000"}

const tzControl4Cmd = {
    key: ["c4_cmd"],
    convertSet: async (entity, key, value, meta) => {
        if (!meta.device) throw new Error("c4_cmd requires a device");
        if (typeof value !== "string") {
            throw new Error('c4_cmd expects a string, e.g. "c4.dmx.led 01 03 ff0000"');
        }

        const sent = await c4.sendC4(meta.device, value);
        return {state: {c4_last_cmd: sent}};
    },
} satisfies Tz.Converter;

// ─── toZigbee: C4 GET Query ──────────────────────────────────────────
//
// Like c4_cmd but uses the "0g" (GET) prefix. Responses arrive
// asynchronously from endpoint 197 and are captured by fzControl4Response
// (published as c4_response in device state): {"c4_query": "c4.dmx.amb 01"}

const tzControl4Query = {
    key: ["c4_query"],
    convertSet: async (entity, key, value, meta) => {
        if (!meta.device) throw new Error("c4_query requires a device");
        if (typeof value !== "string") {
            throw new Error('c4_query expects a string, e.g. "c4.dmx.amb 01"');
        }

        const sent = await c4.queryC4(meta.device, value);
        logger.debug(`[C4 QUERY] sent: ${sent}`, NS);
        return {state: {c4_last_query: sent}};
    },
} satisfies Tz.Converter;

// ─── toZigbee: Read ZCL Attributes ──────────────────────────────────
//
// Read arbitrary cluster attributes for device interrogation. Results are
// returned in device state as probe_result:
//   {"zcl_read": {"cluster": "genBasic"}}
//   {"zcl_read": {"cluster": 0, "attributes": [0,1,2]}}

const tzControl4ZclRead = {
    key: ["zcl_read"],
    convertSet: async (entity, key, value, meta) => {
        if (!meta.device) throw new Error("zcl_read requires a device");
        const val = value as KeyValue;
        const epId = (val.endpoint as number | undefined) || 1;
        const ep = meta.device.getEndpoint(epId);
        if (!ep) throw new Error(`Endpoint ${epId} not found`);

        const cluster = (val.cluster as string | number | undefined) ?? "genBasic";
        let attributes = val.attributes as (string | number)[] | undefined;

        if (!attributes && (cluster === "genBasic" || cluster === 0)) {
            attributes = [...c4.GENBASIC_ATTRS];
        }

        if (!attributes || attributes.length === 0) {
            throw new Error('zcl_read requires "attributes" array (or use cluster "genBasic" for defaults)');
        }

        logger.info(`[C4 PROBE] Reading EP ${epId} cluster ${cluster}: ${JSON.stringify(attributes)}`, NS);

        try {
            const result = await readLoose(ep, cluster, attributes);
            logger.info(`[C4 PROBE] Result: ${JSON.stringify(result)}`, NS);
            return {state: {probe_result: {cluster: String(cluster), endpoint: epId, attributes: result}}};
        } catch (batchErr) {
            logger.info(`[C4 PROBE] Batch read failed (${(batchErr as Error).message}), trying one-by-one...`, NS);
            const result: KeyValue = {};
            for (const attr of attributes) {
                try {
                    Object.assign(result, await readLoose(ep, cluster, [attr]));
                } catch (err) {
                    result[attr] = `<error: ${(err as Error).message}>`;
                }
            }
            return {state: {probe_result: {cluster: String(cluster), endpoint: epId, attributes: result, note: "read one-by-one (batch failed)"}}};
        }
    },
} satisfies Tz.Converter;

// ─── toZigbee: Comprehensive Device Probe ───────────────────────────
//
// Dumps everything knowable about the device in one shot: all endpoints
// with profile/deviceID/cluster lists, plus genBasic attributes from
// endpoint 1. {"c4_probe": true}

const tzControl4Probe = {
    key: ["c4_probe"],
    convertSet: async (entity, key, value, meta) => {
        const device = meta.device;
        if (!device) throw new Error("c4_probe requires a device");
        const result: KeyValue = {timestamp: new Date().toISOString()};

        result.device = {
            ieeeAddr: device.ieeeAddr,
            networkAddress: device.networkAddress,
            manufacturerID: device.manufacturerID,
            manufacturerName: device.manufacturerName,
            modelID: device.modelID,
            type: device.type,
        };

        const endpointsInfo: KeyValue = {};
        for (const ep of device.endpoints) {
            endpointsInfo[ep.ID] = {
                profileID: ep.profileID != null ? `0x${ep.profileID.toString(16).padStart(4, "0")}` : null,
                deviceID: ep.deviceID != null ? `0x${ep.deviceID.toString(16).padStart(4, "0")}` : null,
                inputClusters: ep.inputClusters || [],
                outputClusters: ep.outputClusters || [],
            };
        }
        result.endpoints = endpointsInfo;

        const ep1 = device.getEndpoint(1);
        if (ep1) {
            const genBasic: KeyValue = {};
            for (const attr of c4.GENBASIC_ATTRS) {
                try {
                    Object.assign(genBasic, await readLoose(ep1, "genBasic", [attr]));
                } catch {
                    genBasic[attr] = "<unsupported>";
                }
            }
            result.genBasic = genBasic;
            logger.info(`[C4 PROBE] genBasic: ${JSON.stringify(genBasic)}`, NS);
        }

        logger.info(`[C4 PROBE] Full result: ${JSON.stringify(result)}`, NS);
        return {state: {probe_result: result}};
    },
} satisfies Tz.Converter;

// ─── toZigbee: Device Type Detection + LED Color Reading ─────────────
//
// Runtime detection: probes the device to determine type (dimmer,
// keypaddim, or keypad), then reads all stored LED colors from firmware
// and populates state. Run once after pairing: {"c4_detect": true}
// Migrated devices show their existing C4 colors without manual
// reconfiguration.

const tzControl4Detect = {
    key: ["c4_detect"],
    convertSet: async (entity, key, value, meta) => {
        const device = meta.device;
        if (!device) throw new Error("c4_detect requires a device");

        // Step 1: Detect device type
        const {deviceType, dimCode, confidence} = await c4.detectDeviceType(device);

        // Step 2: Read stored LED colors from firmware
        const colorState = await c4.readStoredColors(device, deviceType);

        // Step 3: Build the full state update
        const state: KeyValue = {
            c4_device_type: deviceType,
            ...colorState,
        };

        // Step 4: Store device type + confidence in device.meta for the
        // self-heal machinery. A manual c4_detect that times out yields an
        // assumed keypad, which the active probe campaign may later confirm
        // or heal.
        device.meta.c4_device_type = deviceType;
        device.meta.c4_type_confidence = confidence;
        device.meta.c4_dim_code = dimCode ?? null;
        device.save();

        state.c4_detect_result = {
            ieee_address: device.ieeeAddr,
            device_type: deviceType,
            confidence,
            dim_code: dimCode ?? null,
            model: c4.MODEL_NAMES[deviceType] ?? "unknown",
            description: c4.MODEL_DESCRIPTIONS[deviceType] ?? "Unknown Control4 device",
            colors_read: Object.keys(colorState).length,
        };

        logger.info(`[C4 DETECT] Complete: ${JSON.stringify(state.c4_detect_result)}`, NS);
        return {state};
    },
} satisfies Tz.Converter;

// ─── Definition ──────────────────────────────────────────────────────
//
// Entity layout per device:
//   - 1 main dimmer light (standard Zigbee HA, harmless on pure keypads)
//   - 1 action entity (button/paddle press events)
//   - Utility converters: c4_led, c4_cmd, c4_query, zcl_read, c4_probe,
//     c4_detect
//
// LED colors are stored as flat hex attributes (c4_led_N_on/off) in
// device state, readable by downstream integrations on startup.

export const definitions: DefinitionWithExtend[] = [
    {
        zigbeeModel: [
            "C4-Zigbee", // Set by the interview quirk for newly paired devices
            "C4-APD120", // Adaptive phase dimmer 120V
            "C4-DIM", // Standard in-wall dimmer
            "C4-KD120", // Keypad dimmer 120V
            "C4-KD277", // Keypad dimmer 277V
            "C4-FPD120", // Forward phase dimmer 120V
            "C4-KC120277", // Configurable keypad 120V/277V
            "LDZ-102", // Legacy dimmer model
        ],
        fingerprint: [{manufacturerID: 43981}],
        model: "C4-Zigbee",
        vendor: "Control4",
        description: "Zigbee dimmer/keypad (C4-APD120, C4-KD120, C4-KC120277)",
        extend: [m.light({configureReporting: false})],
        exposes: [e.action([...c4.ACTION_VALUES])],
        fromZigbee: [fzControl4Response],
        toZigbee: [tzControl4Led, tzControl4Cmd, tzControl4Query, tzControl4ZclRead, tzControl4Probe, tzControl4Detect],
        meta: {disableDefaultResponse: true},
        // Arm the self-heal probe campaign for quiet assumed-keypads at
        // startup. The light() extend adds no onEvent, so a definition-level
        // handler composes cleanly.
        onEvent: (event) => {
            if (event.type !== "start") return;
            c4.c4ArmProbeOnStart(event.data.device, event.data.state);
        },
        configure: async (device, coordinatorEndpoint) => {
            const endpoint = device.getEndpoint(1);
            if (!endpoint) return;

            // Bind standard HA clusters on EP 1. NOTE: no coordinator
            // endpoint registration is needed for the C4 text protocol;
            // reception is gated by the profile whitelist alone and the NCP
            // delivers EP 197 frames without any endpoint registration.
            try {
                await endpoint.bind("genOnOff", coordinatorEndpoint);
                await endpoint.bind("genLevelCtrl", coordinatorEndpoint);
            } catch (err) {
                logger.info(`[C4 CONFIG] Cluster binding failed (may be normal for keypads): ${(err as Error).message}`, NS);
            }

            // Auto-detect device type via the C4 text protocol. c4_detect
            // can always be run manually later if this times out.
            try {
                const {deviceType, dimCode, confidence} = await c4.detectDeviceType(device);
                device.meta.c4_device_type = deviceType;
                device.meta.c4_type_confidence = confidence;
                device.meta.c4_dim_code = dimCode ?? null;
                device.save();
                logger.info(
                    `[C4 CONFIG] Auto-detected device type: ${deviceType} (${c4.MODEL_NAMES[deviceType] ?? "unknown"}, confidence: ${confidence})`,
                    NS,
                );
            } catch (err) {
                logger.warning(`[C4 CONFIG] Auto-detection failed: ${(err as Error).message}`, NS);
                logger.warning(`[C4 CONFIG] Run {"c4_detect": true} to detect device type and read LED colors.`, NS);
            }

            logger.info(`[C4 CONFIG] Device ${device.ieeeAddr} configured.`, NS);
        },
    },
];
