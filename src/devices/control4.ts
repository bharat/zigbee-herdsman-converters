import * as c4 from "../lib/control4";
import * as exposes from "../lib/exposes";
import {logger} from "../lib/logger";
import * as m from "../lib/modernExtend";
import type {DefinitionWithExtend, Fz, KeyValue, Tz, Zh} from "../lib/types";

const e = exposes.presets;
const NS = "zhc:control4";

// Read arbitrary cluster attributes through a loosened Endpoint.read signature
// (the typed API is keyed to known attribute names; the diagnostic converters
// exist precisely to poke at anything).
async function readLoose(ep: Zh.Endpoint, cluster: string | number, attrs: (string | number)[]): Promise<KeyValue> {
    const read = ep.read as unknown as (c: string | number, a: (string | number)[], o?: {timeout?: number}) => Promise<KeyValue | undefined>;
    return (await read.call(ep, cluster, attrs, {timeout: 10000})) ?? {};
}

// C4 responses and telemetry arrive as raw ASCII from endpoint 197, profile
// 0xC25C, cluster 1 (which ZCL resolves to genPowerCfg), so herdsman fires a
// "raw" event captured here.
const fzControl4Response = {
    cluster: "genPowerCfg",
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
        logger.debug(`Received EP ${epId}: ${text}`, NS);

        const respSeq = c4.parseResponseSeq(text);
        if (respSeq && c4.resolveC4PendingQuery(respSeq, text)) {
            logger.debug(`Resolved pending query seq ${respSeq}`, NS);
        }

        const result: KeyValue = {c4_response: text, c4_response_ep: epId};

        const currentType = (meta.state?.c4_device_type as string | undefined) ?? (msg.device?.meta.c4_device_type as string | undefined);

        // Arm the self-heal campaign on the first message from an assumed
        // keypad (idempotent; no-op for load types and confirmed keypads).
        c4.scheduleC4ProbeCampaign(msg.device, currentType, publish);

        // Passive self-heal: any dim answer is authoritative load evidence.
        const dimAnswerCode = c4.parseDimResponse(text);
        if (dimAnswerCode) {
            const healState = c4.applyC4Heal(msg.device, currentType, {dimCode: dimAnswerCode});
            if (healState) Object.assign(result, healState);
        }

        const event = c4.parseButtonEvent(text);
        if (event) {
            result.action = event.action;
            logger.debug(`${c4.c4DeviceLabel(msg.device)} ${event.type}: ${event.action}`, NS);

            // Passive self-heal: a load paddle half only exists on
            // load-bearing hardware.
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
                                logger.debug(`${c4.c4DeviceLabel(msg.device)} Smart behavior: genOnOff.${cmd}`, NS);
                                await ep1.command("genOnOff", cmd, {});
                            }
                        }
                    } catch (err) {
                        logger.warning(`${c4.c4DeviceLabel(msg.device)} Smart behavior failed: ${(err as Error).message}`, NS);
                    }
                }
            }

            // Manual paddle presses and the smart-behavior command above never
            // report state on their own, so schedule a debounced load read.
            c4.scheduleC4StateRead(msg.device, meta.state?.c4_device_type as string | undefined);

            return result;
        }

        const loadStatus = c4.parseLoadStatus(text);
        if (loadStatus) {
            logger.debug(`${c4.c4DeviceLabel(msg.device)} Load level ${loadStatus.level}%`, NS);

            // Passive self-heal: ls telemetry proves the device drives a load.
            const healState = c4.applyC4Heal(msg.device, currentType, {ls: true});
            if (healState) Object.assign(result, healState);

            // Mute the raw c4_response for ls telemetry: the debounced publish
            // below carries the level, and echoing both would double MQTT
            // volume during a dim ramp.
            delete result.c4_response;
            delete result.c4_response_ep;

            c4.scheduleC4LoadStatePublish(msg.device, loadStatus.level, publish);
            return result;
        }

        return result;
    },
} satisfies Fz.Converter<"genPowerCfg", undefined, ["raw"]>;

// Set LED colors, single ({"c4_led": {"led": "top", "color": "ff0000", "mode": "on"}})
// or batch ({"c4_led": {"top_on": "ffffff", "bottom_off": "0000ff", ...}}).
const tzControl4Led = {
    key: ["c4_led"],
    convertSet: async (entity, key, value, meta) => {
        if (!meta.device) throw new Error("c4_led requires a device");
        const val = value as KeyValue;
        const state: KeyValue = {};

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

// Raw C4 text command; the "0s<seq> " prefix and "\r\n" suffix are auto-added.
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

// Like c4_cmd but with the "0g" (GET) prefix; the response arrives
// asynchronously from EP 197 and is published as c4_response.
const tzControl4Query = {
    key: ["c4_query"],
    convertSet: async (entity, key, value, meta) => {
        if (!meta.device) throw new Error("c4_query requires a device");
        if (typeof value !== "string") {
            throw new Error('c4_query expects a string, e.g. "c4.dmx.amb 01"');
        }

        const sent = await c4.queryC4(meta.device, value);
        logger.debug(`Query sent: ${sent}`, NS);
        return {state: {c4_last_query: sent}};
    },
} satisfies Tz.Converter;

// Read arbitrary ZCL attributes for device interrogation; results are
// published as probe_result.
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

        logger.info(`Reading EP ${epId} cluster ${cluster}: ${JSON.stringify(attributes)}`, NS);

        try {
            const result = await readLoose(ep, cluster, attributes);
            logger.info(`Result: ${JSON.stringify(result)}`, NS);
            return {state: {probe_result: {cluster: String(cluster), endpoint: epId, attributes: result}}};
        } catch (batchErr) {
            logger.info(`Batch read failed (${(batchErr as Error).message}), trying one-by-one...`, NS);
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

// Dump all endpoints (profile/deviceID/cluster lists) plus genBasic
// attributes from endpoint 1 in one shot.
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
            logger.info(`genBasic: ${JSON.stringify(genBasic)}`, NS);
        }

        logger.info(`Full probe result: ${JSON.stringify(result)}`, NS);
        return {state: {probe_result: result}};
    },
} satisfies Tz.Converter;

// Runtime detection: probe the device type, then read all firmware-stored
// LED colors into state. Run once after pairing: {"c4_detect": true}.
const tzControl4Detect = {
    key: ["c4_detect"],
    convertSet: async (entity, key, value, meta) => {
        const device = meta.device;
        if (!device) throw new Error("c4_detect requires a device");

        const {deviceType, dimCode, confidence} = await c4.detectDeviceType(device);
        const colorState = await c4.readStoredColors(device, deviceType);

        const state: KeyValue = {
            c4_device_type: deviceType,
            ...colorState,
        };

        // A detect that times out yields an assumed keypad, which the active
        // probe campaign may later confirm or heal.
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

        logger.info(`Detection complete: ${JSON.stringify(state.c4_detect_result)}`, NS);
        return {state};
    },
} satisfies Tz.Converter;

// Read-back verification for one slot (issue #145): {"c4_verify_slot": N}
// reads slot N's stored config and publishes the observed values together
// with a c4_verified_slot correlation marker in a single payload, which is
// what the control4_dimmers integration awaits. The marker is then
// immediately cleared (null removes it from the Z2M state cache) so later
// unrelated state publishes cannot echo a stale marker into a future verify
// pass and resolve it with stale observed values (the same retained-read
// trap that bit the raw c4_response interface).
const tzControl4VerifySlot = {
    key: ["c4_verify_slot"],
    convertSet: async (entity, key, value, meta) => {
        if (!meta.device) throw new Error("c4_verify_slot requires a device");
        const slotId = typeof value === "number" ? value : Number.parseInt(String(value), 10);
        if (!Number.isInteger(slotId) || slotId < 1 || slotId > c4.BUTTONS.length) {
            throw new Error(`c4_verify_slot expects a slot id 1-${c4.BUTTONS.length}, got "${value}"`);
        }

        const observed = await c4.readStoredSlotConfig(meta.device, slotId);
        logger.debug(`${c4.c4DeviceLabel(meta.device)} verify slot ${slotId}: ${JSON.stringify(observed)}`, NS);

        // Publish directly (rather than returning state) so the marker clear
        // is guaranteed to follow the verify payload in order.
        meta.publish({...observed, c4_verified_slot: slotId});
        meta.publish({c4_verified_slot: null});
    },
} satisfies Tz.Converter;

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
        toZigbee: [tzControl4Led, tzControl4Cmd, tzControl4Query, tzControl4ZclRead, tzControl4Probe, tzControl4Detect, tzControl4VerifySlot],
        meta: {disableDefaultResponse: true},
        // Arm the self-heal probe campaign for quiet assumed-keypads at
        // startup (the light() extend adds no onEvent).
        onEvent: (event) => {
            if (event.type !== "start") return;
            c4.c4ArmProbeOnStart(event.data.device, event.data.state);
        },
        configure: async (device, coordinatorEndpoint) => {
            const endpoint = device.getEndpoint(1);
            if (!endpoint) return;

            // No coordinator endpoint registration is needed for the C4 text
            // protocol; reception is gated by the profile whitelist alone.
            try {
                await endpoint.bind("genOnOff", coordinatorEndpoint);
                await endpoint.bind("genLevelCtrl", coordinatorEndpoint);
            } catch (err) {
                logger.info(`Cluster binding failed (may be normal for keypads): ${(err as Error).message}`, NS);
            }

            try {
                const {deviceType, dimCode, confidence} = await c4.detectDeviceType(device);
                device.meta.c4_device_type = deviceType;
                device.meta.c4_type_confidence = confidence;
                device.meta.c4_dim_code = dimCode ?? null;
                device.save();
                logger.info(`Auto-detected device type: ${deviceType} (${c4.MODEL_NAMES[deviceType] ?? "unknown"}, confidence: ${confidence})`, NS);
            } catch (err) {
                logger.warning(`Auto-detection failed: ${(err as Error).message}`, NS);
                logger.warning(`Run {"c4_detect": true} to detect device type and read LED colors.`, NS);
            }

            logger.info(`Device ${device.ieeeAddr} configured.`, NS);
        },
    },
];
