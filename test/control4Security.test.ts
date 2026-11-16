/**
 * Hardening of the Control4 converter against hostile or malformed input:
 * frames from a misbehaving or malicious device, crafted MQTT commands, and
 * devices that leave the network while timers are still running.
 */

import {afterEach, beforeEach, describe, expect, it, vi} from "vitest";
import {definitions} from "../src/devices/control4";
import * as c4 from "../src/lib/control4";
import {logger} from "../src/lib/logger";
import type {KeyValue, Zh} from "../src/lib/types";

// biome-ignore lint/suspicious/noExplicitAny: mock plumbing for the fz/tz/onEvent signatures
type AnyFn = (...args: any[]) => any;

interface MockDevice {
    ieeeAddr: string;
    meta: KeyValue;
    modelID?: string;
    softwareBuildID?: string;
    isDeleted?: boolean;
    save: ReturnType<typeof vi.fn>;
    getEndpoint: ReturnType<typeof vi.fn>;
}

/** A fake herdsman device; `sendRaw` records every frame put on the air. */
function makeDevice(ieeeAddr: string, meta: KeyValue = {}): {device: MockDevice; sent: string[]; ep1: KeyValue} {
    const sent: string[] = [];
    const ep1 = {
        ID: 1,
        read: vi.fn(async () => ({})),
        command: vi.fn(async () => ({})),
        sendRaw: vi.fn((_cluster: number, data: Buffer): Promise<void> => {
            sent.push(data.toString("latin1"));
            return Promise.resolve();
        }),
    };
    const device: MockDevice = {
        ieeeAddr,
        meta: {...meta},
        save: vi.fn(),
        getEndpoint: vi.fn((id: number) => (id === 1 ? ep1 : undefined)),
    };
    return {device, sent, ep1};
}

const asDevice = (d: MockDevice): Zh.Device => d as unknown as Zh.Device;

const definition = definitions[0];
const outlet = definitions[1];
const [rawFz, identityFz] = definition.fromZigbee as unknown as [{convert: AnyFn}, {convert: AnyFn}];

function raw(text: string, device: MockDevice, state: KeyValue = {}, publish: AnyFn = vi.fn()): Promise<KeyValue | undefined> {
    const msg = {data: Buffer.from(text, "latin1"), endpoint: {ID: 197}, device, type: "raw", cluster: "genPowerCfg"};
    return rawFz.convert(definition, msg, publish, {}, {state, device});
}

function identityReport(device: MockDevice, data: KeyValue, state: KeyValue = {}, extra: KeyValue = {}): KeyValue | undefined {
    const msg = {data, endpoint: {ID: 2}, device, type: "attributeReport", cluster: "genPowerCfg", ...extra};
    return identityFz.convert(definition, msg, vi.fn(), {}, {state, device});
}

describe("Control4 security hardening", () => {
    beforeEach(() => {
        vi.spyOn(logger, "debug").mockImplementation(() => {});
        vi.spyOn(logger, "info").mockImplementation(() => {});
        vi.spyOn(logger, "warning").mockImplementation(() => {});
        vi.useFakeTimers();
    });

    afterEach(() => {
        c4.resetC4HealState();
        vi.runOnlyPendingTimers();
        vi.useRealTimers();
        vi.restoreAllMocks();
    });

    describe("async timers survive a removed device", () => {
        it("a probe campaign stops when the device is removed, without saving", async () => {
            const {device} = makeDevice("0x5E01", {c4_device_type: "keypad"});
            const probeFn = vi.fn(async () => null);

            c4.scheduleC4ProbeCampaign(asDevice(device), "keypad", vi.fn(), {probeFn, random: () => 0, backoffMs: 1000});
            device.isDeleted = true;
            await vi.advanceTimersByTimeAsync(60000);

            expect(probeFn).not.toHaveBeenCalled();
            expect(device.save).not.toHaveBeenCalled();
        });

        it("a probe answered after the device left does not touch it", async () => {
            const {device} = makeDevice("0x5E02", {c4_device_type: "keypad"});
            const probeFn = vi.fn(() => {
                device.isDeleted = true; // leaves while the query is out
                return Promise.resolve(null);
            });

            c4.scheduleC4ProbeCampaign(asDevice(device), "keypad", vi.fn(), {probeFn, random: () => 0, backoffMs: 1000});
            await vi.advanceTimersByTimeAsync(60000);

            expect(probeFn).toHaveBeenCalledTimes(1);
            expect(device.save).not.toHaveBeenCalled();
            expect(device.meta.c4_silent_probes).toBeUndefined();
        });

        it("a save() that throws inside a probe step is logged, not raised", async () => {
            const {device} = makeDevice("0x5E03", {c4_device_type: "keypad"});
            device.save.mockImplementation(() => {
                throw new Error("DatabaseEntry with ID '7' does not exist");
            });
            const unhandled = vi.fn();
            process.on("unhandledRejection", unhandled);
            try {
                c4.scheduleC4ProbeCampaign(asDevice(device), "keypad", vi.fn(), {probeFn: async () => null, random: () => 0, backoffMs: 1000});
                await vi.advanceTimersByTimeAsync(0);
                await vi.advanceTimersByTimeAsync(10);
            } finally {
                process.off("unhandledRejection", unhandled);
            }

            expect(unhandled).not.toHaveBeenCalled();
            expect(logger.warning).toHaveBeenCalledWith(expect.stringContaining("does not exist"), "zhc:control4");
        });

        it("a probe step that throws ends the campaign instead of rejecting", async () => {
            const {device} = makeDevice("0x5E04", {c4_device_type: "keypad"});
            const publish = vi.fn(() => {
                throw new Error("publish exploded");
            });
            const unhandled = vi.fn();
            process.on("unhandledRejection", unhandled);
            try {
                c4.scheduleC4ProbeCampaign(asDevice(device), "keypad", publish, {probeFn: async () => "02", random: () => 0});
                await vi.advanceTimersByTimeAsync(0);
                await vi.advanceTimersByTimeAsync(10);
            } finally {
                process.off("unhandledRejection", unhandled);
            }

            expect(unhandled).not.toHaveBeenCalled();
            expect(logger.warning).toHaveBeenCalledWith(expect.stringContaining("publish exploded"), "zhc:control4");
            // The campaign is gone, so a new one can be armed.
            const probeFn = vi.fn(async () => null);
            device.meta.c4_device_type = "keypad";
            device.meta.c4_type_confidence = undefined;
            c4.scheduleC4ProbeCampaign(asDevice(device), "keypad", vi.fn(), {probeFn, random: () => 0});
            await vi.advanceTimersByTimeAsync(0);
            expect(probeFn).toHaveBeenCalledTimes(1);
        });

        it("the load-state timer skips a removed device and never throws", async () => {
            const {device} = makeDevice("0x5E05");
            const publish = vi.fn();
            c4.scheduleC4LoadStatePublish(asDevice(device), 50, publish);
            device.isDeleted = true;
            await vi.advanceTimersByTimeAsync(c4.C4_LOAD_STATE_DEBOUNCE_MS + 10);
            expect(publish).not.toHaveBeenCalled();

            const {device: other} = makeDevice("0x5E06");
            const throwing = vi.fn(() => {
                throw new Error("publish exploded");
            });
            c4.scheduleC4LoadStatePublish(asDevice(other), 50, throwing);
            await vi.advanceTimersByTimeAsync(c4.C4_LOAD_STATE_DEBOUNCE_MS + 10);
            expect(throwing).toHaveBeenCalledTimes(1);
            expect(logger.warning).toHaveBeenCalledWith(expect.stringContaining("publish exploded"), "zhc:control4");
        });

        it("the state-read timer skips a removed device", async () => {
            const {device, ep1} = makeDevice("0x5E07", {c4_device_type: "keypaddim"});
            c4.scheduleC4StateRead(asDevice(device), "keypaddim");
            device.isDeleted = true;
            await vi.advanceTimersByTimeAsync(c4.C4_STATE_READ_DEBOUNCE_MS + 10);
            expect(ep1.read).not.toHaveBeenCalled();
        });

        it("the stop event clears the campaign and every pending timer for that device", async () => {
            const {device, ep1} = makeDevice("0x5E08", {c4_device_type: "keypad"});
            const probeFn = vi.fn(async () => null);
            const publish = vi.fn();

            c4.scheduleC4ProbeCampaign(asDevice(device), "keypad", vi.fn(), {probeFn, random: () => 0.5});
            c4.scheduleC4LoadStatePublish(asDevice(device), 50, publish);
            c4.scheduleC4StateRead(asDevice(device), "keypaddim");

            await (definition.onEvent as AnyFn)({type: "stop", data: {ieeeAddr: device.ieeeAddr}});
            await vi.advanceTimersByTimeAsync(120000);

            expect(probeFn).not.toHaveBeenCalled();
            expect(publish).not.toHaveBeenCalled();
            expect(ep1.read).not.toHaveBeenCalled();

            // Re-joining afterwards can arm a fresh campaign.
            c4.scheduleC4ProbeCampaign(asDevice(device), "keypad", vi.fn(), {probeFn, random: () => 0});
            await vi.advanceTimersByTimeAsync(0);
            expect(probeFn).toHaveBeenCalledTimes(1);
        });

        it("the outlet's stop event clears its timers too", async () => {
            const {device, ep1} = makeDevice("0x5E09");
            c4.scheduleC4StateRead(asDevice(device), undefined);
            await (outlet.onEvent as AnyFn)({type: "stop", data: {ieeeAddr: device.ieeeAddr}});
            await vi.advanceTimersByTimeAsync(c4.C4_STATE_READ_DEBOUNCE_MS + 10);
            expect(ep1.read).not.toHaveBeenCalled();
        });

        it("an identity report whose save() throws is logged, not raised", () => {
            const {device} = makeDevice("0x5E0A");
            device.save.mockImplementation(() => {
                throw new Error("DatabaseEntry with ID '7' does not exist");
            });
            expect(() => c4.applyC4Identity(asDevice(device), {model: "C4-KD120", firmware: "5.1.1"}, {})).not.toThrow();
            expect(logger.warning).toHaveBeenCalledWith(expect.stringContaining("does not exist"), "zhc:control4");
        });
    });

    describe("persist rate limiting", () => {
        const kd = "c4:control4_light:C4-KD120";
        const apd = "c4:control4_light:C4-APD120";

        it("keeps the first listed model and ignores a different one, logging once", () => {
            const {device} = makeDevice("0x5E21");
            // The first report also types the device from its model (a second save).
            expect(identityReport(device, {4: "5.1.1", 7: kd})).toMatchObject({c4_model: "C4-KD120", c4_firmware: "5.1.1"});
            const saves = device.save.mock.calls.length;

            for (let i = 0; i < 10; i++) {
                expect(identityReport(device, {7: i % 2 ? kd : apd}, {c4_model: "C4-KD120"})).toBeUndefined();
            }

            expect(device.meta.c4_model).toBe("C4-KD120");
            expect(device.modelID).toBe("C4-KD120");
            expect(device.save).toHaveBeenCalledTimes(saves);
            const conflicts = vi.mocked(logger.warning).mock.calls.filter((args) => String(args[0]).includes("ignoring reported model"));
            expect(conflicts).toHaveLength(1);
        });

        it("still takes a first listed model over an unlisted one", () => {
            const {device} = makeDevice("0x5E22", {c4_model: "C4-XYZ"});
            identityReport(device, {7: kd});
            expect(device.meta.c4_model).toBe("C4-KD120");
            expect(device.modelID).toBe("C4-KD120");
        });

        it("persists a firmware change at most once per interval", async () => {
            const {device} = makeDevice("0x5E23");
            expect(identityReport(device, {4: "1.0"})).toEqual({c4_firmware: "1.0"});
            for (let i = 0; i < 20; i++) {
                expect(identityReport(device, {4: i % 2 ? "1.0" : "1.1"}, {c4_firmware: "1.0"})).toBeUndefined();
            }
            expect(device.save).toHaveBeenCalledTimes(1);
            expect(device.softwareBuildID).toBe("1.0");

            await vi.advanceTimersByTimeAsync(c4.C4_PERSIST_MIN_INTERVAL_MS);
            expect(identityReport(device, {4: "1.1"}, {c4_firmware: "1.0"})).toEqual({c4_firmware: "1.1"});
            expect(device.save).toHaveBeenCalledTimes(2);
            expect(device.softwareBuildID).toBe("1.1");
        });

        it("rate limits flipping unlisted models", () => {
            const {device} = makeDevice("0x5E24");
            identityReport(device, {7: "c4:x:AAA"});
            identityReport(device, {7: "c4:x:BBB"});
            identityReport(device, {7: "c4:x:AAA"});
            expect(device.meta.c4_model).toBe("AAA");
            expect(device.save).toHaveBeenCalledTimes(1);
        });

        it("never saves an unchanged identity", () => {
            const {device} = makeDevice("0x5E25");
            identityReport(device, {4: "5.1.1", 7: kd}, {});
            const saves = device.save.mock.calls.length;
            for (let i = 0; i < 5; i++) identityReport(device, {4: "5.1.1", 7: kd}, {});
            expect(device.save).toHaveBeenCalledTimes(saves);
        });

        it("takes one dim-answer type change per interval", async () => {
            const {device} = makeDevice("0x5E26", {c4_device_type: "keypad"});

            const first = await raw("0r0001 000 c4.dmx.dim 01", device, {c4_device_type: "keypad"});
            expect(first?.c4_device_type).toBe("dimmer");
            const saves = device.save.mock.calls.length;

            for (let i = 0; i < 10; i++) {
                const code = i % 2 ? "01" : "02";
                const result = await raw(`0r0001 000 c4.dmx.dim ${code}`, device, {c4_device_type: "dimmer"});
                expect(result?.c4_device_type).toBeUndefined();
            }
            expect(device.meta.c4_device_type).toBe("dimmer");
            expect(device.save.mock.calls.length).toBe(saves);

            await vi.advanceTimersByTimeAsync(c4.C4_PERSIST_MIN_INTERVAL_MS);
            const later = await raw("0r0001 000 c4.dmx.dim 02", device, {c4_device_type: "dimmer"});
            expect(later?.c4_device_type).toBe("keypaddim");
        });

        it("ls telemetry still upgrades a keypad right after a dim heal elsewhere", async () => {
            const {device} = makeDevice("0x5E27", {c4_device_type: "keypad"});
            const result = await raw("0t0001 sa c4.dmx.ls 00 00 32", device, {c4_device_type: "keypad"});
            expect(result?.c4_device_type).toBe("keypaddim");
        });
    });

    describe("wire ids", () => {
        beforeEach(() => {
            c4.resetC4ButtonLogState();
        });

        it("maps only the known ids to actions", () => {
            const mapped: Record<string, string> = {
                "00": "button_1_press",
                "01": "button_2_press",
                "02": "button_3_press",
                "03": "button_4_press",
                "04": "button_5_press",
                "05": "button_6_press",
                "07": "paddle_up_press",
                "08": "paddle_down_press",
            };
            for (let id = 0; id < 256; id++) {
                const hex = id.toString(16).padStart(2, "0");
                const action = c4.parseButtonEvent(`0t0001 sa c4.dmx.bp ${hex}`)?.action;
                expect(action).toBe(mapped[hex]);
                if (action) expect(c4.ACTION_VALUES).toContain(action);
            }
        });

        it.each(["1a2b3c4d5e", "001", "7", "0x", "g1"])("publishes no action for the malformed id %s", async (id) => {
            for (const kind of ["bp", "sc"]) {
                expect(c4.parseButtonEvent(`0t0001 sa c4.dmx.${kind} ${id}`)).toBeNull();
            }
            expect(c4.parseButtonEvent(`0t0001 sa c4.dmx.cc ${id} 01`)).toBeNull();

            const {device} = makeDevice("0x5E31", {c4_device_type: "keypaddim", c4_type_confidence: "confirmed"});
            const result = await raw(`0t0001 sa c4.dmx.bp ${id}`, device);
            expect(result?.action).toBeUndefined();
        });

        it("ignores a click count that is not one or two hex digits", () => {
            expect(c4.parseButtonEvent("0t0001 sa c4.dmx.cc 00 1ff")).toBeNull();
            expect(c4.parseButtonEvent("0t0001 sa c4.dmx.cc 00 0x2")).toBeNull();
            expect(c4.parseButtonEvent("0tdc28 sa c4.dm.cc 00 100")).toBeNull();
        });

        it("keeps the unknown-id log guard bounded", () => {
            for (let id = 0; id < 256; id++) c4.parseButtonEvent(`0t0001 sa c4.dmx.bp ${id.toString(16).padStart(2, "0")}`);
            for (let i = 0; i < 1000; i++) c4.parseButtonEvent(`0t0001 sa c4.dmx.bp ${i.toString(16).padStart(6, "0")}`);
            const warnings = vi.mocked(logger.warning).mock.calls.filter((args) => String(args[0]).includes("Unknown wire id"));
            // 248 unknown two-digit ids plus one shared malformed key, each logged once.
            expect(warnings).toHaveLength(249);
        });
    });

    describe("identity model", () => {
        it("stores a listed model or a short plain name only", () => {
            expect(c4.parseC4Identity({7: "c4:control4_light:C4-KD120"}).model).toBe("C4-KD120");
            expect(c4.parseC4Identity({7: "c4:x:C4-NEW-THING9"}).model).toBe("C4-NEW-THING9");
            for (const bad of ["c4:x:ZZZ\n[fake log line]", "c4:x:has space", "c4:x:semi;colon", `c4:x:${"A".repeat(33)}`, "c4:x:\u001b[2J", ""]) {
                expect(c4.parseC4Identity({7: bad}).model).toBeUndefined();
            }
        });

        it("drops a firmware string with control characters or excess length", () => {
            expect(c4.parseC4Identity({4: "5.1.1"}).firmware).toBe("5.1.1");
            expect(c4.parseC4Identity({4: "1.0\r\nINJECTED"}).firmware).toBeUndefined();
            expect(c4.parseC4Identity({4: "9".repeat(33)}).firmware).toBeUndefined();
        });

        it("never stores a malformed model on the device", () => {
            const {device} = makeDevice("0x5E41");
            expect(identityReport(device, {7: "c4:x:ZZZ\nfoo"})).toBeUndefined();
            expect(device.meta.c4_model).toBeUndefined();
            expect(device.save).not.toHaveBeenCalled();
        });

        it("an unlisted meta model doesn't shadow a listed modelID", () => {
            const {device} = makeDevice("0x5E42", {c4_model: "ZZZ"});
            device.modelID = "C4-KD120";
            expect(c4.c4ModelType(asDevice(device))).toEqual({model: "C4-KD120", type: "keypaddim"});
            expect(c4.c4ModelType(asDevice(device), {c4_model: "C4-KC120277"})).toEqual({model: "C4-KC120277", type: "keypad"});
        });

        it("an inherited property name never counts as a model", () => {
            const {device} = makeDevice("0x5E43", {c4_model: "constructor"});
            device.modelID = "__proto__";
            expect(c4.c4ModelType(asDevice(device), {c4_model: "toString"})).toBeUndefined();
        });

        it("ignores an identity frame on another profile when the message carries one", () => {
            const {device} = makeDevice("0x5E44");
            expect(identityReport(device, {7: "c4:x:C4-KD120"}, {}, {profileId: 0x0104})).toBeUndefined();
            expect(device.meta.c4_model).toBeUndefined();
            expect(identityReport(device, {7: "c4:x:C4-KD120"}, {}, {profileId: c4.C4_IDENTITY_PROFILE})).toMatchObject({c4_model: "C4-KD120"});
        });
    });

    describe("query reply matching (bharat/homeassistant-control4-zigbee#241)", () => {
        /** Start a query on `device` and return its promise plus the sequence number it went out with. */
        async function startQuery(device: MockDevice, sent: string[], cmdBody: string) {
            const promise = c4.queryC4WithResponse(asDevice(device), cmdBody, 3000);
            await Promise.resolve();
            const seq = /^0g([0-9a-f]{4}) /.exec(sent[sent.length - 1])?.[1];
            if (!seq) throw new Error("query not sent");
            return {promise, seq};
        }

        it("only the queried device's reply resolves the query", async () => {
            const {device: victim, sent} = makeDevice("0x5E51", {c4_device_type: "keypad", c4_type_confidence: "confirmed"});
            const {device: other} = makeDevice("0x5E52", {c4_device_type: "keypad", c4_type_confidence: "confirmed"});
            const {promise, seq} = await startQuery(victim, sent, "c4.dmx.dim");

            await raw(`0r${seq} 000 c4.dmx.dim 01`, other);
            expect(c4.resolveC4PendingQuery(seq, `0r${seq} 000 c4.dmx.dim 01`, undefined)).toBe(false);
            await raw(`0r${seq} 000 c4.dmx.dim 02`, victim);

            expect(await promise).toBe(`0r${seq} 000 c4.dmx.dim 02`);
        });

        it("a reply that answers a different command doesn't resolve the query", async () => {
            const {device, sent} = makeDevice("0x5E53");
            const {promise, seq} = await startQuery(device, sent, "c4.dmx.led 01 03");

            expect(c4.resolveC4PendingQuery(seq, `0r${seq} 000 c4.dmx.dim 01`, device.ieeeAddr)).toBe(false);
            expect(c4.resolveC4PendingQuery(seq, `0r${seq} 000 c4.dmx.led 00ff00`, device.ieeeAddr)).toBe(true);
            expect(await promise).toBe(`0r${seq} 000 c4.dmx.led 00ff00`);
        });

        it("an error reply still resolves (it carries no echo)", async () => {
            const {device, sent} = makeDevice("0x5E54");
            const {promise, seq} = await startQuery(device, sent, "c4.dmx.dim");
            expect(c4.resolveC4PendingQuery(seq, `0r${seq} n01`, device.ieeeAddr)).toBe(true);
            expect(await promise).toBe(`0r${seq} n01`);
        });

        it("isPlausibleC4Reply checks the frame shape and the echoed command", () => {
            expect(c4.isPlausibleC4Reply("0r0001 000 c4.dm.tv 0064", "c4.dm.tv")).toBe(true);
            expect(c4.isPlausibleC4Reply("0r0001 v01", "c4.dm.tv")).toBe(true);
            expect(c4.isPlausibleC4Reply("0r0001 000 c4.dmx.led 0064", "c4.dm.tv")).toBe(false);
            expect(c4.isPlausibleC4Reply("0t0001 sa c4.dm.tv 0064", "c4.dm.tv")).toBe(false);
        });

        it("the stop event gives up the device's pending queries at once", async () => {
            const {device, sent} = makeDevice("0x5E55");
            const {promise} = await startQuery(device, sent, "c4.dmx.dim");
            await (definition.onEvent as AnyFn)({type: "stop", data: {ieeeAddr: device.ieeeAddr}});
            expect(await promise).toBeNull();
            expect(logger.warning).not.toHaveBeenCalledWith(expect.stringContaining("Timeout"), "zhc:control4");
        });
    });
});
