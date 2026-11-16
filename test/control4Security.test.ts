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

function tz(key: string): AnyFn {
    const converter = (definition.toZigbee ?? []).find((t) => t.key?.includes(key));
    if (!converter?.convertSet) throw new Error(`no converter for ${key}`);
    return converter.convertSet as AnyFn;
}

function tzMeta(device: MockDevice): KeyValue {
    return {device: asDevice(device), publish: vi.fn(), state: {}, message: {}};
}

/** Frame bodies put on the air, without the "0s<seq> " / "0g<seq> " prefix and CRLF. */
function bodies(sent: string[]): string[] {
    return sent.map((frame) => frame.replace(/^0[sg][0-9a-f]{4} /, "").replace(/\r\n$/, ""));
}

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

    describe("logging device text", () => {
        const ch = (code: number) => String.fromCharCode(code);
        // LF, ESC, CR, DEL, a C1 control and LINE SEPARATOR.
        const hostile = `0t1 sa c4.dmx.ls 0 0 65${ch(0x0a)}[fake log line]${ch(0x1b)}[2J${ch(0x0d)}${ch(0x7f)}${ch(0x85)}${ch(0x2028)}`;

        /** True when every character is printable ASCII. */
        const printable = (s: string) => [...s].every((c) => c.charCodeAt(0) >= 0x20 && c.charCodeAt(0) <= 0x7e);

        /** Every message passed to a logger mock, joined. */
        function logged(fn: unknown): string {
            return vi
                .mocked(fn as AnyFn)
                .mock.calls.map((args: unknown[]) => String(args[0]))
                .join("|");
        }

        it("c4LogText escapes control characters and clips long text", () => {
            const escaped = c4.c4LogText(hostile);
            expect(printable(escaped)).toBe(true);
            expect(escaped).toContain("[fake log line]");
            expect(escaped).toContain("\\n[fake log line]");
            expect(escaped).toContain("\\u001b[2J\\r\\u007f\\u0085\\u2028");
            expect(c4.c4LogText("x".repeat(1000)).length).toBeLessThan(220);
        });

        it("no raw control character reaches a log line from a hostile frame", async () => {
            const {device} = makeDevice("0x5E61", {c4_device_type: "keypaddim", c4_type_confidence: "confirmed"});
            await raw(hostile, device);
            const all = logged(logger.debug) + logged(logger.info) + logged(logger.warning);
            expect(all).toContain("[fake log line]");
            expect(printable(all)).toBe(true);
        });

        it("rate-limits the malformed-frame warning per device", async () => {
            const {device} = makeDevice("0x5E62", {c4_device_type: "keypaddim", c4_type_confidence: "confirmed"});
            const {device: other} = makeDevice("0x5E63", {c4_device_type: "keypaddim", c4_type_confidence: "confirmed"});
            const warnings = () => vi.mocked(logger.warning).mock.calls.filter((args) => String(args[0]).includes("out-of-range load level"));

            for (let i = 0; i < 50; i++) await raw("0t0001 sa c4.dmx.ls 00 00 65", device);
            expect(warnings()).toHaveLength(1);

            await raw("0t0001 sa c4.dmx.ls 00 00 65", other);
            expect(warnings()).toHaveLength(2);

            await vi.advanceTimersByTimeAsync(c4.C4_FRAME_WARN_INTERVAL_MS);
            await raw("0t0001 sa c4.dmx.ls 00 00 65", device);
            expect(warnings()).toHaveLength(3);
        });
    });

    describe("c4_led and raw command validation", () => {
        const ch = (code: number) => String.fromCharCode(code);

        it("sends and publishes legitimate single LED commands unchanged", async () => {
            const {device, sent} = makeDevice("0x5E71");
            const led = tz("c4_led");

            expect(await led(undefined, "c4_led", {led: "top", color: "FF0000", mode: "on"}, tzMeta(device))).toEqual({
                state: {c4_led_top_on: "ff0000"},
            });
            expect(await led(undefined, "c4_led", {led: 3, color: "#00ff00", mode: "off"}, tzMeta(device))).toEqual({
                state: {c4_led_3_off: "00ff00"},
            });
            expect(await led(undefined, "c4_led", {led: "02", color: "0000ff", mode: "05"}, tzMeta(device))).toEqual({
                state: {c4_led_02_05: "0000ff"},
            });
            expect(await led(undefined, "c4_led", {color: "ffffff"}, tzMeta(device))).toEqual({state: {c4_led_top_on: "ffffff"}});

            expect(bodies(sent)).toEqual([
                "c4.dmx.led 01 03 ff0000",
                "c4.dmx.led 02 04 00ff00",
                "c4.dmx.led 02 05 0000ff",
                "c4.dmx.led 01 03 ffffff",
            ]);
        });

        it.each([
            ["a smuggled frame", {led: "01 03 ff0000\r\n0s0001 c4.dmx.btn 01 01 00\r\n0s0002 c4.dmx.led 01"}],
            ["__proto__", {led: "__proto__"}],
            ["constructor", {led: "constructor"}],
            ["toString", {mode: "toString"}],
            ["an out-of-range code", {led: "06"}],
            ["a long code", {mode: "003"}],
            ["an object", {led: {x: 1}}],
        ])("rejects %s as an LED or mode and sends nothing", async (_label, fields) => {
            const {device, sent} = makeDevice("0x5E72");
            await expect(tz("c4_led")(undefined, "c4_led", {color: "00ff00", ...fields}, tzMeta(device))).rejects.toThrow(/Invalid LED/);
            expect(sent).toEqual([]);
        });

        it("rejects a non-hex color", async () => {
            const {device, sent} = makeDevice("0x5E73");
            await expect(tz("c4_led")(undefined, "c4_led", {color: "zzzzzz"}, tzMeta(device))).rejects.toThrow(/Invalid color/);
            await expect(tz("c4_led")(undefined, "c4_led", {color: {r: 1}}, tzMeta(device))).rejects.toThrow(/Invalid color/);
            expect(sent).toEqual([]);
        });

        it("batch form publishes the validated colors and sends nothing if any is bad", async () => {
            const {device, sent} = makeDevice("0x5E74");
            const led = tz("c4_led");

            expect(await led(undefined, "c4_led", {top_on: "#FFFFFF", bottom_off: "0000ff"}, tzMeta(device))).toEqual({
                state: {c4_top_led_on: "ffffff", c4_bottom_led_off: "0000ff"},
            });
            expect(bodies(sent)).toEqual(["c4.dmx.led 01 03 ffffff", "c4.dmx.led 04 04 0000ff"]);

            sent.length = 0;
            await expect(led(undefined, "c4_led", {top_on: "ffffff", bottom_on: "ff0000\r\n0s0001 x"}, tzMeta(device))).rejects.toThrow(
                /Invalid color/,
            );
            expect(sent).toEqual([]);
        });

        it.each([
            ["CRLF", "c4.dmx.led 01 03 ff0000\r\n0s0001 c4.dmx.btn 01 01 00"],
            ["a bare LF", "c4.dmx.led 01 03 ff0000\n"],
            ["NUL", `c4.dmx.led${ch(0)}`],
            ["DEL", `c4.dmx.led${ch(0x7f)}`],
            ["U+010A, which the ascii encoder turns into LF", `c4.dmx.led 01 03 ff0000${ch(0x10a)}0s0001 c4.dmx.btn 01 01 00`],
            ["U+010D, which the ascii encoder turns into CR", `c4.dmx.led 01 03 ff0000${ch(0x10d)}`],
            ["a non-ASCII letter", `c4.dmx.l${ch(0xe9)}d`],
        ])("c4_cmd and c4_query reject text with %s", async (_label, text) => {
            const {device, sent} = makeDevice("0x5E75");
            await expect(tz("c4_cmd")(undefined, "c4_cmd", text, tzMeta(device))).rejects.toThrow(/printable ASCII/);
            await expect(tz("c4_query")(undefined, "c4_query", text, tzMeta(device))).rejects.toThrow(/printable ASCII/);
            expect(sent).toEqual([]);
        });

        it("c4_cmd still sends a plain command with its CRLF terminator", async () => {
            const {device, sent} = makeDevice("0x5E76");
            await tz("c4_cmd")(undefined, "c4_cmd", "c4.dmx.led 01 03 ff0000", tzMeta(device));
            expect(sent).toHaveLength(1);
            expect(sent[0]).toMatch(/^0s[0-9a-f]{4} c4\.dmx\.led 01 03 ff0000\r\n$/);
        });
    });

    describe("telemetry and colors", () => {
        const good = "0t6850 sa c4.dmx.ls 00 00 63 0079 0070 000d 000e 03aa 0000 0000";

        it("keeps a real frame's readings", () => {
            expect(c4.parseLoadTelemetry(good)).toEqual({
                c4_load_voltage: 121,
                c4_load_current: 112,
                c4_load_power: 13,
                c4_load_apparent_power: 14,
                c4_load_power_factor: 0.938,
                c4_load_field_9: 0,
                c4_load_field_10: 0,
            });
        });

        it.each([
            ["an overlong field", "0t1 sa c4.dmx.ls 00 00 10 ffffffffffffffffffffffffffffffff 0 0 0 0 0 0"],
            ["a five-digit field", "0t1 sa c4.dmx.ls 00 00 10 00079 0070 000d 000e 03aa 0000 0000"],
            ["an implausible voltage", "0t1 sa c4.dmx.ls 00 00 10 ffff 0070 000d 000e 03aa 0000 0000"],
            ["an implausible current", "0t1 sa c4.dmx.ls 00 00 10 0079 ffff 000d 000e 03aa 0000 0000"],
            ["an implausible power", "0t1 sa c4.dmx.ls 00 00 10 0079 0070 ffff 000e 03aa 0000 0000"],
            ["an implausible apparent power", "0t1 sa c4.dmx.ls 00 00 10 0079 0070 000d ffff 03aa 0000 0000"],
            ["a power factor above 1", "0t1 sa c4.dmx.ls 00 00 10 0079 0070 000d 000e 03e9 0000 0000"],
            ["too many fields", `0t1 sa c4.dmx.ls 00 00 10 0079 0070 000d 000e 03aa${" 0".repeat(10)}`],
        ])("drops the readings for %s", (_label, frame) => {
            expect(c4.parseLoadTelemetry(frame)).toBeNull();
        });

        it("an implausible frame still publishes the level but no readings", async () => {
            const {device} = makeDevice("0x5E81", {c4_device_type: "keypaddim", c4_type_confidence: "confirmed"});
            const publish = vi.fn();
            await raw("0t1 sa c4.dmx.ls 00 00 32 ffff 0070 000d 000e 03aa 0000 0000", device, {}, publish);
            await vi.advanceTimersByTimeAsync(c4.C4_LOAD_STATE_DEBOUNCE_MS + 10);
            expect(publish).toHaveBeenCalledExactlyOnceWith({state: "ON", brightness: 128});
        });

        it("rejects a level that is not 1-4 hex digits", () => {
            expect(c4.parseLoadStatus("0t1 sa c4.dmx.ls 00 00 1zz")).toBeNull();
            expect(c4.parseLoadStatus("0t1 sa c4.dm.t0c 0x32")).toBeNull();
            expect(c4.parseLoadStatus("0t1 sa c4.dmx.ls 00 00 32")).toEqual({level: 50});
        });

        it("reads only hex LED colors", () => {
            expect(c4.parseLedColorResponse("0r0001 000 c4.dmx.led zzzzzz")).toBeNull();
            expect(c4.parseLedColorResponse("0r0001 000 c4.dmx.led ___123")).toBeNull();
            expect(c4.parseLedColorResponse("0r0001 000 c4.dmx.led A0b1C2")).toBe("a0b1c2");
        });
    });

    describe("MQTT-triggered work", () => {
        it("zcl_read caps and type-checks the attribute list", async () => {
            const {device, ep1} = makeDevice("0x5E91");
            const zclRead = tz("zcl_read");
            const many = Array.from({length: 33}, (_, i) => i);

            await expect(zclRead(undefined, "zcl_read", {cluster: "genBasic", attributes: many}, tzMeta(device))).rejects.toThrow(/at most 32/);
            await expect(zclRead(undefined, "zcl_read", {cluster: "genBasic", attributes: [{}]}, tzMeta(device))).rejects.toThrow(/names or numeric/);
            await expect(zclRead(undefined, "zcl_read", {cluster: "genBasic", attributes: "modelId"}, tzMeta(device))).rejects.toThrow(/array/);
            expect(ep1.read).not.toHaveBeenCalled();

            await zclRead(undefined, "zcl_read", {cluster: "genBasic", attributes: many.slice(0, 32)}, tzMeta(device));
            expect(ep1.read).toHaveBeenCalledTimes(1);
        });

        it.each([
            ["c4_read_dimming", true],
            ["c4_detect", true],
            ["c4_verify_slot", 3],
        ])("%s refuses a repeat while one is running, then runs again", async (key, value) => {
            const {device, sent} = makeDevice("0x5E92");
            const convert = tz(key);

            const first = convert(undefined, key, value, tzMeta(device));
            await expect(convert(undefined, key, value, tzMeta(device))).rejects.toThrow(/already running/);
            const burst = sent.length;

            await vi.advanceTimersByTimeAsync(60000);
            await first;
            expect(sent.length).toBeGreaterThan(burst);

            const second = convert(undefined, key, value, tzMeta(device));
            await vi.advanceTimersByTimeAsync(60000);
            await expect(second).resolves.not.toThrow();
        });

        it("guards per device, and per slot for c4_verify_slot", async () => {
            const {device} = makeDevice("0x5E93");
            const {device: other} = makeDevice("0x5E94");
            const verify = tz("c4_verify_slot");

            const runs = [
                verify(undefined, "c4_verify_slot", 1, tzMeta(device)),
                verify(undefined, "c4_verify_slot", 2, tzMeta(device)),
                verify(undefined, "c4_verify_slot", 1, tzMeta(other)),
            ];
            await vi.advanceTimersByTimeAsync(60000);
            await expect(Promise.all(runs)).resolves.toBeDefined();
        });

        it("a thrown run releases the guard", async () => {
            const {device} = makeDevice("0x5E95");
            device.getEndpoint.mockImplementation(() => undefined);
            const readDimming = tz("c4_read_dimming");
            // Every query fails to send (no endpoint) and the table comes back empty.
            const run = readDimming(undefined, "c4_read_dimming", true, tzMeta(device));
            await vi.advanceTimersByTimeAsync(60000);
            await run;
            await expect(c4.withC4InFlightGuard(asDevice(device), "x", () => Promise.reject(new Error("boom")))).rejects.toThrow("boom");
            await expect(c4.withC4InFlightGuard(asDevice(device), "x", () => Promise.resolve(1))).resolves.toBe(1);
        });

        it("a run that outlives a stop event doesn't release a newer run's guard", async () => {
            const {device} = makeDevice("0x5E96");
            let finishOld: (value: number) => void = () => {};
            const old = c4.withC4InFlightGuard(asDevice(device), "op", () => new Promise<number>((resolve) => (finishOld = resolve)));

            await (definition.onEvent as AnyFn)({type: "stop", data: {ieeeAddr: device.ieeeAddr}});
            let finishNew: (value: number) => void = () => {};
            const fresh = c4.withC4InFlightGuard(asDevice(device), "op", () => new Promise<number>((resolve) => (finishNew = resolve)));

            finishOld(1);
            await old;
            await expect(c4.withC4InFlightGuard(asDevice(device), "op", () => Promise.resolve(3))).rejects.toThrow(/already running/);
            finishNew(2);
            await expect(fresh).resolves.toBe(2);
        });
    });
});
