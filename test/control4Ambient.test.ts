/**
 * Ambient light: the reading a Control4 switch pushes with "c4.dmx.amb 01 02"
 * set, or returns to a "c4.dmx.amb 00" read, published as `ambient_light`
 * (bharat/homeassistant-control4-zigbee#279). Frames are taken from real
 * C4-APD120 and C4-SW120277 switches on firmware 5.1.1.
 */

import {afterEach, beforeEach, describe, expect, it, vi} from "vitest";
import {definitions} from "../src/devices/control4";
import {prepareDefinition} from "../src/index";
import * as c4 from "../src/lib/control4";
import {logger} from "../src/lib/logger";
import type {KeyValue, Zh} from "../src/lib/types";

// biome-ignore lint/suspicious/noExplicitAny: mock plumbing for the fz/tz/onEvent signatures
type AnyFn = (...args: any[]) => any;

interface MockDevice {
    ieeeAddr: string;
    meta: KeyValue;
    save: ReturnType<typeof vi.fn>;
    getEndpoint: ReturnType<typeof vi.fn>;
}

/** A fake herdsman device; `sendRaw` records every frame put on the air and resolves via `ack`. */
function makeDevice(ieeeAddr: string, ack: () => Promise<void> = () => Promise.resolve()): {device: MockDevice; sent: string[]} {
    const sent: string[] = [];
    const ep1 = {
        ID: 1,
        read: vi.fn(async () => ({})),
        command: vi.fn(async () => ({})),
        sendRaw: vi.fn((_cluster: number, data: Buffer): Promise<void> => {
            sent.push(data.toString("latin1"));
            return ack();
        }),
    };
    const device: MockDevice = {
        ieeeAddr,
        meta: {c4_device_type: "dimmer", c4_type_confidence: "confirmed"},
        save: vi.fn(),
        getEndpoint: vi.fn((id: number) => (id === 1 ? ep1 : undefined)),
    };
    return {device, sent};
}

const asDevice = (d: MockDevice): Zh.Device => d as unknown as Zh.Device;

const definition = definitions[0];
const outlet = prepareDefinition(definitions[1]);

function raw(text: string, device: MockDevice, def = definition): Promise<KeyValue | undefined> {
    const rawFz = (def.fromZigbee ?? []).find((converter) => converter.cluster === "genPowerCfg") as unknown as {convert: AnyFn};
    const msg = {data: Buffer.from(text, "latin1"), endpoint: {ID: 197}, device, type: "raw", cluster: "genPowerCfg"};
    return rawFz.convert(def, msg, vi.fn(), {}, {state: {}, device});
}

/** Send `body` through c4_query and return the sequence number it went out with. */
async function query(device: MockDevice, sent: string[], body: string, def = definition): Promise<string> {
    const converter = (def.toZigbee ?? []).find((t) => t.key?.includes("c4_query"));
    if (!converter?.convertSet) throw new Error("no c4_query converter");
    void converter.convertSet(asDevice(device).getEndpoint(1), "c4_query", body, {
        device: asDevice(device),
        publish: vi.fn(),
        state: {},
        message: {},
    } as never);
    await Promise.resolve();
    const seq = /^0g([0-9a-f]{4}) /.exec(sent[sent.length - 1])?.[1];
    if (!seq) throw new Error("query not sent");
    return seq;
}

describe("Control4 ambient light", () => {
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

    describe("parseAmbientPush", () => {
        it("returns the reported (second) byte", () => {
            expect(c4.parseAmbientPush("0t68be sa c4.dmx.amb c6 ea")).toBe(0xea);
            expect(c4.parseAmbientPush("0t68c0 sa c4.dmx.amb 9f 9f")).toBe(0x9f);
        });

        it("ignores the 00 first byte of the push sent when push mode is turned on", () => {
            expect(c4.parseAmbientPush("0t7225 sa c4.dmx.amb 00 b1")).toBe(0xb1);
            expect(c4.parseAmbientPush("0t7226 sa c4.dmx.amb 00 00")).toBe(0);
        });

        it("covers the whole byte range and tolerates a trailing CR/LF", () => {
            expect(c4.parseAmbientPush("0t0001 sa c4.dmx.amb ff ff\r\n")).toBe(255);
            expect(c4.parseAmbientPush("0t0001 sa c4.dmx.amb FF 0A")).toBe(10);
        });

        it("rejects anything but a two-byte amb push", () => {
            for (const text of [
                "0r0001 000 c4.dmx.amb ff ff",
                "0t0001 sa c4.dmx.amb ff",
                "0t0001 sa c4.dmx.amb ff ff ff",
                "0t0001 sa c4.dmx.amb fff ff",
                "0t0001 sa c4.dmx.amb zz ff",
                "0t0001 sa c4.dmx.ambx ff ff",
                "0t0001 sa c4.dmx.ls 00 00 64 0078",
                "x0t0001 sa c4.dmx.amb ff ff",
                "",
            ]) {
                expect(c4.parseAmbientPush(text), text).toBeNull();
            }
            expect(c4.parseAmbientPush(null)).toBeNull();
            expect(c4.parseAmbientPush(undefined)).toBeNull();
        });
    });

    describe("parseAmbientReadReply", () => {
        it("returns the one-byte reading", () => {
            expect(c4.parseAmbientReadReply("0rb65e 000 c4.dmx.amb ff")).toBe(255);
            expect(c4.parseAmbientReadReply("0r0001 000 c4.dmx.amb 1d\r\n")).toBe(0x1d);
            expect(c4.parseAmbientReadReply("0r0001 000 c4.dmx.amb 00")).toBe(0);
        });

        it("rejects replies of another shape (06, 04, errors, pushes)", () => {
            for (const text of [
                "0r0001 000 c4.dmx.amb ff ff",
                "0r0001 000 c4.dmx.amb 00001388",
                "0r0001 n01",
                "0r0001 v01",
                "0r0001 000",
                "0t0001 sa c4.dmx.amb ff ff",
                "0r0001 000 c4.dmx.dim 01",
            ]) {
                expect(c4.parseAmbientReadReply(text), text).toBeNull();
            }
            expect(c4.parseAmbientReadReply(null)).toBeNull();
        });
    });

    describe("isC4AmbientRead", () => {
        it("matches only the 00 read", () => {
            expect(c4.isC4AmbientRead("c4.dmx.amb 00")).toBe(true);
            expect(c4.isC4AmbientRead("  c4.dmx.amb   00 ")).toBe(true);
            for (const body of ["c4.dmx.amb 01", "c4.dmx.amb 06", "c4.dmx.amb 00 01", "c4.dmx.amb", "c4.dmx.amb 000"]) {
                expect(c4.isC4AmbientRead(body), body).toBe(false);
            }
        });
    });

    describe("raw handler", () => {
        it("publishes a push as ambient_light and keeps c4_response", async () => {
            const {device} = makeDevice("0xA001");
            const result = await raw("0t68be sa c4.dmx.amb c6 ea", device);
            expect(result?.ambient_light).toBe(0xea);
            expect(result?.c4_response).toBe("0t68be sa c4.dmx.amb c6 ea");
        });

        it("uses the reported byte for the push sent when push mode is turned on", async () => {
            const {device} = makeDevice("0xA002");
            expect((await raw("0t7225 sa c4.dmx.amb 00 b1", device))?.ambient_light).toBe(0xb1);
        });

        it("publishes the reply to a c4_query amb 00 read and keeps c4_response", async () => {
            const {device, sent} = makeDevice("0xA003");
            const seq = await query(device, sent, "c4.dmx.amb 00");
            const result = await raw(`0r${seq} 000 c4.dmx.amb 1d`, device);
            expect(result?.ambient_light).toBe(0x1d);
            expect(result?.c4_response).toBe(`0r${seq} 000 c4.dmx.amb 1d`);
        });

        it("reads a reply that arrives before the send resolves", async () => {
            const {device, sent} = makeDevice("0xA004", () => new Promise(() => {}));
            const seq = await query(device, sent, "c4.dmx.amb 00");
            expect((await raw(`0r${seq} 000 c4.dmx.amb 42`, device))?.ambient_light).toBe(0x42);
        });

        it("ignores replies to the other amb parameters, which have the same shape", async () => {
            const {device, sent} = makeDevice("0xA005");
            for (const [param, answer] of [
                ["01", "00"],
                ["03", "1e"],
                ["05", "ff"],
            ]) {
                const seq = await query(device, sent, `c4.dmx.amb ${param}`);
                const result = await raw(`0r${seq} 000 c4.dmx.amb ${answer}`, device);
                expect(result, param).not.toHaveProperty("ambient_light");
                expect(result?.c4_response).toBe(`0r${seq} 000 c4.dmx.amb ${answer}`);
            }
        });

        it("ignores an amb reply nobody asked for", async () => {
            const {device} = makeDevice("0xA006");
            expect(await raw("0r0001 000 c4.dmx.amb ff", device)).not.toHaveProperty("ambient_light");
        });

        it("only takes the reply from the queried device, and only once", async () => {
            const {device, sent} = makeDevice("0xA007");
            const {device: other} = makeDevice("0xA008");
            const seq = await query(device, sent, "c4.dmx.amb 00");

            expect(await raw(`0r${seq} 000 c4.dmx.amb ff`, other)).not.toHaveProperty("ambient_light");
            expect((await raw(`0r${seq} 000 c4.dmx.amb 10`, device))?.ambient_light).toBe(0x10);
            expect(await raw(`0r${seq} 000 c4.dmx.amb 20`, device)).not.toHaveProperty("ambient_light");
        });

        it("forgets a read whose reply comes too late", async () => {
            const {device, sent} = makeDevice("0xA009");
            const seq = await query(device, sent, "c4.dmx.amb 00");
            vi.advanceTimersByTime(c4.C4_AMBIENT_READ_TTL_MS + 1);
            expect(await raw(`0r${seq} 000 c4.dmx.amb ff`, device)).not.toHaveProperty("ambient_light");
        });

        it("forgets the device's reads on the stop event", async () => {
            const {device, sent} = makeDevice("0xA00A");
            const seq = await query(device, sent, "c4.dmx.amb 00");
            await (definition.onEvent as AnyFn)({type: "stop", data: {ieeeAddr: device.ieeeAddr}});
            expect(await raw(`0r${seq} 000 c4.dmx.amb ff`, device)).not.toHaveProperty("ambient_light");
        });

        it("bounds the number of reads it remembers", async () => {
            const {device, sent} = makeDevice("0xA00B");
            const first = await query(device, sent, "c4.dmx.amb 00");
            for (let i = 0; i < 300; i++) await query(device, sent, "c4.dmx.amb 00");
            expect(await raw(`0r${first} 000 c4.dmx.amb ff`, device)).not.toHaveProperty("ambient_light");
        });

        it("publishes nothing for the outlet's n01 answer", async () => {
            const {device, sent} = makeDevice("0xA00C");
            const seq = await query(device, sent, "c4.dmx.amb 00", outlet);
            const result = await raw(`0r${seq} n01`, device, outlet);
            expect(result).not.toHaveProperty("ambient_light");
            expect(result?.c4_response).toBe(`0r${seq} n01`);
        });
    });
});
