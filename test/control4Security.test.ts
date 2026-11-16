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
});
