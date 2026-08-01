/**
 * Tests for the Control4 glue layer: self-heal confidence model, active
 * probe campaign, debounced load-state publish and ZCL-read fallback,
 * startup arming, the raw fromZigbee handler, and the frozen MQTT
 * contract. Ported from the external converter's c4-self-heal,
 * c4-load-state, c4-state-read and c4-startup-arming suites.
 */

import {afterEach, beforeEach, describe, expect, it, vi} from "vitest";
import {definitions} from "../src/devices/control4";
import {
    ACTION_VALUES,
    applyC4Heal,
    C4_CONFIDENCE_ASSUMED,
    C4_CONFIDENCE_CONFIRMED,
    C4_LOAD_STATE_DEBOUNCE_MS,
    C4_MAX_SILENT_PROBES,
    C4_STATE_READ_DEBOUNCE_MS,
    c4ArmProbeOnStart,
    classifyDimProbeResponse,
    effectiveConfidence,
    healTypeFromEvidence,
    isC4DimNegativeResponse,
    resetC4HealState,
    scheduleC4LoadStatePublish,
    scheduleC4ProbeCampaign,
    scheduleC4StateRead,
} from "../src/lib/control4";
import {logger} from "../src/lib/logger";
import type {KeyValue, Zh} from "../src/lib/types";

interface MockEndpoint {
    // biome-ignore lint/style/useNamingConvention: mirrors the Zh.Endpoint field name
    ID: number;
    read: ReturnType<typeof vi.fn>;
    command: ReturnType<typeof vi.fn>;
}

interface MockDevice {
    ieeeAddr: string;
    meta: KeyValue;
    save: ReturnType<typeof vi.fn>;
    getEndpoint: ReturnType<typeof vi.fn>;
}

/** A tiny fake herdsman device with a spyable save(), a mutable meta, and one EP1. */
function makeDevice(ieeeAddr: string, meta: KeyValue = {}, opts: {readImpl?: () => Promise<KeyValue>} = {}): {device: MockDevice; ep1: MockEndpoint} {
    const ep1: MockEndpoint = {
        ID: 1,
        read: vi.fn(opts.readImpl ?? (async () => ({}))),
        command: vi.fn(async () => ({})),
    };
    const device: MockDevice = {
        ieeeAddr,
        meta: {...meta},
        save: vi.fn(),
        getEndpoint: vi.fn((id: number) => (id === 1 ? ep1 : undefined)),
    };
    return {device, ep1};
}

const asDevice = (d: MockDevice): Zh.Device => d as unknown as Zh.Device;

describe("Control4 glue", () => {
    beforeEach(() => {
        vi.spyOn(logger, "debug").mockImplementation(() => {});
        vi.spyOn(logger, "info").mockImplementation(() => {});
        vi.spyOn(logger, "warning").mockImplementation(() => {});
    });

    afterEach(() => {
        resetC4HealState();
        vi.restoreAllMocks();
    });

    describe("effectiveConfidence (backward compatibility)", () => {
        it("treats an explicit confirmed marker as confirmed", () => {
            expect(effectiveConfidence({c4_type_confidence: C4_CONFIDENCE_CONFIRMED})).toBe(C4_CONFIDENCE_CONFIRMED);
        });

        it("treats legacy state without a marker as assumed", () => {
            expect(effectiveConfidence({c4_device_type: "keypad"})).toBe(C4_CONFIDENCE_ASSUMED);
        });

        it("treats missing meta as assumed", () => {
            expect(effectiveConfidence(undefined)).toBe(C4_CONFIDENCE_ASSUMED);
        });
    });

    describe("healTypeFromEvidence (pure classification)", () => {
        it("dim code 01 heals a keypad to a dimmer", () => {
            expect(healTypeFromEvidence("keypad", {dimCode: "01"})).toBe("dimmer");
        });

        it("dim code 02 heals a keypad to a keypaddim", () => {
            expect(healTypeFromEvidence("keypad", {dimCode: "02"})).toBe("keypaddim");
        });

        it("an unknown nonzero dim code heals to keypaddim", () => {
            expect(healTypeFromEvidence("keypad", {dimCode: "07"})).toBe("keypaddim");
        });

        it("ls telemetry upgrades a keypad to keypaddim as the safe default", () => {
            expect(healTypeFromEvidence("keypad", {ls: true})).toBe("keypaddim");
        });

        it("ls telemetry upgrades an unclassified device to keypaddim", () => {
            expect(healTypeFromEvidence(undefined, {ls: true})).toBe("keypaddim");
        });

        it("ls telemetry never downgrades an existing dimmer", () => {
            expect(healTypeFromEvidence("dimmer", {ls: true})).toBeNull();
        });

        it("paddle telemetry upgrades a keypad to keypaddim", () => {
            expect(healTypeFromEvidence("keypad", {paddle: true})).toBe("keypaddim");
        });

        it("paddle telemetry upgrades an unclassified device to keypaddim", () => {
            expect(healTypeFromEvidence(undefined, {paddle: true})).toBe("keypaddim");
        });

        it("paddle telemetry never downgrades an existing dimmer", () => {
            expect(healTypeFromEvidence("dimmer", {paddle: true})).toBeNull();
        });

        it("paddle telemetry is a no-op on an existing keypaddim", () => {
            expect(healTypeFromEvidence("keypaddim", {paddle: true})).toBeNull();
        });

        it("a dim answer matching the current type is a no-op", () => {
            expect(healTypeFromEvidence("dimmer", {dimCode: "01"})).toBeNull();
        });

        it("empty (non-load) evidence never reclassifies", () => {
            expect(healTypeFromEvidence("keypad", {})).toBeNull();
        });
    });

    describe("classifyDimProbeResponse / isC4DimNegativeResponse", () => {
        it("classifies a dim code answer as heal", () => {
            expect(classifyDimProbeResponse("0r0001 000 c4.dmx.dim 02")).toEqual({kind: "heal", dimCode: "02"});
        });

        it("classifies an explicit n01 answer as negative", () => {
            expect(classifyDimProbeResponse("0r0001 n01")).toEqual({kind: "negative"});
        });

        it("classifies a v01 error form as negative", () => {
            expect(classifyDimProbeResponse("0r0001 v01")).toEqual({kind: "negative"});
        });

        it("classifies null (timeout) as silent", () => {
            expect(classifyDimProbeResponse(null)).toEqual({kind: "silent"});
        });

        it("classifies unrelated text as silent", () => {
            expect(classifyDimProbeResponse("0r0001 000 c4.dmx.led ffffff")).toEqual({kind: "silent"});
        });

        it("isC4DimNegativeResponse accepts n01 and v-forms only", () => {
            expect(isC4DimNegativeResponse("0r0001 n01")).toBe(true);
            expect(isC4DimNegativeResponse("0r0001 v01")).toBe(true);
            expect(isC4DimNegativeResponse("0r0001 000 c4.dmx.dim 01")).toBe(false);
            expect(isC4DimNegativeResponse(null)).toBe(false);
        });
    });

    describe("applyC4Heal (passive self-heal)", () => {
        it("heals an assumed keypad to keypaddim on ls telemetry", () => {
            const {device} = makeDevice("0x0A01", {c4_device_type: "keypad", c4_type_confidence: C4_CONFIDENCE_ASSUMED});
            const publish = vi.fn();

            const state = applyC4Heal(asDevice(device), "keypad", {ls: true}, publish);

            expect(state?.c4_device_type).toBe("keypaddim");
            expect(device.meta.c4_device_type).toBe("keypaddim");
            expect(device.meta.c4_type_confidence).toBe(C4_CONFIDENCE_CONFIRMED);
            expect(device.save).toHaveBeenCalled();
            expect(publish).toHaveBeenCalledWith(expect.objectContaining({c4_device_type: "keypaddim"}));
            expect((state?.c4_detect_result as KeyValue | undefined)?.healed).toBe(true);
        });

        it("heals an assumed keypad to dimmer on a dim answer of 01", () => {
            const {device} = makeDevice("0x0A02", {c4_device_type: "keypad"});

            const state = applyC4Heal(asDevice(device), "keypad", {dimCode: "01"}, vi.fn());

            expect(state?.c4_device_type).toBe("dimmer");
            expect(device.meta.c4_device_type).toBe("dimmer");
            expect(device.meta.c4_dim_code).toBe("01");
            expect(device.meta.c4_type_confidence).toBe(C4_CONFIDENCE_CONFIRMED);
        });

        it("heals a legacy keypad that has no confidence marker", () => {
            const {device} = makeDevice("0x0A04", {c4_device_type: "keypad"});
            expect(effectiveConfidence(device.meta)).toBe(C4_CONFIDENCE_ASSUMED);

            const state = applyC4Heal(asDevice(device), "keypad", {ls: true}, vi.fn());

            expect(state?.c4_device_type).toBe("keypaddim");
            expect(device.meta.c4_type_confidence).toBe(C4_CONFIDENCE_CONFIRMED);
        });

        it("does not reclassify a confirmed keypad on non-load evidence", () => {
            const {device} = makeDevice("0x0A05", {c4_device_type: "keypad", c4_type_confidence: C4_CONFIDENCE_CONFIRMED});
            const publish = vi.fn();

            const state = applyC4Heal(asDevice(device), "keypad", {}, publish);

            expect(state).toBeNull();
            expect(device.meta.c4_device_type).toBe("keypad");
            expect(publish).not.toHaveBeenCalled();
        });

        it("is idempotent once a device is confirmed at the target type", () => {
            const {device} = makeDevice("0x0A06", {c4_device_type: "keypaddim", c4_type_confidence: C4_CONFIDENCE_CONFIRMED});
            const publish = vi.fn();

            const state = applyC4Heal(asDevice(device), "keypaddim", {ls: true}, publish);

            expect(state).toBeNull();
            expect(publish).not.toHaveBeenCalled();
        });

        it("heals an assumed keypad to keypaddim on paddle telemetry", () => {
            const {device} = makeDevice("0x0A07", {c4_device_type: "keypad", c4_type_confidence: C4_CONFIDENCE_ASSUMED});
            const publish = vi.fn();

            const state = applyC4Heal(asDevice(device), "keypad", {paddle: true}, publish);

            expect(state?.c4_device_type).toBe("keypaddim");
            expect(device.meta.c4_device_type).toBe("keypaddim");
            expect(device.meta.c4_type_confidence).toBe(C4_CONFIDENCE_CONFIRMED);
            expect((state?.c4_detect_result as KeyValue | undefined)?.evidence).toContain("paddle");
            expect(publish).toHaveBeenCalledWith(expect.objectContaining({c4_device_type: "keypaddim"}));
        });

        it("paddle telemetry does not downgrade an existing dimmer", () => {
            const {device} = makeDevice("0x0A08", {c4_device_type: "dimmer", c4_type_confidence: C4_CONFIDENCE_CONFIRMED});
            const publish = vi.fn();

            const state = applyC4Heal(asDevice(device), "dimmer", {paddle: true}, publish);

            expect(state).toBeNull();
            expect(device.meta.c4_device_type).toBe("dimmer");
            expect(publish).not.toHaveBeenCalled();
        });
    });

    describe("scheduleC4ProbeCampaign (active self-heal)", () => {
        beforeEach(() => {
            vi.useFakeTimers();
        });

        afterEach(() => {
            resetC4HealState();
            vi.runOnlyPendingTimers();
            vi.useRealTimers();
        });

        it("confirms a true keypad after 3 silent probes and stops", async () => {
            const {device} = makeDevice("0x0C01", {c4_device_type: "keypad"});
            const publish = vi.fn();
            const probeFn = vi.fn(async () => null); // always silent

            scheduleC4ProbeCampaign(asDevice(device), "keypad", publish, {
                probeFn,
                random: () => 0, // fire the first probe immediately
                initialMaxMs: 60000,
                backoffMs: 1000,
            });

            // Drive the whole campaign: jittered start, then two backoff gaps.
            await vi.advanceTimersByTimeAsync(0);
            await vi.advanceTimersByTimeAsync(1000);
            await vi.advanceTimersByTimeAsync(2000);

            expect(probeFn).toHaveBeenCalledTimes(C4_MAX_SILENT_PROBES);
            expect(device.meta.c4_device_type).toBe("keypad");
            expect(device.meta.c4_type_confidence).toBe(C4_CONFIDENCE_CONFIRMED);

            // No further probes after confirmation.
            await vi.advanceTimersByTimeAsync(60000);
            expect(probeFn).toHaveBeenCalledTimes(C4_MAX_SILENT_PROBES);
        });

        it("never probes a confirmed keypad", async () => {
            const {device} = makeDevice("0x0C05", {c4_device_type: "keypad", c4_type_confidence: C4_CONFIDENCE_CONFIRMED});
            const probeFn = vi.fn(async () => null);

            scheduleC4ProbeCampaign(asDevice(device), "keypad", vi.fn(), {probeFn});
            await vi.advanceTimersByTimeAsync(120000);

            expect(probeFn).not.toHaveBeenCalled();
        });

        it("never probes a load-bearing device", async () => {
            const {device} = makeDevice("0x0C06", {c4_device_type: "dimmer"});
            const probeFn = vi.fn(async () => null);

            scheduleC4ProbeCampaign(asDevice(device), "dimmer", vi.fn(), {probeFn});
            await vi.advanceTimersByTimeAsync(120000);

            expect(probeFn).not.toHaveBeenCalled();
        });

        it("a dim answer during the campaign heals and stops probing", async () => {
            const {device} = makeDevice("0x0C02", {c4_device_type: "keypad"});
            const publish = vi.fn();
            const probeFn = vi.fn(async () => "02"); // device answers: it has a load

            scheduleC4ProbeCampaign(asDevice(device), "keypad", publish, {probeFn, random: () => 0, backoffMs: 1000});

            await vi.advanceTimersByTimeAsync(0);

            expect(device.meta.c4_device_type).toBe("keypaddim");
            expect(device.meta.c4_type_confidence).toBe(C4_CONFIDENCE_CONFIRMED);

            // Campaign is over; no more probes.
            await vi.advanceTimersByTimeAsync(60000);
            expect(probeFn).toHaveBeenCalledTimes(1);
        });

        it("confirms immediately on an explicit n01 answer (skips the silent budget)", async () => {
            const {device} = makeDevice("0x0C07", {c4_device_type: "keypad"});
            const publish = vi.fn();
            const probeFn = vi.fn(async () => classifyDimProbeResponse("0r0001 n01"));

            scheduleC4ProbeCampaign(asDevice(device), "keypad", publish, {probeFn, random: () => 0, backoffMs: 1000});

            await vi.advanceTimersByTimeAsync(0);

            expect(probeFn).toHaveBeenCalledTimes(1);
            expect(device.meta.c4_type_confidence).toBe(C4_CONFIDENCE_CONFIRMED);
            expect(publish).toHaveBeenCalledWith(
                expect.objectContaining({c4_detect_result: expect.objectContaining({evidence: "explicit n01 answer"})}),
            );

            // No second probe.
            await vi.advanceTimersByTimeAsync(120000);
            expect(probeFn).toHaveBeenCalledTimes(1);
        });

        it("only starts one campaign per device per process", async () => {
            const {device} = makeDevice("0x0C03", {c4_device_type: "keypad"});
            const probeFn = vi.fn(async () => null);

            scheduleC4ProbeCampaign(asDevice(device), "keypad", vi.fn(), {probeFn, random: () => 0, backoffMs: 1000});
            // A second call while the first campaign is live must be a no-op.
            scheduleC4ProbeCampaign(asDevice(device), "keypad", vi.fn(), {probeFn, random: () => 0, backoffMs: 1000});

            await vi.advanceTimersByTimeAsync(0);
            expect(probeFn).toHaveBeenCalledTimes(1);
        });

        it("spaces silent probes with exponentially growing gaps", async () => {
            const {device} = makeDevice("0x0C0F", {c4_device_type: "keypad"});
            const probeFn = vi.fn(async () => null);

            scheduleC4ProbeCampaign(asDevice(device), "keypad", vi.fn(), {
                probeFn,
                random: () => 0, // deterministic: first probe at t=0
                initialMaxMs: 60000,
                backoffMs: 1000,
            });

            // First probe fires immediately (jitter = 0).
            await vi.advanceTimersByTimeAsync(0);
            expect(probeFn).toHaveBeenCalledTimes(1);

            // Second probe is one backoff unit later; not before.
            await vi.advanceTimersByTimeAsync(999);
            expect(probeFn).toHaveBeenCalledTimes(1);
            await vi.advanceTimersByTimeAsync(1);
            expect(probeFn).toHaveBeenCalledTimes(2);

            // Third probe is two backoff units later (the gap grew).
            await vi.advanceTimersByTimeAsync(1999);
            expect(probeFn).toHaveBeenCalledTimes(2);
            await vi.advanceTimersByTimeAsync(1);
            expect(probeFn).toHaveBeenCalledTimes(3);
        });

        it("resumes the silent count from persisted meta after a restart", async () => {
            // A device that has already gone silent twice before restart.
            const {device} = makeDevice("0x0C04", {c4_device_type: "keypad", c4_silent_probes: 2});
            const probeFn = vi.fn(async () => null);

            scheduleC4ProbeCampaign(asDevice(device), "keypad", vi.fn(), {probeFn, random: () => 0, backoffMs: 1000});

            // One more silent probe should be enough to confirm (2 + 1 == 3).
            await vi.advanceTimersByTimeAsync(0);

            expect(probeFn).toHaveBeenCalledTimes(1);
            expect(device.meta.c4_type_confidence).toBe(C4_CONFIDENCE_CONFIRMED);
        });
    });

    describe("c4ArmProbeOnStart (startup arming)", () => {
        beforeEach(() => {
            vi.useFakeTimers();
        });

        afterEach(() => {
            resetC4HealState();
            vi.runOnlyPendingTimers();
            vi.useRealTimers();
        });

        it("arms a campaign for an assumed keypad at startup", async () => {
            const {device} = makeDevice("0x0D01", {c4_device_type: "keypad"});
            const probeFn = vi.fn(async () => null);

            c4ArmProbeOnStart(asDevice(device), {}, {probeFn, random: () => 0, backoffMs: 1000});

            await vi.advanceTimersByTimeAsync(0);
            expect(probeFn).toHaveBeenCalledTimes(1);
        });

        it("treats an absent classification as an assumed keypad", async () => {
            const {device} = makeDevice("0x0D02", {});
            const probeFn = vi.fn(async () => null);

            c4ArmProbeOnStart(asDevice(device), undefined, {probeFn, random: () => 0, backoffMs: 1000});

            await vi.advanceTimersByTimeAsync(0);
            expect(probeFn).toHaveBeenCalledTimes(1);
        });

        it("never arms for a confirmed keypad", async () => {
            const {device} = makeDevice("0x0D03", {c4_device_type: "keypad", c4_type_confidence: C4_CONFIDENCE_CONFIRMED});
            const probeFn = vi.fn(async () => null);

            c4ArmProbeOnStart(asDevice(device), {}, {probeFn});
            await vi.advanceTimersByTimeAsync(120000);
            expect(probeFn).not.toHaveBeenCalled();
        });

        it("never arms for a load type from published state", async () => {
            const {device} = makeDevice("0x0D04", {});
            const probeFn = vi.fn(async () => null);

            c4ArmProbeOnStart(asDevice(device), {c4_device_type: "dimmer"}, {probeFn});
            await vi.advanceTimersByTimeAsync(120000);
            expect(probeFn).not.toHaveBeenCalled();
        });

        it("startup and fz-side arming are idempotent (one campaign)", async () => {
            const {device} = makeDevice("0x0D05", {c4_device_type: "keypad"});
            const probeFn = vi.fn(async () => null);

            c4ArmProbeOnStart(asDevice(device), {}, {probeFn, random: () => 0, backoffMs: 1000});
            scheduleC4ProbeCampaign(asDevice(device), "keypad", vi.fn(), {probeFn, random: () => 0, backoffMs: 1000});

            await vi.advanceTimersByTimeAsync(0);
            expect(probeFn).toHaveBeenCalledTimes(1);
        });
    });

    describe("scheduleC4LoadStatePublish (ls telemetry sync)", () => {
        beforeEach(() => {
            vi.useFakeTimers();
        });

        afterEach(() => {
            vi.runOnlyPendingTimers();
            vi.useRealTimers();
        });

        it("exports a positive debounce delay", () => {
            expect(C4_LOAD_STATE_DEBOUNCE_MS).toBeGreaterThan(0);
        });

        it("publishes ON with scaled brightness for a mid level (19 -> 48)", async () => {
            const {device} = makeDevice("0x0101");
            const publish = vi.fn();

            scheduleC4LoadStatePublish(asDevice(device), 19, publish);

            expect(publish).not.toHaveBeenCalled();
            await vi.advanceTimersByTimeAsync(C4_LOAD_STATE_DEBOUNCE_MS);

            expect(publish).toHaveBeenCalledTimes(1);
            expect(publish).toHaveBeenCalledWith({state: "ON", brightness: 48});
        });

        it("publishes OFF without any brightness key for level 0", async () => {
            const {device} = makeDevice("0x0102");
            const publish = vi.fn();

            scheduleC4LoadStatePublish(asDevice(device), 0, publish);
            await vi.advanceTimersByTimeAsync(C4_LOAD_STATE_DEBOUNCE_MS);

            expect(publish).toHaveBeenCalledTimes(1);
            const payload = publish.mock.calls[0][0];
            expect(payload).toEqual({state: "OFF"});
            expect(payload).not.toHaveProperty("brightness");
        });

        it("coalesces a dim-ramp burst into one publish with the final level", async () => {
            const {device} = makeDevice("0x0103");
            const publish = vi.fn();

            // A burst of ls frames 200 ms apart, ending at level 0 (turned off).
            const levels = [4, 20, 89, 51, 33, 0];
            for (const lvl of levels) {
                scheduleC4LoadStatePublish(asDevice(device), lvl, publish);
                await vi.advanceTimersByTimeAsync(200);
            }

            // Still within the debounce window after the last frame.
            expect(publish).not.toHaveBeenCalled();

            await vi.advanceTimersByTimeAsync(C4_LOAD_STATE_DEBOUNCE_MS);

            expect(publish).toHaveBeenCalledTimes(1);
            expect(publish).toHaveBeenCalledWith({state: "OFF"});
        });

        it("publishes once per quiet window at real ls ramp cadence", async () => {
            const {device} = makeDevice("0x0104");
            const publish = vi.fn();

            // Field data: real ls inter-frame gaps during a ramp are 500 to
            // 1500 ms, so each 900 ms gap exceeds the 500 ms quiet window and
            // the ramp yields MULTIPLE publishes (one per frame), not one.
            const levels = [21, 54, 89, 100];
            for (const lvl of levels) {
                scheduleC4LoadStatePublish(asDevice(device), lvl, publish);
                await vi.advanceTimersByTimeAsync(900);
            }

            expect(publish).toHaveBeenCalledTimes(levels.length);
            expect(publish).toHaveBeenNthCalledWith(1, {state: "ON", brightness: Math.round((21 * 255) / 100)});
            expect(publish).toHaveBeenNthCalledWith(2, {state: "ON", brightness: Math.round((54 * 255) / 100)});
            expect(publish).toHaveBeenNthCalledWith(3, {state: "ON", brightness: Math.round((89 * 255) / 100)});
            // The final settled level is always published as the last call.
            expect(publish).toHaveBeenLastCalledWith({state: "ON", brightness: 255});
        });

        it("debounces and publishes two devices independently", async () => {
            const a = makeDevice("0x01AA");
            const b = makeDevice("0x01BB");
            const publishA = vi.fn();
            const publishB = vi.fn();

            scheduleC4LoadStatePublish(asDevice(a.device), 100, publishA);
            await vi.advanceTimersByTimeAsync(200);
            scheduleC4LoadStatePublish(asDevice(b.device), 50, publishB);

            // Advance so device A's window elapses but device B's does not.
            await vi.advanceTimersByTimeAsync(C4_LOAD_STATE_DEBOUNCE_MS - 200);
            expect(publishA).toHaveBeenCalledTimes(1);
            expect(publishA).toHaveBeenCalledWith({state: "ON", brightness: 255});
            expect(publishB).not.toHaveBeenCalled();

            // Finish device B's window.
            await vi.advanceTimersByTimeAsync(200);
            expect(publishB).toHaveBeenCalledTimes(1);
            expect(publishB).toHaveBeenCalledWith({state: "ON", brightness: 128});
        });
    });

    describe("scheduleC4StateRead (manual paddle sync fallback)", () => {
        beforeEach(() => {
            vi.useFakeTimers();
        });

        afterEach(() => {
            vi.runOnlyPendingTimers();
            vi.useRealTimers();
        });

        it("exports a positive debounce delay", () => {
            expect(C4_STATE_READ_DEBOUNCE_MS).toBeGreaterThan(0);
        });

        it("a single event reads genOnOff + genLevelCtrl on EP1 after the delay", async () => {
            const {device, ep1} = makeDevice("0x0001");

            scheduleC4StateRead(asDevice(device), "dimmer");

            // Nothing fires before the debounce window elapses.
            await vi.advanceTimersByTimeAsync(C4_STATE_READ_DEBOUNCE_MS - 1);
            expect(ep1.read).not.toHaveBeenCalled();

            await vi.advanceTimersByTimeAsync(1);

            expect(ep1.read).toHaveBeenCalledTimes(2);
            expect(ep1.read).toHaveBeenNthCalledWith(1, "genOnOff", ["onOff"]);
            expect(ep1.read).toHaveBeenNthCalledWith(2, "genLevelCtrl", ["currentLevel"]);
        });

        it("coalesces a burst of events into exactly one read", async () => {
            const {device, ep1} = makeDevice("0x0002");

            // Five events 100 ms apart, simulating a dimmer paddle hold.
            for (let i = 0; i < 5; i++) {
                scheduleC4StateRead(asDevice(device), "keypaddim");
                await vi.advanceTimersByTimeAsync(100);
            }

            // Still within the debounce window after the last event.
            expect(ep1.read).not.toHaveBeenCalled();

            await vi.advanceTimersByTimeAsync(C4_STATE_READ_DEBOUNCE_MS);

            // One read of each attribute, not five.
            expect(ep1.read).toHaveBeenCalledTimes(2);
        });

        it("never reads for a pure keypad (no load)", async () => {
            const {device, ep1} = makeDevice("0x0003");

            scheduleC4StateRead(asDevice(device), "keypad");
            await vi.advanceTimersByTimeAsync(C4_STATE_READ_DEBOUNCE_MS * 2);

            expect(ep1.read).not.toHaveBeenCalled();
            expect(device.getEndpoint).not.toHaveBeenCalled();
        });

        it("reads when the device type is unknown (absent)", async () => {
            const {device, ep1} = makeDevice("0x0004");

            scheduleC4StateRead(asDevice(device), undefined);
            await vi.advanceTimersByTimeAsync(C4_STATE_READ_DEBOUNCE_MS);

            expect(ep1.read).toHaveBeenCalledTimes(2);
        });

        it("swallows a read failure without throwing", async () => {
            const {device, ep1} = makeDevice(
                "0x0005",
                {},
                {
                    readImpl: () => Promise.reject(new Error("device unreachable")),
                },
            );

            expect(() => scheduleC4StateRead(asDevice(device), "dimmer")).not.toThrow();

            let drainError: unknown;
            try {
                await vi.advanceTimersByTimeAsync(C4_STATE_READ_DEBOUNCE_MS);
            } catch (err) {
                drainError = err;
            }
            expect(drainError).toBeUndefined();

            // Both reads were attempted even though the first rejected.
            expect(ep1.read).toHaveBeenCalledTimes(2);
        });

        it("suppresses the ZCL read when an ls frame arrives before it fires", async () => {
            const {device, ep1} = makeDevice("0x0201");

            // A button event schedules the fallback read.
            scheduleC4StateRead(asDevice(device), "dimmer");

            // An ls frame arrives before the read timer fires.
            await vi.advanceTimersByTimeAsync(100);
            scheduleC4LoadStatePublish(asDevice(device), 42, vi.fn());

            // Let the read window fully elapse.
            await vi.advanceTimersByTimeAsync(C4_STATE_READ_DEBOUNCE_MS);

            // The read was skipped in favor of the ls-telemetry publish.
            expect(ep1.read).not.toHaveBeenCalled();
        });

        it("debounces two devices independently", async () => {
            const a = makeDevice("0xAAAA");
            const b = makeDevice("0xBBBB");

            scheduleC4StateRead(asDevice(a.device), "dimmer");
            await vi.advanceTimersByTimeAsync(400);
            scheduleC4StateRead(asDevice(b.device), "dimmer");

            // Advance so device A's window elapses but device B's does not.
            await vi.advanceTimersByTimeAsync(C4_STATE_READ_DEBOUNCE_MS - 400);
            expect(a.ep1.read).toHaveBeenCalledTimes(2);
            expect(b.ep1.read).not.toHaveBeenCalled();

            // Finish device B's window.
            await vi.advanceTimersByTimeAsync(400);
            expect(b.ep1.read).toHaveBeenCalledTimes(2);
        });
    });

    describe("fzControl4Response (raw handler behavior)", () => {
        // biome-ignore lint/suspicious/noExplicitAny: mock plumbing for the fz convert signature
        type AnyFn = (...args: any[]) => any;
        const definition = definitions[0];
        const fzConvert = (definition.fromZigbee as unknown as [{convert: AnyFn}])[0].convert;

        function convert(text: string, device: MockDevice, state: KeyValue = {}): Promise<KeyValue | undefined> {
            const msg = {
                data: Buffer.from(text, "ascii"),
                endpoint: {ID: 197},
                device,
                type: "raw",
                cluster: "genPowerCfg",
            };
            return fzConvert(definition, msg, vi.fn(), {}, {state, device});
        }

        beforeEach(() => {
            vi.useFakeTimers();
        });

        afterEach(() => {
            resetC4HealState();
            vi.runOnlyPendingTimers();
            vi.useRealTimers();
        });

        it("publishes action for a button press and echoes c4_response", async () => {
            const {device} = makeDevice("0x0E01", {c4_device_type: "keypaddim", c4_type_confidence: C4_CONFIDENCE_CONFIRMED});

            const result = await convert("0t0001 sa c4.dmx.bp 01", device);

            expect(result?.action).toBe("button_2_press");
            expect(result?.c4_response).toBe("0t0001 sa c4.dmx.bp 01");
            expect(result?.c4_response_ep).toBe(197);
        });

        it("mutes c4_response for unsolicited ls telemetry (only state fields flow)", async () => {
            const {device} = makeDevice("0x0E02", {c4_device_type: "keypaddim", c4_type_confidence: C4_CONFIDENCE_CONFIRMED});

            const result = await convert("0t0001 sa c4.dmx.ls 00 00 32 0078", device);

            expect(result).toBeDefined();
            expect(result).not.toHaveProperty("c4_response");
            expect(result).not.toHaveProperty("c4_response_ep");
        });

        it("keeps c4_response for query responses (0r form)", async () => {
            const {device} = makeDevice("0x0E03", {c4_device_type: "keypaddim", c4_type_confidence: C4_CONFIDENCE_CONFIRMED});

            const result = await convert("0r0001 000 c4.dmx.led ffffff", device);

            expect(result?.c4_response).toBe("0r0001 000 c4.dmx.led ffffff");
        });

        it("heals an assumed keypad to keypaddim on a paddle event", async () => {
            const {device} = makeDevice("0x0E04", {c4_device_type: "keypad", c4_type_confidence: C4_CONFIDENCE_ASSUMED});

            const result = await convert("0t0001 sa c4.dmx.bp 07", device, {c4_device_type: "keypad"});

            expect(result?.action).toBe("paddle_up_press");
            expect(result?.c4_device_type).toBe("keypaddim");
            expect(device.meta.c4_device_type).toBe("keypaddim");
        });

        it("heals on a dim answer arriving as a raw response", async () => {
            const {device} = makeDevice("0x0E05", {c4_device_type: "keypad", c4_type_confidence: C4_CONFIDENCE_ASSUMED});

            const result = await convert("0r0001 000 c4.dmx.dim 02", device, {c4_device_type: "keypad"});

            expect(result?.c4_device_type).toBe("keypaddim");
            expect(device.meta.c4_type_confidence).toBe(C4_CONFIDENCE_CONFIRMED);
        });
    });

    describe("Frozen MQTT contract", () => {
        const definition = definitions[0];

        it("action enum carries exactly the 48 frozen values", () => {
            const expected: string[] = [];
            for (let n = 1; n <= 6; n++) {
                expected.push(
                    `button_${n}_press`,
                    `button_${n}_scene`,
                    `button_${n}_click_1`,
                    `button_${n}_click_2`,
                    `button_${n}_click_3`,
                    `button_${n}_click_4`,
                );
            }
            for (const paddle of ["paddle_up", "paddle_down"]) {
                expected.push(
                    `${paddle}_press`,
                    `${paddle}_scene`,
                    `${paddle}_click_1`,
                    `${paddle}_click_2`,
                    `${paddle}_click_3`,
                    `${paddle}_click_4`,
                );
            }
            expect([...ACTION_VALUES].sort()).toEqual(expected.sort());
        });

        it("toZigbee accepts the frozen command keys", () => {
            const keys = (definition.toZigbee ?? []).flatMap((tz) => tz.key ?? []);
            for (const frozen of ["c4_led", "c4_cmd", "c4_query", "zcl_read", "c4_probe", "c4_detect"]) {
                expect(keys).toContain(frozen);
            }
        });

        it("definition model and vendor are stable", () => {
            expect(definition.model).toBe("C4-Zigbee");
            expect(definition.vendor).toBe("Control4");
        });

        it("fingerprint matches on the Control4 manufacturer ID", () => {
            expect(definition.fingerprint).toEqual([{manufacturerID: 43981}]);
        });
    });
});
