import { getDevicesByUserId, revokeDeviceById, setDeviceBlocked } from '../models/deviceModel.js';
import { recordDeviceEvent } from '../models/deviceEventModel.js';
import { supabase } from '../config/db.js';

// The action has already taken effect by the time it is logged, so a logging
// failure is reported server-side rather than failing the request.
const logDeviceEvent = (req, action) =>
    recordDeviceEvent({
        userId: req.user.id,
        action,
        targetDeviceId: req.params.id,
        actorDeviceId: req.user.did,
    }).catch((err) => console.error(`Failed to record device ${action} event:`, err));

export const getDevices = async (req, res) => {
    try {
        const userId = req.user.id; // injected by verifySession
        const devices = await getDevicesByUserId(userId);

        // The session's device row is carried in the token as `did`
        const processedDevices = devices.map(device => ({
            ...device,
            isCurrent: device.id === req.user.did,
        }));

        return res.status(200).json({ devices: processedDevices });
    } catch (err) {
        console.error("Fetch devices error:", err);
        return res.status(500).json({ error: "Failed to fetch devices" });
    }
};

export const revokeDevice = async (req, res) => {
    try {
        const userId = req.user.id;
        const deviceId = req.params.id;

        await revokeDeviceById(deviceId, userId);
        await logDeviceEvent(req, "revoke");
        return res.status(200).json({ message: "Device revoked successfully" });
    } catch (err) {
        console.error("Revoke device error:", err);
        return res.status(500).json({ error: "Failed to revoke device" });
    }
};

const setBlocked = (blocked) => async (req, res) => {
    try {
        const userId = req.user.id;
        const deviceId = req.params.id;

        if (blocked && deviceId === req.user.did) {
            return res.status(400).json({ error: "You can't block the device you're using." });
        }

        await setDeviceBlocked(deviceId, userId, blocked);
        await logDeviceEvent(req, blocked ? "block" : "unblock");
        return res.status(200).json({ message: blocked ? "Device blocked" : "Device unblocked" });
    } catch (err) {
        console.error(`${blocked ? "Block" : "Unblock"} device error:`, err);
        if (err.message === "Device not found or not owned by user") {
            return res.status(404).json({ error: "Device not found" });
        }
        return res.status(500).json({ error: `Failed to ${blocked ? "block" : "unblock"} device` });
    }
};

export const blockDevice = setBlocked(true);
export const unblockDevice = setBlocked(false);

export const registerDevice = async (req, res) => {
    try {
        const userId = req.user.id;
        const { name } = req.body;

        if (name) {
            await supabase
                .from("user_devices")
                .update({ device_name: name })
                .eq("id", req.user.did)
                .eq("user_id", userId);
        }

        return res.status(200).json({ message: "Device registered" });
    } catch (err) {
        console.error("Device register error:", err);
        return res.status(500).json({ error: "Failed to register device" });
    }
};
