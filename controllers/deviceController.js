import { getDevicesByUserId, revokeDeviceById } from '../models/deviceModel.js';
import { supabase } from '../config/db.js';

export const getDevices = async (req, res) => {
    try {
        const userId = req.user.id; // injected by verifySession
        const currentToken = req.cookies['sb-refresh-token'];

        const devices = await getDevicesByUserId(userId);

        // Map to add `isCurrent` tag and remove sensitive attributes
        const processedDevices = devices.map(device => {
            const isCurrent = device.refresh_token === currentToken;

            // Do not send refresh tokens back to the client
            const { refresh_token, ...safeDevice } = device;
            return {
                ...safeDevice,
                isCurrent
            };
        });

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
        return res.status(200).json({ message: "Device revoked successfully" });
    } catch (err) {
        console.error("Revoke device error:", err);
        return res.status(500).json({ error: "Failed to revoke device" });
    }
};

export const registerDevice = async (req, res) => {
    try {
        const userId = req.user.id;
        const currentToken = req.cookies['sb-refresh-token'];
        const { name } = req.body;

        if (name && currentToken) {
            await supabase
                .from("user_devices")
                .update({ device_name: name })
                .eq("refresh_token", currentToken)
                .eq("user_id", userId);
        }

        return res.status(200).json({ message: "Device registered" });
    } catch (err) {
        console.error("Device register error:", err);
        return res.status(500).json({ error: "Failed to register device" });
    }
};
