import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { checkBreach } from '../controllers/breachController.js';

function makeRes() {
    return {
        status: vi.fn().mockReturnThis(),
        json: vi.fn(),
        setHeader: vi.fn(),
        send: vi.fn(),
    };
}

describe('Epic 7.3 - breachController unit tests', () => {
    beforeEach(() => {
        vi.restoreAllMocks();
    });

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it('returns 400 for invalid prefix', async () => {
        const req = { params: { prefix: 'XYZ' } };
        const res = makeRes();
        const fetchSpy = vi.fn();
        vi.stubGlobal('fetch', fetchSpy);

        await checkBreach(req, res);

        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({ error: 'Invalid prefix format. Expected 5 hex characters.' });
        expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('proxies suffix body on valid prefix', async () => {
        const req = { params: { prefix: '21BD1' } };
        const res = makeRes();
        const responseText = 'AAA:1\\nBBB:2';
        const fetchSpy = vi.fn().mockResolvedValue({
            ok: true,
            text: vi.fn().mockResolvedValue(responseText),
        });
        vi.stubGlobal('fetch', fetchSpy);

        await checkBreach(req, res);

        expect(fetchSpy).toHaveBeenCalledWith(
            'https://api.pwnedpasswords.com/range/21BD1',
            expect.objectContaining({
                method: 'GET',
                headers: expect.objectContaining({ 'User-Agent': 'PasswordPal-Backend' }),
            }),
        );
        expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'text/plain');
        expect(res.send).toHaveBeenCalledWith(responseText);
    });

    it('returns 500 when upstream returns non-ok', async () => {
        const req = { params: { prefix: '21BD1' } };
        const res = makeRes();
        const fetchSpy = vi.fn().mockResolvedValue({ ok: false, status: 429 });
        vi.stubGlobal('fetch', fetchSpy);

        await checkBreach(req, res);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({ error: 'Failed to check breach status.' });
    });

    it('returns 500 when fetch throws', async () => {
        const req = { params: { prefix: '21BD1' } };
        const res = makeRes();
        const fetchSpy = vi.fn().mockRejectedValue(new Error('network'));
        vi.stubGlobal('fetch', fetchSpy);

        await checkBreach(req, res);

        expect(res.status).toHaveBeenCalledWith(500);
        expect(res.json).toHaveBeenCalledWith({ error: 'Failed to check breach status.' });
    });
});
