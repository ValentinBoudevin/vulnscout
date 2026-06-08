import { BulkNvdRefreshHandler, BulkEpssRefreshHandler, BulkNvdRefreshCancelHandler, BulkEpssRefreshCancelHandler } from "../../src/handlers/bulkRefresh";
import type { BulkRefreshResponse, CancelRefreshResponse } from "../../src/handlers/bulkRefresh";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

const makeOkResponse = (body: BulkRefreshResponse) => ({
    ok: true,
    status: 202,
    json: async () => body,
} as Response);

const makeErrorResponse = (status: number) => ({
    ok: false,
    status,
    json: async () => ({ error: "error" }),
} as Response);

describe("BulkNvdRefreshHandler.trigger", () => {
    it("returns BulkRefreshResponse on 202", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse({ status: "started", total: 5 }));
        const result = await BulkNvdRefreshHandler.trigger(["CVE-2024-0001", "CVE-2024-0002"]);
        expect(result).not.toBeNull();
        expect(result!.status).toBe("started");
        expect(result!.total).toBe(5);
    });

    it("sends the correct request body", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse({ status: "started", total: 1 }));
        const cveIds = ["CVE-2024-0001"];
        await BulkNvdRefreshHandler.trigger(cveIds);
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/bulk-nvd-refresh"),
            expect.objectContaining({
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cve_ids: cveIds }),
            }),
        );
    });

    it("returns null on 409 (already in progress)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(409));
        const result = await BulkNvdRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).toBeNull();
    });

    it("returns null on 400 (bad request)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(400));
        const result = await BulkNvdRefreshHandler.trigger([]);
        expect(result).toBeNull();
    });

    it("returns null when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network error"));
        const result = await BulkNvdRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).toBeNull();
    });

    it("returns null when json() throws (malformed 202 body)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 202,
            json: async () => { throw new Error("bad json"); },
        } as unknown as Response);
        const result = await BulkNvdRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).toBeNull();
    });
});

describe("BulkEpssRefreshHandler.trigger", () => {
    it("returns BulkRefreshResponse on 202", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse({ status: "started", total: 10 }));
        const result = await BulkEpssRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).not.toBeNull();
        expect(result!.total).toBe(10);
    });

    it("sends the correct request body", async () => {
        mockFetch.mockResolvedValueOnce(makeOkResponse({ status: "started", total: 1 }));
        const cveIds = ["CVE-2024-0001", "CVE-2024-0002"];
        await BulkEpssRefreshHandler.trigger(cveIds);
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/bulk-epss-refresh"),
            expect.objectContaining({
                method: "POST",
                body: JSON.stringify({ cve_ids: cveIds }),
            }),
        );
    });

    it("returns null on 409", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(409));
        const result = await BulkEpssRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).toBeNull();
    });

    it("returns null on 400", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(400));
        const result = await BulkEpssRefreshHandler.trigger([]);
        expect(result).toBeNull();
    });

    it("returns null when json() throws (malformed 202 body)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 202,
            json: async () => { throw new Error("bad json"); },
        } as unknown as Response);
        const result = await BulkEpssRefreshHandler.trigger(["CVE-2024-0001"]);
        expect(result).toBeNull();
    });
});

const makeOkCancelResponse = (body: CancelRefreshResponse) => ({
    ok: true,
    status: 200,
    json: async () => body,
} as Response);

describe("BulkNvdRefreshCancelHandler.trigger", () => {
    it("returns CancelRefreshResponse on 200", async () => {
        mockFetch.mockResolvedValueOnce(makeOkCancelResponse({ status: "cancelling" }));
        const result = await BulkNvdRefreshCancelHandler.trigger();
        expect(result).not.toBeNull();
        expect(result!.status).toBe("cancelling");
    });

    it("sends POST to the correct cancel endpoint", async () => {
        mockFetch.mockResolvedValueOnce(makeOkCancelResponse({ status: "cancelling" }));
        await BulkNvdRefreshCancelHandler.trigger();
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/cancel-nvd-refresh"),
            expect.objectContaining({ method: "POST" }),
        );
    });

    it("returns null on 409 (nothing in progress)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(409));
        const result = await BulkNvdRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });

    it("returns null when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network error"));
        const result = await BulkNvdRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });
});

describe("BulkEpssRefreshCancelHandler.trigger", () => {
    it("returns CancelRefreshResponse on 200", async () => {
        mockFetch.mockResolvedValueOnce(makeOkCancelResponse({ status: "cancelling" }));
        const result = await BulkEpssRefreshCancelHandler.trigger();
        expect(result).not.toBeNull();
        expect(result!.status).toBe("cancelling");
    });

    it("sends POST to the correct cancel endpoint", async () => {
        mockFetch.mockResolvedValueOnce(makeOkCancelResponse({ status: "cancelling" }));
        await BulkEpssRefreshCancelHandler.trigger();
        expect(mockFetch).toHaveBeenCalledWith(
            expect.stringContaining("/api/vulnerabilities/cancel-epss-refresh"),
            expect.objectContaining({ method: "POST" }),
        );
    });

    it("returns null on 409 (nothing in progress)", async () => {
        mockFetch.mockResolvedValueOnce(makeErrorResponse(409));
        const result = await BulkEpssRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });

    it("returns null when fetch rejects", async () => {
        mockFetch.mockRejectedValueOnce(new Error("network error"));
        const result = await BulkEpssRefreshCancelHandler.trigger();
        expect(result).toBeNull();
    });
});
