import NvdRefreshHandler from "../../src/handlers/nvdRefresh";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

describe("NvdRefreshHandler.triggerSingleRefresh", () => {
    it("returns kind:success with Vulnerability on 200", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({
                vulnerabilities: [{
                    id: "CVE-2024-0001",
                    found_by: [],
                    datasource: "nvd",
                    namespace: "nvd",
                    aliases: [],
                    related_vulnerabilities: [],
                    urls: [],
                    texts: {},
                    fix: {},
                    severity: { severity: "high", min_score: 8.1, max_score: 8.1, cvss: [] },
                    epss: {},
                    effort: {},
                    advisories: [],
                    packages: [],
                }]
            }),
        } as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result.kind).toBe("success");
        if (result.kind === "success") {
            expect(result.vuln.id).toBe("CVE-2024-0001");
        }
    });

    it("returns kind:error code:unavailable on 503", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 503,
            json: async () => ({ error: "NVD unavailable", error_code: "unavailable", api_key_configured: true }),
        } as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result.kind).toBe("error");
        if (result.kind === "error") {
            expect(result.code).toBe("unavailable");
            expect(result.apiKeyConfigured).toBe(true);
        }
    });

    it("returns kind:error code:rate_limited apiKeyConfigured:false on 429 without key", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 429,
            json: async () => ({ error: "rate limited", error_code: "rate_limited", api_key_configured: false }),
        } as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result.kind).toBe("error");
        if (result.kind === "error") {
            expect(result.code).toBe("rate_limited");
            expect(result.apiKeyConfigured).toBe(false);
        }
    });

    it("defaults apiKeyConfigured to true when body is missing", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 503,
            json: async () => { throw new Error("not json"); },
        } as unknown as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result.kind).toBe("error");
        if (result.kind === "error") {
            expect(result.apiKeyConfigured).toBe(true);
        }
    });
});
