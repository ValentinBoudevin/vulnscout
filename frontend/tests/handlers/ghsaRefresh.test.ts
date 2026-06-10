import GhsaRefreshHandler from "../../src/handlers/ghsaRefresh";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

const mockVulnResponse = {
    id: "GHSA-1234-5678-abcd",
    found_by: [],
    datasource: "ghsa",
    namespace: "ghsa",
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
};

describe("GhsaRefreshHandler.triggerSingleRefresh", () => {
    it("returns Vulnerability on 200 with valid data", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ vulnerabilities: [mockVulnResponse] }),
        } as Response);

        const vuln = await GhsaRefreshHandler.triggerSingleRefresh("GHSA-1234-5678-abcd");
        expect(vuln).not.toBeNull();
        expect(vuln!.id).toBe("GHSA-1234-5678-abcd");
    });

    it("returns null on non-ok response", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 503,
        } as Response);

        const result = await GhsaRefreshHandler.triggerSingleRefresh("GHSA-1234-5678-abcd");
        expect(result).toBeNull();
    });

    it("returns null on 404", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 404,
        } as Response);

        const result = await GhsaRefreshHandler.triggerSingleRefresh("GHSA-9999-fake");
        expect(result).toBeNull();
    });

    it("calls the /ghsa-refresh endpoint with the CVE ID", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ vulnerabilities: [mockVulnResponse] }),
        } as Response);

        await GhsaRefreshHandler.triggerSingleRefresh("GHSA-1234-5678-abcd");
        const calledUrl: string = mockFetch.mock.calls[0][0];
        expect(calledUrl).toContain("/ghsa-refresh");
        expect(calledUrl).toContain("GHSA-1234-5678-abcd");
    });

    it("returns null when vulnerabilities array is empty", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ vulnerabilities: [] }),
        } as Response);

        const result = await GhsaRefreshHandler.triggerSingleRefresh("GHSA-1234-5678-abcd");
        expect(result).toBeNull();
    });

    it("returns null when json() throws (malformed response)", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => { throw new Error("invalid json"); },
        } as unknown as Response);

        const result = await GhsaRefreshHandler.triggerSingleRefresh("GHSA-1234-5678-abcd");
        expect(result).toBeNull();
    });

    it("returns null when vulnerabilities key is missing from response", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ data: [mockVulnResponse] }),
        } as Response);

        const result = await GhsaRefreshHandler.triggerSingleRefresh("GHSA-1234-5678-abcd");
        expect(result).toBeNull();
    });

    it("URL-encodes the GHSA ID", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: true,
            status: 200,
            json: async () => ({ vulnerabilities: [{ ...mockVulnResponse, id: "GHSA-ab/cd" }] }),
        } as Response);

        await GhsaRefreshHandler.triggerSingleRefresh("GHSA-ab/cd");
        const calledUrl: string = mockFetch.mock.calls[0][0];
        expect(calledUrl).toContain("GHSA-ab%2Fcd");
    });
});
