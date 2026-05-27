import NvdRefreshHandler from "../../src/handlers/nvdRefresh";

const mockFetch = jest.fn();
global.fetch = mockFetch as typeof fetch;

beforeEach(() => {
    mockFetch.mockReset();
});

describe("NvdRefreshHandler.triggerSingleRefresh", () => {
    it("returns a Vulnerability object on 200", async () => {
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

        const vuln = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(vuln).not.toBeNull();
        expect(vuln!.id).toBe("CVE-2024-0001");
    });

    it("returns null on 503", async () => {
        mockFetch.mockResolvedValueOnce({
            ok: false,
            status: 503,
            text: async () => "NVD unavailable",
        } as Response);

        const result = await NvdRefreshHandler.triggerSingleRefresh("CVE-2024-0001");
        expect(result).toBeNull();
    });
});
