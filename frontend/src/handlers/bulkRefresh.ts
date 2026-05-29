/**
 * Bulk NVD and EPSS refresh handlers.
 *
 * These fire-and-forget endpoints return 202 immediately; actual progress
 * is tracked via /api/nvd/progress and /api/epss/progress respectively.
 */

export interface BulkRefreshResponse {
    status: string;
    total: number;
}

export class BulkNvdRefreshHandler {
    static async trigger(cveIds: string[]): Promise<BulkRefreshResponse | null> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/bulk-nvd-refresh`;
        try {
            const response = await fetch(url, {
                method: "POST",
                mode: "cors",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cve_ids: cveIds }),
            });
            if (!response.ok) return null;
            return response.json().catch(() => null);
        } catch {
            return null;
        }
    }
}

export class BulkEpssRefreshHandler {
    static async trigger(cveIds: string[]): Promise<BulkRefreshResponse | null> {
        const url = `${import.meta.env.VITE_API_URL}/api/vulnerabilities/bulk-epss-refresh`;
        try {
            const response = await fetch(url, {
                method: "POST",
                mode: "cors",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ cve_ids: cveIds }),
            });
            if (!response.ok) return null;
            return response.json().catch(() => null);
        } catch {
            return null;
        }
    }
}
