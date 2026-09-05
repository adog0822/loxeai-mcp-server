/**
 * Scan orchestration: detect -> trust-gate -> run -> sanitize -> store.
 */
import { type Batch } from "./types.js";
export declare class ScannerUnavailableError extends Error {
    constructor();
}
export declare class TrustError extends Error {
    constructor(reason: string);
}
export type ScanOptions = {
    path: string;
    frameworks?: string[];
    configPath?: string;
    scanner?: string;
};
export declare function performScan(options: ScanOptions): Promise<Batch>;
