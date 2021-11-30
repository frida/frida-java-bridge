export function getApi(): Api;
export function withRunnableArtThread(vm: VM, env: Env, callback: (thread: Thread) => void): void;
export function translateMethod(methodId: NativePointerValue): NativePointer;

export class ArtStackVisitor {
    constructor(thread: Thread, context: Context, walkKind: WalkKind, numFrames?: number, checkSuspended?: boolean);
    walkStack(includeTransitions?: boolean): void;
    getMethod(): ArtMethod | null;
    getCurrentQuickFramePc(): NativePointer;
    getCurrentQuickFrame(): NativePointer;
    getCurrentShadowFrame(): NativePointer;
    describeLocation(): string;
    getCurrentOatQuickMethodHeader(): NativePointer;
    getCurrentQuickFrameInfo(): QuickFrameInfo;
}

export type WalkKind = "include-inlined-frames" | "skip-inlined-frames";

export interface ArtMethod extends ObjectWrapper {
    prettyMethod(withSignature?: boolean): string;
}

export interface QuickFrameInfo {
    frameSizeInBytes: number;
    coreSpillMask: number;
    fpSpillMask: number;
}

export type Api = any;
export type VM = any;
export type Env = any;
export type Thread = any;
export type Context = any;
