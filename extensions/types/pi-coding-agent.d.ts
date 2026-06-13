declare module "@earendil-works/pi-coding-agent" {
	export interface ExtensionAPI {
		on(event: string, handler: (event: any, ctx: ExtensionContext) => Promise<void> | void): void;
		registerTool(name: string, options: any): void;
	}

	export interface ExtensionContext {
		ui: {
			notify(message: string, level: "info" | "success" | "warning" | "error"): void;
		};
	}
}
